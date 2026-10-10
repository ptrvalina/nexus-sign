import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Secure push v1: how a push message travels from Auth Core to the bank's app
 * without Apple, Google or anything between them reading it.
 * Specification: docs/protocol/secure-push.md.
 * Shared vectors: test-vectors/secure-push-v1.json.
 *
 * Once per device, at push registration, the device and Auth Core agree a
 * 32-byte push key over ECDH P-256 (both halves ephemeral):
 *
 *   K = HKDF-SHA256(ikm = ECDH x coordinate, salt = "NEXUS-SIGN/PUSH/v1", info = credentialId, 32)
 *
 * Every message is then sealed with AES-256-GCM under K:
 *
 *   AAD      = "NEXUS-SIGN/PUSH/v1" "\n" messageId "\n" credentialId
 *   envelope = { v: 1, id: messageId, cid: credentialId, iv: b64url(12 bytes), ct: b64url(ciphertext || 16-byte tag) }
 *
 * The plaintext is the UTF-8 JSON of PushContent. The envelope is all that is
 * stored and all that is handed to APNs or FCM.
 *
 * After decrypting, the device proves it with a receipt keyed by K, so the
 * notification extension can confirm delivery while the phone is locked,
 * without its request-signing key:
 *
 *   receipt = b64url(HMAC-SHA256(K, "NEXUS-SIGN/PUSH-RECEIPT/v1" "\n" messageId "\n" credentialId))
 *
 * Both sides name the key they hold, so a token refresh from a device whose
 * key differs from Auth Core's (an agreement whose answer was lost) is
 * refused and the device agrees a new key:
 *
 *   keyId = b64url(first 16 bytes of HMAC-SHA256(K, "NEXUS-SIGN/PUSH-KEY-ID/v1"))
 */

export const PUSH_PROTOCOL_DOMAIN = 'NEXUS-SIGN/PUSH/v1';
export const PUSH_RECEIPT_DOMAIN = 'NEXUS-SIGN/PUSH-RECEIPT/v1';
export const PUSH_KEY_ID_DOMAIN = 'NEXUS-SIGN/PUSH-KEY-ID/v1';
export const PUSH_ENVELOPE_VERSION = 1;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/** Limits that keep a sealed message inside the 4 KB APNs and FCM payloads. */
export const PUSH_TITLE_MAX = 120;
export const PUSH_BODY_MAX = 600;
export const PUSH_DATA_MAX_FIELDS = 16;
export const PUSH_DATA_KEY_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
export const PUSH_DATA_VALUE_MAX = 256;
export const PUSH_PLAINTEXT_MAX_BYTES = 2048;

export const PUSH_CATEGORIES = [
  'AUTHORIZATION_REQUEST',
  'INCOMING_PAYMENT',
  'OUTGOING_PAYMENT',
  'CARD_TRANSACTION',
  'ACCOUNT',
  'SECURITY',
  'GENERAL',
] as const;
export type PushCategory = (typeof PUSH_CATEGORIES)[number];

/** What the customer sees, after the app has decrypted the message. */
export interface PushContent {
  v: 1;
  category: PushCategory;
  title: string;
  body: string;
  /** Set for AUTHORIZATION_REQUEST: the app fetches and verifies it. */
  authorizationId: string | null;
  /** Small key-value data for the bank app (account ID, deep link name). */
  data: Record<string, string>;
  sentAt: string;
}

export interface PushEnvelope {
  v: 1;
  id: string;
  cid: string;
  iv: string;
  ct: string;
}

/** The push key agreed at registration, bound to the credential. */
export function derivePushKey(sharedSecret: Buffer, credentialId: string): Buffer {
  if (sharedSecret.length !== 32) throw new Error('ECDH shared secret must be 32 bytes');
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.from(PUSH_PROTOCOL_DOMAIN, 'utf8'), Buffer.from(credentialId, 'utf8'), 32));
}

export function pushAssociatedData(messageId: string, credentialId: string): Buffer {
  return Buffer.from(`${PUSH_PROTOCOL_DOMAIN}\n${messageId}\n${credentialId}`, 'utf8');
}

/** Names a push key without revealing it (22 base64url characters). */
export function pushKeyId(pushKey: Buffer): string {
  return createHmac('sha256', pushKey).update(PUSH_KEY_ID_DOMAIN, 'utf8').digest().subarray(0, 16).toString('base64url');
}

export function pushReceipt(pushKey: Buffer, messageId: string, credentialId: string): string {
  return createHmac('sha256', pushKey).update(`${PUSH_RECEIPT_DOMAIN}\n${messageId}\n${credentialId}`, 'utf8').digest('base64url');
}

export function isValidPushReceipt(pushKey: Buffer, messageId: string, credentialId: string, receipt: string): boolean {
  const expected = Buffer.from(pushReceipt(pushKey, messageId, credentialId), 'utf8');
  const given = Buffer.from(receipt, 'utf8');
  return given.length === expected.length && timingSafeEqual(given, expected);
}

const DISPLAY_UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u;

/** Rejects content that would not fit or that the app could not render safely. */
export function assertValidPushContent(content: PushContent): void {
  if (content.title.length === 0 || content.title.length > PUSH_TITLE_MAX) throw new Error(`title must be 1 to ${PUSH_TITLE_MAX} characters`);
  if (content.body.length > PUSH_BODY_MAX) throw new Error(`body must be at most ${PUSH_BODY_MAX} characters`);
  const entries = Object.entries(content.data);
  if (entries.length > PUSH_DATA_MAX_FIELDS) throw new Error(`at most ${PUSH_DATA_MAX_FIELDS} data fields`);
  for (const [key, value] of entries) {
    if (!PUSH_DATA_KEY_PATTERN.test(key)) throw new Error(`data key ${JSON.stringify(key)} is not allowed`);
    if (typeof value !== 'string' || value.length > PUSH_DATA_VALUE_MAX) throw new Error(`data value for ${key} must be a string of at most ${PUSH_DATA_VALUE_MAX} characters`);
  }
  // Bidi controls, zero-width and other format characters could make a
  // notification read differently from what the bank sent. Line breaks are
  // allowed in the body only. Lone surrogates are not valid text and would
  // not decode on the device.
  if (DISPLAY_UNSAFE.test(content.title)) throw new Error('title contains control, format or separator characters');
  if (DISPLAY_UNSAFE.test(content.body.replace(/\n/g, ''))) throw new Error('body contains control, format or separator characters');
  if (Buffer.byteLength(JSON.stringify(content), 'utf8') > PUSH_PLAINTEXT_MAX_BYTES) {
    throw new Error(`message is larger than ${PUSH_PLAINTEXT_MAX_BYTES} bytes`);
  }
}

/** Seals `content` for one device. `iv` is fixed only by the vector generator. */
export function sealPushMessage(pushKey: Buffer, messageId: string, credentialId: string, content: PushContent, iv: Buffer = randomBytes(IV_LENGTH)): PushEnvelope {
  if (pushKey.length !== 32) throw new Error('push key must be 32 bytes');
  if (iv.length !== IV_LENGTH) throw new Error(`IV must be ${IV_LENGTH} bytes`);
  assertValidPushContent(content);
  const cipher = createCipheriv('aes-256-gcm', pushKey, iv, { authTagLength: TAG_LENGTH });
  cipher.setAAD(pushAssociatedData(messageId, credentialId));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(content), 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { v: PUSH_ENVELOPE_VERSION, id: messageId, cid: credentialId, iv: iv.toString('base64url'), ct: ciphertext.toString('base64url') };
}

/** The device side, used by tests and the sandbox; the SDKs implement the same. */
export function openPushMessage(pushKey: Buffer, envelope: PushEnvelope): PushContent {
  if (envelope.v !== PUSH_ENVELOPE_VERSION) throw new Error('unsupported envelope version');
  const iv = Buffer.from(envelope.iv, 'base64url');
  const sealed = Buffer.from(envelope.ct, 'base64url');
  if (iv.length !== IV_LENGTH || sealed.length <= TAG_LENGTH) throw new Error('malformed envelope');
  const decipher = createDecipheriv('aes-256-gcm', pushKey, iv, { authTagLength: TAG_LENGTH });
  decipher.setAAD(pushAssociatedData(envelope.id, envelope.cid));
  decipher.setAuthTag(sealed.subarray(sealed.length - TAG_LENGTH));
  const plaintext = Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - TAG_LENGTH)), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8')) as PushContent;
}
