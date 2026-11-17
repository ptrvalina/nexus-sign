import { createHash, createHmac, hkdfSync } from 'node:crypto';

/**
 * Device protocols v1: how an enrolled device authenticates its own requests
 * without a bearer token, and how it confirms a transaction offline.
 * Specification: docs/protocol/device-authentication-and-offline-confirmation.md.
 * Shared vectors: test-vectors/device-protocols-v1.json.
 */

const DEVICE_REQUEST_DOMAIN = 'NEXUS-SIGN/DEVICE-REQUEST/v1';
export const OFFLINE_KDF_SALT = 'NEXUS-SIGN/OFFLINE/v1';
/** Offline v3 (finding D-01): a fresh Auth Core key for each authorization. */
export const OFFLINE_KDF_SALT_V3 = 'NEXUS-SIGN/OFFLINE/v3';
export const OFFLINE_CODE_DOMAIN = 'NEXUS-SIGN/OFFLINE-CODE/v1';
/** v1: code only. v2: the device also signs the bytes (deferred signature,
 * docs/protocol/offline-confirmation-v2-deferred-signature.md); SDKs up to
 * 2.0.0 refuse it, so they cannot leave a payment provisional. */
const OFFLINE_QR_PREFIX = { 1: 'NXS1.', 2: 'NXS2.', 3: 'NXS3.' } as const;
export const OFFLINE_CODE_DIGITS = 8;

export interface DeviceRequestParts {
  method: string;
  /** Path and query exactly as sent, starting with `/v1/`. */
  path: string;
  timestamp: string;
  nonce: string;
  credentialId: string;
  body: Buffer;
}

/** The exact bytes a device signs with its authentication key. */
export function deviceRequestSigningInput(parts: DeviceRequestParts): Buffer {
  const bodyHash = createHash('sha256').update(parts.body).digest('hex');
  return Buffer.from([
    DEVICE_REQUEST_DOMAIN,
    parts.method.toUpperCase(),
    parts.path,
    parts.timestamp,
    parts.nonce,
    parts.credentialId,
    bodyHash,
  ].join('\n'), 'utf8');
}

/**
 * Offline confirmation key: HKDF-SHA256 over the ECDH shared secret (the
 * 32-byte x coordinate) of the device offline key and the server's
 * per-credential key, bound to the credential ID.
 */
export function deriveOfflineKey(sharedSecret: Buffer, credentialId: string): Buffer {
  if (sharedSecret.length !== 32) throw new Error('ECDH shared secret must be 32 bytes');
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.from(OFFLINE_KDF_SALT, 'utf8'), Buffer.from(credentialId, 'utf8'), 32));
}

/** HMAC-SHA256(K, domain || 0x00 || SHA-256(canonical bytes)); kept as evidence. */
export function offlineConfirmationTag(offlineKey: Buffer, canonicalPayload: Buffer): Buffer {
  const payloadHash = createHash('sha256').update(canonicalPayload).digest();
  return createHmac('sha256', offlineKey)
    .update(Buffer.concat([Buffer.from(OFFLINE_CODE_DOMAIN, 'utf8'), Buffer.from([0]), payloadHash]))
    .digest();
}

/** The code the customer types: RFC 4226 dynamic truncation of the tag, 8 digits. */
export function offlineCodeFromTag(tag: Buffer): string {
  const offset = tag[tag.length - 1] & 0x0f;
  const binary = ((tag[offset] & 0x7f) << 24) | (tag[offset + 1] << 16) | (tag[offset + 2] << 8) | tag[offset + 3];
  return String(binary % 10 ** OFFLINE_CODE_DIGITS).padStart(OFFLINE_CODE_DIGITS, '0');
}

/**
 * Offline v3 key (finding D-01): HKDF-SHA256 over the ECDH shared secret of
 * the device offline key and Auth Core's key for this one authorization,
 * bound to the credential and the authorization. A secret taken from the
 * device process serves this authorization only.
 */
export function deriveOfflineKeyPerAuthorization(sharedSecret: Buffer, credentialId: string, authorizationId: string): Buffer {
  if (sharedSecret.length !== 32) throw new Error('ECDH shared secret must be 32 bytes');
  const info = Buffer.concat([Buffer.from(credentialId, 'utf8'), Buffer.from([0]), Buffer.from(authorizationId, 'utf8')]);
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.from(OFFLINE_KDF_SALT_V3, 'utf8'), info, 32));
}

/** v3 QR content: `NXS3.` + base64url(canonical bytes) + `.` + base64url(DER SPKI of Auth Core's key for this authorization). */
export function offlineQrPayloadV3(canonicalPayload: Buffer, serverPublicKeySpki: Buffer): string {
  return `${OFFLINE_QR_PREFIX[3]}${canonicalPayload.toString('base64url')}.${serverPublicKeySpki.toString('base64url')}`;
}

/** QR content: prefix + base64url(canonical bytes). */
export function offlineQrPayload(canonicalPayload: Buffer, version: 1 | 2 = 1): string {
  return OFFLINE_QR_PREFIX[version] + canonicalPayload.toString('base64url');
}
