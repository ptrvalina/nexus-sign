import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { MASTER_KEY_NAMES, masterKeyMaterial } from './masterKeyVault';

/**
 * AES-256-GCM for the few secrets Auth Core must read back in plaintext:
 *
 * - `webhook`: a bank's webhook signing key, needed to compute the HMAC of
 *   every delivery (master key WEBHOOK_SECRET_ENCRYPTION_KEY);
 * - `device`: a credential's offline confirmation key and push key, needed to
 *   check offline codes and encrypt push messages (DEVICE_SECRET_ENCRYPTION_KEY);
 * - `admin`: an admin account's TOTP secret, needed to check its one-time
 *   codes (master key ADMIN_SECRET_ENCRYPTION_KEY).
 *
 * Credentials that only need to be verified (client secrets, recovery
 * verifiers) are hashed instead; do not use this module for those. Each master
 * key is 32 random bytes, base64-encoded, from the bank's secrets manager, and
 * the purpose (and the owning record) is bound into the ciphertext as
 * associated data.
 *
 * Key ring: the current key encrypts; previous keys are still
 * accepted for decryption during a rotation. The keys come from
 * masterKeyVault.ts: `<NAME>`/`<NAME>_PREVIOUS` in development, or wrapped
 * by an HSM key-encryption key (`<NAME>_WRAPPED`, MASTER_KEY_SOURCE=hsm). Ciphertexts written since 2.0.0 name their key:
 *
 *   k1$<key id>$<iv>$<auth tag>$<ciphertext>      key id: first 8 bytes of SHA-256(key), hex
 *
 * Older formats (`iv$tag$ct`, and `v2$iv$tag$ct` for webhook secrets) are
 * still read, trying the current key and then the previous ones.
 * `cli/rotateSecretKeys.js` re-encrypts stored secrets under the current key.
 */
export type SecretPurpose = 'webhook' | 'device' | 'admin';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const FORMAT = 'k1';

export { MASTER_KEY_NAMES };

interface RingKey { id: string; key: Buffer }

export function masterKeyId(key: Buffer): string {
  return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

/** Current and previous master keys of a purpose (from the environment or,
 * with MASTER_KEY_SOURCE=hsm, unwrapped by the HSM at startup). */
export function keyRing(purpose: SecretPurpose): { current: RingKey; previous: RingKey[] } {
  const material = masterKeyMaterial(purpose);
  if (!material) throw new Error(`${MASTER_KEY_NAMES[purpose]} is not configured`);
  return {
    current: { id: masterKeyId(material.current), key: material.current },
    previous: material.previous.map((key) => ({ id: masterKeyId(key), key })),
  };
}

/** Associated data: the purpose and the owning record, so a ciphertext
 * copied to another row fails to decrypt. */
function associatedData(purpose: SecretPurpose, owner?: string): Buffer {
  return Buffer.from(owner ? `${purpose}:${owner}` : purpose, 'utf8');
}

function seal(key: Buffer, plaintext: string | Buffer, aad: Buffer | null): [string, string, string] {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return [iv.toString('base64'), cipher.getAuthTag().toString('base64'), ciphertext.toString('base64')];
}

function open(key: Buffer, [ivB64, tagB64, ctB64]: string[], aad: Buffer | null): Buffer {
  const authTag = Buffer.from(tagB64, 'base64');
  if (authTag.length !== 16) throw new Error('Stored encrypted secret is malformed');
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(ivB64, 'base64'), { authTagLength: 16 });
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]);
}

/** Encrypts under the current master key of the purpose: `k1$keyId$iv$tag$ct`. */
export function encryptSecret(plaintext: string | Buffer, purpose: SecretPurpose = 'webhook', owner?: string): string {
  if (purpose === 'webhook' && !owner) throw new Error('webhook secrets are bound to their bank client');
  const { current } = keyRing(purpose);
  return [FORMAT, current.id, ...seal(current.key, plaintext, associatedData(purpose, owner))].join('$');
}

export function decryptSecretBytes(stored: string, purpose: SecretPurpose = 'webhook', owner?: string): Buffer {
  const parts = stored.split('$');
  const ring = keyRing(purpose);
  const aad = associatedData(purpose, owner);
  if (parts[0] === FORMAT) {
    if (parts.length !== 5) throw new Error('Stored encrypted secret is malformed');
    const key = [ring.current, ...ring.previous].find((k) => k.id === parts[1]);
    if (!key) throw new Error(`Stored secret is encrypted with master key ${parts[1]}, which is neither ${MASTER_KEY_NAMES[purpose]} nor listed in ${MASTER_KEY_NAMES[purpose]}_PREVIOUS`);
    return open(key.key, parts.slice(2), aad);
  }
  // Formats before 2.0.0: no key ID. Webhook secrets without the v2 prefix
  // have no associated data.
  const legacyWebhookUnbound = purpose === 'webhook' && parts[0] !== 'v2';
  const body = purpose === 'webhook' && parts[0] === 'v2' ? parts.slice(1) : parts;
  if (body.length !== 3) throw new Error('Stored encrypted secret is malformed');
  let lastError: unknown;
  for (const key of [ring.current, ...ring.previous]) {
    try {
      return open(key.key, body, legacyWebhookUnbound ? null : aad);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error('Stored encrypted secret could not be decrypted');
}

export function decryptSecret(stored: string, purpose: SecretPurpose = 'webhook', owner?: string): string {
  return decryptSecretBytes(stored, purpose, owner).toString('utf8');
}

/** True when the stored value is not yet encrypted under the current key. */
export function needsRewrap(stored: string, purpose: SecretPurpose): boolean {
  const parts = stored.split('$');
  return !(parts[0] === FORMAT && parts[1] === keyRing(purpose).current.id);
}

/** Re-encrypts a stored secret under the current key (same plaintext, same binding). */
export function rewrapSecret(stored: string, purpose: SecretPurpose, owner?: string): string {
  return encryptSecret(decryptSecretBytes(stored, purpose, owner), purpose, owner);
}
