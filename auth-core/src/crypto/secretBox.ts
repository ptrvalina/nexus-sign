import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { env } from '../config/env';

/**
 * AES-256-GCM for the few secrets Auth Core must read back in plaintext:
 *
 * - `webhook`: a bank's webhook signing key, needed to compute the HMAC of
 *   every delivery (master key WEBHOOK_SECRET_ENCRYPTION_KEY);
 * - `device`: a credential's offline confirmation key, needed to check the
 *   customer's offline code (master key DEVICE_SECRET_ENCRYPTION_KEY);
 * - `admin`: an admin account's TOTP secret, needed to check its one-time
 *   codes (master key ADMIN_SECRET_ENCRYPTION_KEY).
 *
 * Credentials that only need to be verified (client secrets, recovery
 * verifiers) are hashed instead; do not use this module for those. Each master
 * key is 32 random bytes, base64-encoded, from the bank's secrets manager, and
 * the purpose is bound into the ciphertext as associated data.
 */
export type SecretPurpose = 'webhook' | 'device' | 'admin';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

function masterKey(purpose: SecretPurpose): Buffer {
  const name = ({ webhook: 'WEBHOOK_SECRET_ENCRYPTION_KEY', device: 'DEVICE_SECRET_ENCRYPTION_KEY', admin: 'ADMIN_SECRET_ENCRYPTION_KEY' } as const)[purpose];
  const raw = env[name];
  if (!raw) throw new Error(`${name} is not configured`);
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) throw new Error(`${name} must decode to exactly 32 bytes`);
  return key;
}

/** Associated data: the purpose and, for device secrets, the owning record,
 * so a ciphertext copied to another row fails to decrypt. */
function associatedData(purpose: SecretPurpose, owner?: string): Buffer {
  return Buffer.from(owner ? `${purpose}:${owner}` : purpose, 'utf8');
}

/**
 * Returns `iv$authTag$ciphertext` (each base64) for a single TEXT column, or
 * for webhook secrets `v2$iv$authTag$ciphertext`, bound to the bank client as
 * associated data so a secret copied to another bank's row fails to decrypt
 * (NXS-035).
 */
export function encryptSecret(plaintext: string | Buffer, purpose: SecretPurpose = 'webhook', owner?: string): string {
  if (purpose === 'webhook' && !owner) throw new Error('webhook secrets are bound to their bank client');
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, masterKey(purpose), iv);
  cipher.setAAD(associatedData(purpose, owner));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const parts = [iv.toString('base64'), cipher.getAuthTag().toString('base64'), ciphertext.toString('base64')];
  return (purpose === 'webhook' ? ['v2', ...parts] : parts).join('$');
}

export function decryptSecretBytes(stored: string, purpose: SecretPurpose = 'webhook', owner?: string): Buffer {
  let parts = stored.split('$');
  // Webhook secrets written before 2.0 have no associated data.
  const bound = purpose !== 'webhook' || parts[0] === 'v2';
  if (purpose === 'webhook' && parts[0] === 'v2') parts = parts.slice(1);
  if (parts.length !== 3) throw new Error('Stored encrypted secret is malformed');
  const [ivB64, authTagB64, ciphertextB64] = parts;
  const authTag = Buffer.from(authTagB64, 'base64');
  if (authTag.length !== 16) throw new Error('Stored encrypted secret is malformed');
  const decipher = createDecipheriv(ALGORITHM, masterKey(purpose), Buffer.from(ivB64, 'base64'), { authTagLength: 16 });
  if (bound) decipher.setAAD(associatedData(purpose, owner));
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(Buffer.from(ciphertextB64, 'base64')), decipher.final()]);
}

export function decryptSecret(stored: string, purpose: SecretPurpose = 'webhook', owner?: string): string {
  return decryptSecretBytes(stored, purpose, owner).toString('utf8');
}
