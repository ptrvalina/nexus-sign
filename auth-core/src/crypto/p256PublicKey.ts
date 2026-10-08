import { createPublicKey } from 'node:crypto';
import { ValidationError } from '../services/errors';

/** DER prefix of a SubjectPublicKeyInfo for id-ecPublicKey / prime256v1
 * followed by a 65-byte uncompressed point. */
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

export interface P256PublicKey {
  /** Normalized PEM, as stored in the credential registry. */
  pem: string;
  /** DER SubjectPublicKeyInfo. */
  spki: Buffer;
  /** Uncompressed EC point (0x04 || X || Y). */
  point: Buffer;
}

/** Strict PEM: header, base64 lines, footer. Anything else (a NUL byte,
 * trailing text, a second key) is refused before parsing, because the raw
 * PEM text is part of the attestation binding. */
const STRICT_PEM = /^-----BEGIN PUBLIC KEY-----\r?\n(?:[A-Za-z0-9+/=]{1,76}\r?\n)+-----END PUBLIC KEY-----(?:\r?\n)?$/;

/**
 * Parses a device public key and requires ECDSA P-256 in SubjectPublicKeyInfo
 * form. Every credential is recorded as ES256, so any other key type (RSA,
 * P-384, a compressed point, a certificate) is rejected at registration.
 */
export function parseP256PublicKey(pem: string): P256PublicKey {
  if (!STRICT_PEM.test(pem)) throw new ValidationError('publicKeyPem must be a single PEM public key');
  let spki: Buffer;
  try {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
      throw new ValidationError('publicKeyPem must be an ECDSA P-256 public key');
    }
    spki = key.export({ type: 'spki', format: 'der' });
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    throw new ValidationError('publicKeyPem is not a valid PEM public key');
  }
  if (spki.length !== P256_SPKI_PREFIX.length + 65 || !spki.subarray(0, P256_SPKI_PREFIX.length).equals(P256_SPKI_PREFIX)) {
    throw new ValidationError('publicKeyPem must use the uncompressed P-256 point encoding');
  }
  const body = spki.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return { pem: `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`, spki, point: spki.subarray(P256_SPKI_PREFIX.length) };
}
