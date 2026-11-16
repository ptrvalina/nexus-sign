import { createPublicKey, verify } from 'node:crypto';

/**
 * Compact JWS (RFC 7515) with ES256 only (RFC 7518 section 3.4): ECDSA P-256
 * over SHA-256, signature as r || s (64 bytes). Nothing else is accepted: no
 * other algorithm, no `none`, no key or certificate carried in the header
 * (`jwk`, `jku`, `x5c`, `x5u`), no critical extensions. The verification key
 * is always chosen by the caller from its own registry, by `kid`.
 */
export interface ParsedJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: Buffer;
  signature: Buffer;
}

export class JwsError extends Error {
  constructor(message: string) { super(message); this.name = 'JwsError'; }
}

const B64URL = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_HEADER_PARAMETERS = ['jwk', 'jku', 'x5c', 'x5u', 'crit'];

function decodeJson(part: string, what: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    throw new JwsError(`${what} is not base64url JSON`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new JwsError(`${what} is not a JSON object`);
  return value as Record<string, unknown>;
}

/** Splits and decodes a compact ES256 JWS without verifying it. */
export function parseEs256Jws(token: string, maxLength = 8192): ParsedJws {
  if (typeof token !== 'string' || token.length > maxLength) throw new JwsError('token is missing or too long');
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((p) => B64URL.test(p))) throw new JwsError('token is not a compact JWS');
  const header = decodeJson(parts[0], 'header');
  if (header.alg !== 'ES256') throw new JwsError('alg must be ES256');
  for (const name of FORBIDDEN_HEADER_PARAMETERS) {
    if (name in header) throw new JwsError(`header parameter "${name}" is not accepted`);
  }
  const signature = Buffer.from(parts[2], 'base64url');
  if (signature.length !== 64) throw new JwsError('ES256 signature must be 64 bytes');
  return {
    header,
    payload: decodeJson(parts[1], 'payload'),
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
    signature,
  };
}

/** True when the JWS signature verifies with the P-256 public key. */
export function verifyEs256(parsed: ParsedJws, publicKeyPem: string): boolean {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new JwsError('verification key is not a P-256 key');
  }
  return verify('sha256', parsed.signingInput, { key, dsaEncoding: 'ieee-p1363' }, parsed.signature);
}
