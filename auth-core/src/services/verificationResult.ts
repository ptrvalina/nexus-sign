import { JwsError, parseEs256Jws, verifyEs256 } from '../crypto/jws';

/**
 * Verification result v1: how an audio or video verification
 * provider reports a result that Auth Core can check itself, instead of
 * trusting the bank gateway that relays it.
 * Specification: docs/protocol/verification-result-v1.md.
 *
 *   header  { alg: "ES256", typ: "nexus-verification-result+jwt", kid }
 *   claims  { iss: providerId, aud: "nexus-sign:<clientId>", sub: sessionId,
 *             authorization_id, canonical_payload_hash, credential_id,
 *             channel: "AUDIO" | "VIDEO", result: "VERIFIED" | "FAILED",
 *             session_nonce_sha256, iat, exp, jti, assurance? }
 *
 * The provider key is looked up by (bank, iss, kid) among keys the Auth Core
 * operator registered (cli/registerVerificationProvider.ts); the bank backend
 * cannot register keys through the API, so a compromised bank gateway alone
 * cannot produce a result that verifies.
 */
export const RESULT_TOKEN_TYPE = 'nexus-verification-result+jwt';
export const MAX_RESULT_LIFETIME_SECONDS = 600;
export const CLOCK_SKEW_SECONDS = 60;

export interface ResultExpectations {
  clientId: string;
  sessionId: string;
  authorizationId: string;
  canonicalPayloadHash: string;
  credentialId: string;
  channel: 'AUDIO' | 'VIDEO';
  /** SHA-256 (hex) of the session nonce, as stored for the session. */
  sessionNonceSha256: string;
  nowSeconds: number;
}

export interface ProviderKey {
  providerId: string;
  keyId: string;
  channels: string[];
  publicKeyPem: string;
}

export interface VerifiedResult {
  result: 'VERIFIED' | 'FAILED';
  providerId: string;
  keyId: string;
  jti: string;
  assurance: string | null;
  issuedAt: number;
}

export class VerificationResultError extends Error {
  constructor(readonly reason: string) { super(`Verification result rejected: ${reason}`); this.name = 'VerificationResultError'; }
}

type KeyLookup = (providerId: string, keyId: string) => Promise<ProviderKey | null>;

function claim(payload: Record<string, unknown>, name: string, pattern?: RegExp): string {
  const value = payload[name];
  if (typeof value !== 'string' || (pattern && !pattern.test(value))) throw new VerificationResultError(`claim ${name} is missing or malformed`);
  return value;
}

function seconds(payload: Record<string, unknown>, name: string): number {
  const value = payload[name];
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) throw new VerificationResultError(`claim ${name} is missing or malformed`);
  return value;
}

/** Verifies a provider result token against the session it claims to close.
 * Every check is a refusal; there is no partial acceptance. */
export async function verifyResultToken(token: string, expected: ResultExpectations, lookupKey: KeyLookup): Promise<VerifiedResult> {
  let parsed;
  try {
    parsed = parseEs256Jws(token);
  } catch (error) {
    throw new VerificationResultError(error instanceof JwsError ? error.message : 'token is malformed');
  }
  if (parsed.header.typ !== RESULT_TOKEN_TYPE) throw new VerificationResultError(`typ must be ${RESULT_TOKEN_TYPE}`);
  const keyId = typeof parsed.header.kid === 'string' ? parsed.header.kid : '';
  const p = parsed.payload;
  const providerId = claim(p, 'iss', /^[A-Za-z0-9._-]{1,64}$/);
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(keyId)) throw new VerificationResultError('kid is missing or malformed');

  const key = await lookupKey(providerId, keyId);
  if (!key) throw new VerificationResultError('unknown or retired provider key');
  let valid: boolean;
  try {
    valid = verifyEs256(parsed, key.publicKeyPem);
  } catch (error) {
    throw new VerificationResultError(error instanceof JwsError ? error.message : 'signature check failed');
  }
  if (!valid) throw new VerificationResultError('signature does not verify');

  // Bound to this bank, this session, this transaction and this device.
  if (claim(p, 'aud') !== `nexus-sign:${expected.clientId}`) throw new VerificationResultError('aud does not name this bank');
  if (claim(p, 'sub') !== expected.sessionId) throw new VerificationResultError('sub is not this verification session');
  if (claim(p, 'authorization_id') !== expected.authorizationId) throw new VerificationResultError('authorization_id does not match');
  if (claim(p, 'canonical_payload_hash') !== expected.canonicalPayloadHash) throw new VerificationResultError('canonical_payload_hash does not match the transaction');
  if (claim(p, 'credential_id') !== expected.credentialId) throw new VerificationResultError('credential_id does not match');
  const channel = claim(p, 'channel');
  if (channel !== expected.channel) throw new VerificationResultError('channel does not match the session');
  if (!key.channels.includes(channel)) throw new VerificationResultError(`the provider key is not registered for ${channel}`);
  if (claim(p, 'session_nonce_sha256') !== expected.sessionNonceSha256) throw new VerificationResultError('session_nonce_sha256 does not match the session');
  const result = claim(p, 'result');
  if (result !== 'VERIFIED' && result !== 'FAILED') throw new VerificationResultError('result must be VERIFIED or FAILED');

  // Fresh and short-lived.
  const iat = seconds(p, 'iat');
  const exp = seconds(p, 'exp');
  if (iat > expected.nowSeconds + CLOCK_SKEW_SECONDS) throw new VerificationResultError('iat is in the future');
  if (exp <= expected.nowSeconds) throw new VerificationResultError('the result has expired');
  if (exp <= iat || exp - iat > MAX_RESULT_LIFETIME_SECONDS) throw new VerificationResultError(`exp must be after iat and at most ${MAX_RESULT_LIFETIME_SECONDS} s later`);

  const jti = claim(p, 'jti', /^[A-Za-z0-9._:-]{16,128}$/);
  const assurance = p.assurance === undefined ? null : claim(p, 'assurance', /^[A-Za-z0-9 ._:-]{1,64}$/);
  return { result, providerId, keyId, jti, assurance, issuedAt: iat };
}
