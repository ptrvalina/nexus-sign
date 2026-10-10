import { randomBytes } from 'node:crypto';
import { redis } from '../db/redis';
import { tokenKey } from '../crypto/tokenDigest';
import { env } from '../config/env';
import { certificateMatches, getClientRecord } from './clientService';

/**
 * Opaque bearer tokens for bank backends, stored in Redis by digest. Unlike a
 * self-contained JWT, a token can be revoked instantly and is only
 * meaningful to this Auth Core deployment. Every request re-checks that the
 * bank client is still ACTIVE, so disabling a client takes effect at once.
 */
const TOKEN_KEY_PREFIX = 'oauth_token:';
const CLIENT_TOKENS_PREFIX = 'oauth_client_tokens:';
const TOKEN_BYTE_LENGTH = 32;

export interface IssuedToken {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}

export async function issueToken(clientId: string): Promise<IssuedToken> {
  const accessToken = randomBytes(TOKEN_BYTE_LENGTH).toString('base64url');
  const ttl = env.OAUTH_TOKEN_TTL_SECONDS;
  const key = tokenKey(TOKEN_KEY_PREFIX, accessToken);
  await redis.multi()
    .set(key, clientId, 'EX', ttl)
    .sadd(CLIENT_TOKENS_PREFIX + clientId, key)
    .expire(CLIENT_TOKENS_PREFIX + clientId, ttl)
    .exec();
  return { accessToken, tokenType: 'Bearer', expiresIn: ttl };
}

export type TokenResolution =
  | { clientId: string; outcome: 'ok' }
  | { clientId: string; outcome: 'certificate_mismatch' }
  | { clientId: null; outcome: 'invalid' };

/**
 * The client a token was issued to, if the token is known and unexpired and
 * its client is ACTIVE. With `certificateSha256` (the gateway's verified
 * client certificate, passed whenever mTLS is required) the certificate must
 * also be registered for that client, so a token taken from one bank cannot
 * be used through another bank's gateway connection.
 */
export async function resolveToken(accessToken: string, certificateSha256?: string | null): Promise<TokenResolution> {
  const clientId = await redis.get(tokenKey(TOKEN_KEY_PREFIX, accessToken));
  if (!clientId) return { clientId: null, outcome: 'invalid' };
  const client = await getClientRecord(clientId);
  if (client?.status !== 'ACTIVE') return { clientId: null, outcome: 'invalid' };
  if (certificateSha256 !== undefined && !certificateMatches(client, certificateSha256)) return { clientId, outcome: 'certificate_mismatch' };
  return { clientId, outcome: 'ok' };
}

/** Revokes every token of a client, e.g. after its secret is rotated. */
export async function revokeClientTokens(clientId: string): Promise<number> {
  const keys = await redis.smembers(CLIENT_TOKENS_PREFIX + clientId);
  if (keys.length > 0) await redis.del(...keys);
  await redis.del(CLIENT_TOKENS_PREFIX + clientId);
  return keys.length;
}
