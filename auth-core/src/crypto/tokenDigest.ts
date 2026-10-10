import { createHash } from 'node:crypto';

/**
 * Redis key for a bearer token or session cookie. Only the SHA-256 of the
 * token is stored, so read access to Redis (a replica, a backup, a memory
 * dump) does not yield usable credentials.
 */
export function tokenKey(prefix: string, token: string): string {
  return prefix + createHash('sha256').update(token, 'utf8').digest('base64url');
}
