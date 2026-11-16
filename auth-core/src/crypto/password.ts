import { randomBytes, scrypt as scryptCallback, timingSafeEqual, type ScryptOptions } from 'node:crypto';

/**
 * One-way hashing for secrets that only need to be verified. Secrets that
 * must be read back, such as webhook HMAC keys, use src/crypto/secretBox.ts.
 *
 * Two cost profiles:
 * - `password` (human-chosen admin passwords): scrypt N=2^17, r=8, p=1, the
 *   OWASP minimum for scrypt;
 * - `secret` (256-bit random bank client secrets, verified on every token
 *   request): N=2^14, r=8, p=1. Guessing a random 256-bit value is not
 *   helped by a low work factor, and a high one would let token requests
 *   exhaust memory.
 *
 * Stored as `scrypt$N$r$p$salt$hash`. The 1.4 format `scrypt$salt$hash`
 * (N=2^14, r=8, p=1) still verifies; `needsRehash` reports hashes below the
 * profile so they are upgraded at the next successful login.
 */
export type HashProfile = 'password' | 'secret';

const PROFILES: Record<HashProfile, { N: number; r: number; p: number }> = {
  password: { N: 2 ** 17, r: 8, p: 1 },
  secret: { N: 2 ** 14, r: 8, p: 1 },
};
const LEGACY = { N: 2 ** 14, r: 8, p: 1 };
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;
const MAX_N = 2 ** 20;

function scrypt(password: string, salt: Buffer, keylen: number, options: ScryptOptions): Promise<Buffer> {
  // 128 * N * r bytes plus headroom; Node's 32 MiB default is too small for N=2^17.
  const maxmem = 128 * (options.N ?? 0) * (options.r ?? 8) * 2;
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, { ...options, maxmem }, (error, key) => (error ? reject(error) : resolve(key)));
  });
}

interface Parsed { N: number; r: number; p: number; salt: Buffer; hash: Buffer }

function parse(stored: string): Parsed | null {
  const parts = stored.split('$');
  if (parts[0] !== 'scrypt') return null;
  if (parts.length === 3) return { ...LEGACY, salt: Buffer.from(parts[1] ?? '', 'base64'), hash: Buffer.from(parts[2] ?? '', 'base64') };
  if (parts.length !== 6) return null;
  const [N, r, p] = parts.slice(1, 4).map(Number);
  if (![N, r, p].every(Number.isInteger) || N < 2 ** 14 || N > MAX_N || (N & (N - 1)) !== 0 || r < 1 || r > 32 || p < 1 || p > 16) return null;
  return { N, r, p, salt: Buffer.from(parts[4] ?? '', 'base64'), hash: Buffer.from(parts[5] ?? '', 'base64') };
}

export async function hashPassword(plaintext: string, profile: HashProfile = 'password'): Promise<string> {
  const { N, r, p } = PROFILES[profile];
  const salt = randomBytes(SALT_LENGTH);
  const derived = await scrypt(plaintext, salt, KEY_LENGTH, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

export async function verifyPassword(plaintext: string, stored: string): Promise<boolean> {
  const parsed = parse(stored);
  if (!parsed || parsed.salt.length === 0 || parsed.hash.length === 0) return false;
  const candidate = await scrypt(plaintext, parsed.salt, parsed.hash.length, { N: parsed.N, r: parsed.r, p: parsed.p });
  return candidate.length === parsed.hash.length && timingSafeEqual(candidate, parsed.hash);
}

/** True when `stored` uses weaker parameters than the profile. */
export function needsRehash(stored: string, profile: HashProfile = 'password'): boolean {
  const parsed = parse(stored);
  const target = PROFILES[profile];
  return !parsed || parsed.N < target.N || parsed.r < target.r || parsed.p < target.p;
}

const dummyHashes: Partial<Record<HashProfile, Promise<string>>> = {};

/** Performs the same scrypt work as a real verification and returns false.
 * Called when the account does not exist, so response time does not reveal
 * which client IDs or usernames are registered. */
export async function verifyAgainstDummy(plaintext: string, profile: HashProfile = 'password'): Promise<false> {
  dummyHashes[profile] ??= hashPassword(randomBytes(16).toString('hex'), profile);
  await verifyPassword(plaintext, await dummyHashes[profile]!);
  return false;
}
