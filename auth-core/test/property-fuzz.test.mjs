// Property and fuzz tests over the parsers and encoders a hostile input
// reaches first. Deterministic: the generator is seeded, and a failure prints
// the seed and the input (FUZZ_SEED and FUZZ_RUNS override the defaults).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { loadTs } from './support/load-ts.mjs';

const { canonicalizeAuthorization, canonicalJson, assertValidBeneficiary, DISPLAY_UNSAFE_CHARACTER } = loadTs('services/canonicalAuthorization.ts');
const { parseDerElement } = loadTs('crypto/der.ts');
const { parseP256PublicKey } = loadTs('crypto/p256PublicKey.ts');
const { verifyTotp, totpCode, base32Encode, base32Decode } = loadTs('crypto/totp.ts');
const { hashPassword, verifyPassword, needsRehash } = loadTs('crypto/password.ts');
const { normalizeFingerprint, normalizeIp } = loadTs('middleware/mtlsGateway.ts', { stubs: { '../config/env': { env: {} } } });

const RUNS = Number(process.env.FUZZ_RUNS ?? 400);
const SEED = Number(process.env.FUZZ_SEED ?? 20261006);

/** Mulberry32: small, seeded, good enough for test input generation. */
function rng(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const random = rng(SEED);
const int = (n) => Math.floor(random() * n);
const pick = (xs) => xs[int(xs.length)];

// Code points that a display-safe string may and may not contain.
const SAFE = ['a', 'Z', '0', ' ', 'ł', 'é', 'Ж', '中', '€', '😀', '-', '/', '"', '\\'];
const UNSAFE = ['\n', '\r', '\t', '\u0000', '\u007f', '​', '‎', '‮', '⁦', ' ', ' ', '﻿', '\ud800', '\udfff'];
const safeString = () => Array.from({ length: int(24) }, () => pick(SAFE)).join('');

const base = {
  version: '1', domain: 'NEXUS-SIGN/TRANSACTION-AUTH', authorization_id: '00000000-0000-4000-8000-000000000001',
  nexus_id: '123456789', credential_id: '00000000-0000-4000-8000-000000000002', transaction_reference: 'TX-1',
  operation_type: 'PAYMENT', amount_minor: '125000', currency: 'PLN', beneficiary: { name: 'Jan', iban: 'PL61109010140000071219812874' },
  policy_reference: 'p', policy_version: '1', nonce: 'n', issued_at: '2026-10-06T10:00:00Z', expires_at: '2026-10-06T10:05:00Z',
};

const fail = (what, input) => assert.fail(`${what} (FUZZ_SEED=${SEED}) input=${JSON.stringify(input)}`);

test('canonical JSON is key-order independent, round-trips and is valid UTF-8', () => {
  for (let i = 0; i < RUNS; i += 1) {
    const value = Object.fromEntries(Array.from({ length: 1 + int(8) }, () => [`k${int(50)}_${safeString().replace(/[^a-z]/g, '')}`, int(4) === 0 ? { [`n${int(9)}`]: safeString() } : safeString()]));
    const shuffled = Object.fromEntries(Object.entries(value).sort(() => random() - 0.5));
    const a = canonicalJson(value); const b = canonicalJson(shuffled);
    if (!a.equals(b)) fail('order changed the bytes', value);
    if (Buffer.from(a.toString('utf8'), 'utf8').compare(a) !== 0) fail('not valid UTF-8', value);
    assert.deepEqual(JSON.parse(a.toString('utf8')), value);
  }
});

test('a beneficiary value is accepted exactly when it satisfies the display text rules', () => {
  // Independent oracle for the rules in docs/protocol/authorization-protocol-v1.md.
  const LATIN = new Set(['a', 'Z', 'ł', 'é']);
  const CYRILLIC = new Set(['Ж']);
  for (let i = 0; i < RUNS; i += 1) {
    const chars = Array.from({ length: 1 + int(20) }, () => (int(6) === 0 ? pick(UNSAFE) : pick(SAFE)));
    const text = chars.join('');
    // Surrogates are judged on the joined text: \ud800 followed by \udfff is a
    // valid pair (U+103FF), not two lone surrogates.
    const refused = chars.some((c) => UNSAFE.includes(c) && !/[\ud800-\udfff]/.test(c))
      || !text.isWellFormed()
      || text !== text.normalize('NFC')
      || /^\p{Zs}|\p{Zs}$/u.test(text)
      || text.includes('  ')
      || (chars.some((c) => LATIN.has(c)) && chars.some((c) => CYRILLIC.has(c)));
    let accepted = true;
    try { canonicalizeAuthorization({ ...base, beneficiary: { name: text, iban: 'PL61109010140000071219812874' } }); } catch { accepted = false; }
    if (accepted === refused) fail(refused ? 'unsafe value accepted' : 'safe value refused', text);
  }
  assert.ok(DISPLAY_UNSAFE_CHARACTER.test('\ud83d'), 'a lone high surrogate is unsafe');
  assert.ok(!DISPLAY_UNSAFE_CHARACTER.test('😀'), 'a surrogate pair is a normal character');
  assert.throws(() => assertValidBeneficiary({ name: 'ACME\udc00' }));
});

test('the DER parser never crashes, loops or reads past its input on random and mutated bytes', () => {
  const seedDer = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004' + '11'.repeat(64), 'hex');
  for (let i = 0; i < RUNS * 5; i += 1) {
    const input = int(2) === 0 ? randomBytes(int(80)) : Buffer.from(seedDer).map((byte) => (int(20) === 0 ? int(256) : byte));
    try {
      const element = parseDerElement(input);
      if (element.end > input.length || element.end <= 0) fail('element outside the input', input.toString('hex'));
    } catch (error) {
      if (!(error instanceof Error)) fail('non-Error thrown', input.toString('hex'));
    }
  }
});

test('P-256 public key parsing refuses every mutation of a valid PEM it cannot prove valid', () => {
  const valid = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.ok(parseP256PublicKey(valid));
  let accepted = 0;
  for (let i = 0; i < RUNS; i += 1) {
    const chars = [...valid];
    const at = 27 + int(chars.length - 60);
    chars[at] = pick('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.split(''));
    const mutated = chars.join('');
    if (mutated === valid) continue;
    try { parseP256PublicKey(mutated); accepted += 1; } catch (error) { if (!(error instanceof Error)) fail('non-Error thrown', mutated); }
  }
  // Mutations inside the point coordinates that stay on the curve are vanishingly rare.
  assert.ok(accepted < RUNS / 50, `${accepted} mutated keys accepted`);
});

test('TOTP: only the codes of the three current steps verify, never twice', () => {
  for (let i = 0; i < RUNS / 4; i += 1) {
    const secret = randomBytes(20);
    assert.deepEqual(base32Decode(base32Encode(secret)), secret);
    const now = 1_700_000_000_000 + int(1e9) * 1000;
    const step = Math.floor(now / 30000);
    const code = String(int(1e6)).padStart(6, '0');
    const valid = [step - 1, step, step + 1].filter((s) => totpCode(secret, s) === code);
    const result = verifyTotp(secret, code, null, now);
    if ((valid.length > 0) !== (result !== null)) fail('random code verdict', { code, step });
    if (result !== null && verifyTotp(secret, code, result, now) !== null && valid.filter((s) => s > result).length === 0) fail('replay accepted', { code });
  }
});

test('password hashes: new format, legacy format still verifies and is flagged for rehash', async () => {
  const stored = await hashPassword('correct horse battery staple');
  assert.match(stored, /^scrypt\$131072\$8\$1\$/);
  assert.equal(await verifyPassword('correct horse battery staple', stored), true);
  assert.equal(await verifyPassword('wrong', stored), false);
  assert.equal(needsRehash(stored), false);
  const secret = await hashPassword('random-client-secret', 'secret');
  assert.match(secret, /^scrypt\$16384\$8\$1\$/);
  assert.equal(needsRehash(secret, 'secret'), false);
  assert.equal(needsRehash(secret, 'password'), true);
  // 1.4 format: scrypt$salt$hash with N=2^14.
  const { scryptSync } = await import('node:crypto');
  const salt = randomBytes(16);
  const legacy = `scrypt$${salt.toString('base64')}$${scryptSync('old password', salt, 64).toString('base64')}`;
  assert.equal(await verifyPassword('old password', legacy), true);
  assert.equal(needsRehash(legacy), true);
  for (const malformed of ['scrypt$1$8$1$AA==$AA==', 'scrypt$16384$8$1$$', 'bcrypt$x', 'scrypt$3000$8$1$AA==$AA==']) {
    assert.equal(await verifyPassword('x', malformed), false, malformed);
  }
});

test('certificate fingerprints and peer addresses normalise to one form', () => {
  for (let i = 0; i < RUNS; i += 1) {
    const hex = randomBytes(32).toString('hex');
    const variants = [hex, hex.toUpperCase(), hex.match(/../g).join(':'), ` ${hex} `];
    for (const v of variants) assert.equal(normalizeFingerprint(v), hex);
    assert.equal(normalizeFingerprint(hex.slice(1)), null);
    assert.equal(normalizeFingerprint(`${hex}00`), null);
  }
  assert.equal(normalizeIp('::ffff:10.0.0.1'), '10.0.0.1');
  assert.equal(normalizeIp('10.0.0.1'), '10.0.0.1');
  assert.equal(normalizeIp('::1'), '::1');
});
