import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './support/load-ts.mjs';

const { base32Decode, base32Encode, totpCode, verifyTotp } = loadTs('crypto/totp.ts');

// RFC 6238 appendix B (SHA-1 seed), last six digits of the eight-digit values.
const secret = Buffer.from('12345678901234567890');
const vectors = [[59, '287082'], [1111111109, '081804'], [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037']];

test('TOTP codes match RFC 6238', () => {
  for (const [seconds, code] of vectors) assert.equal(totpCode(secret, Math.floor(seconds / 30)), code, String(seconds));
});

test('a code is accepted within one step of drift, and only after the last used step', () => {
  const now = 1111111111 * 1000;
  const step = Math.floor(1111111111 / 30);
  assert.equal(verifyTotp(secret, totpCode(secret, step), null, now), step);
  assert.equal(verifyTotp(secret, totpCode(secret, step - 1), null, now), step - 1);
  assert.equal(verifyTotp(secret, totpCode(secret, step + 1), null, now), step + 1);
  assert.equal(verifyTotp(secret, totpCode(secret, step - 2), null, now), null);
  assert.equal(verifyTotp(secret, totpCode(secret, step), step, now), null, 'replay');
  assert.equal(verifyTotp(secret, '12345', null, now), null);
  assert.equal(verifyTotp(secret, 'abcdef', null, now), null);
});

test('base32 round-trips (RFC 4648)', () => {
  assert.equal(base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI');
  assert.equal(base32Decode('MZXW6YTBOI').toString(), 'foobar');
  assert.equal(base32Encode(secret), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
});
