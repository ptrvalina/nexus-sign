import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { loadTs } from './support/load-ts.mjs';

const { canonicalizeAuthorization, hashCanonicalAuthorization } = loadTs('services/canonicalAuthorization.ts');
const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts');
const example = JSON.parse(readFileSync(new URL('../test-vectors/authorization-v1-example.json', import.meta.url), 'utf8'));
const { _canonical_utf8_base64: expectedBase64, _canonical_sha256: expectedHash, ...fields } = example;

test('authorization v1 example: canonical bytes and hash are stable', () => {
  const bytes = canonicalizeAuthorization(fields);
  assert.equal(bytes.toString('base64'), expectedBase64);
  assert.equal(hashCanonicalAuthorization(fields), expectedHash);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), expectedHash);
});

test('the server verifies a device signature over the canonical bytes and nothing else', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const hsm = new SoftwareHsmAdapter();
  const bytes = canonicalizeAuthorization(fields);
  const signature = sign('sha256', bytes, { key: privateKey, dsaEncoding: 'der' });
  assert.equal(await hsm.verifySignature(pem, bytes, signature, 'der'), true);

  const tampered = canonicalizeAuthorization({ ...fields, amount_minor: '1' });
  assert.equal(await hsm.verifySignature(pem, tampered, signature, 'der'), false);
  const reordered = Buffer.from(JSON.stringify(fields), 'utf8'); // same values, not canonical
  assert.equal(await hsm.verifySignature(pem, reordered, signature, 'der'), false);
});
