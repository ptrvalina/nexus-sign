import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { loadTs } from './support/load-ts.mjs';

const { rawToDer, derToRaw } = loadTs('crypto/ecdsaSignatureFormat.ts');
const { parseP256PublicKey } = loadTs('crypto/p256PublicKey.ts');
const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts');
const { buildAttestationBinding, hashAttestationBinding } = loadTs('services/attestationBinding.ts');

const p256 = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const pemOf = (key) => key.export({ type: 'spki', format: 'pem' }).toString();

test('DER and raw conversion round-trips and stays verifiable (200 signatures)', () => {
  const { privateKey, publicKey } = p256();
  for (let i = 0; i < 200; i += 1) {
    const message = Buffer.from(`message ${i}`);
    const der = sign('sha256', message, { key: privateKey, dsaEncoding: 'der' });
    const raw = derToRaw(der);
    assert.equal(raw.length, 64);
    assert.ok(verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, raw));
    assert.ok(verify('sha256', message, { key: publicKey, dsaEncoding: 'der' }, rawToDer(raw)));
  }
});

test('DER to raw accepts only the canonical encoding', () => {
  const { privateKey } = p256();
  const der = sign('sha256', Buffer.from('payload'), { key: privateKey, dsaEncoding: 'der' });
  const withTrailingByte = Buffer.concat([der, Buffer.from([0x00])]);
  const longerLength = Buffer.from(der); longerLength[1] += 1;
  const r = der.subarray(4, 4 + der[3]);
  const s = der.subarray(4 + der[3] + 2);
  const paddedR = Buffer.concat([Buffer.from([0x02, r.length + 1, 0x00]), r]);
  const nonMinimal = Buffer.concat([Buffer.from([0x30, paddedR.length + s.length + 2]), paddedR, Buffer.from([0x02, s.length]), s]);
  for (const bad of [withTrailingByte, longerLength, nonMinimal, Buffer.from([0x30, 0x00]), Buffer.alloc(0)]) {
    assert.throws(() => derToRaw(bad));
  }
});

test('device public keys: only uncompressed P-256 SPKI is accepted', () => {
  const parsed = parseP256PublicKey(pemOf(p256().publicKey));
  assert.equal(parsed.point.length, 65);
  assert.equal(parsed.point[0], 0x04);
  const rejects = [
    pemOf(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey),
    pemOf(generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey),
    pemOf(generateKeyPairSync('ed25519').publicKey),
    '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n',
    'not a key',
  ];
  for (const pem of rejects) assert.throws(() => parseP256PublicKey(pem), { name: 'ValidationError' });
});

test('software HSM: malformed keys and signatures are invalid, never errors', async () => {
  const hsm = new SoftwareHsmAdapter();
  const { privateKey, publicKey } = p256();
  const payload = Buffer.from('payload');
  const der = sign('sha256', payload, { key: privateKey, dsaEncoding: 'der' });
  assert.equal(await hsm.verifySignature(pemOf(publicKey), payload, der, 'der'), true);
  assert.equal(await hsm.verifySignature(pemOf(publicKey), payload, derToRaw(der), 'raw'), true);
  assert.equal(await hsm.verifySignature(pemOf(publicKey), Buffer.from('other'), der, 'der'), false);
  assert.equal(await hsm.verifySignature(pemOf(publicKey), payload, Buffer.alloc(10), 'raw'), false);
  assert.equal(await hsm.verifySignature(pemOf(publicKey), payload, Buffer.from('garbage'), 'der'), false);
  assert.equal(await hsm.verifySignature('not a key', payload, der, 'der'), false);
});

test('software HSM: evidence seals verify with the published evidence key', async () => {
  const hsm = new SoftwareHsmAdapter();
  await hsm.healthCheck();
  const digest = createHash('sha256').update('evidence').digest();
  const { signature } = await hsm.signEvidence(digest);
  assert.ok(verify('sha256', digest, { key: await hsm.evidencePublicKeyPem(), dsaEncoding: 'der' }, signature));
});

test('attestation binding: known-answer vector', () => {
  const challenge = createHash('sha256').update('ms_test_bootstrap_token', 'utf8').digest();
  const pem = '-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----';
  const binding = buildAttestationBinding(challenge, pem);
  assert.deepEqual(binding, Buffer.concat([challenge, Buffer.from([0]), Buffer.from(pem, 'utf8')]));
  assert.equal(hashAttestationBinding(binding).toString('base64url'), 'mazPV5IJxfbF4Nyg1JsNJ296IXnW8rOHox91aY8uIZ8');
  assert.deepEqual(buildAttestationBinding(challenge, pem, {}), binding, 'without device keys the binding is unchanged');
});

test('attestation binding covers the authentication and offline keys when present', () => {
  const challenge = Buffer.alloc(32, 7);
  const [sig, auth, offline] = ['SIG', 'AUTH', 'OFFLINE'].map((k) => `-----BEGIN PUBLIC KEY-----\n${k}\n-----END PUBLIC KEY-----`);
  const nul = Buffer.from([0]);
  assert.deepEqual(buildAttestationBinding(challenge, sig, { authPublicKeyPem: auth, offlinePublicKeyPem: offline }),
    Buffer.concat([challenge, nul, Buffer.from(sig), nul, Buffer.from(auth), nul, Buffer.from(offline)]));
  assert.deepEqual(buildAttestationBinding(challenge, sig, { authPublicKeyPem: auth }),
    Buffer.concat([challenge, nul, Buffer.from(sig), nul, Buffer.from(auth), nul]));
  assert.notDeepEqual(buildAttestationBinding(challenge, sig, { authPublicKeyPem: auth }), buildAttestationBinding(challenge, sig, { offlinePublicKeyPem: auth }),
    'the slot of each key is fixed');
});
