import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { loadTs } from './support/load-ts.mjs';

const vectors = JSON.parse(readFileSync(new URL('../test-vectors/device-protocols-v1.json', import.meta.url), 'utf8'));
const protocol = loadTs('services/deviceProtocol.ts');

/** A fresh P-256 key as the ECDH object, a KeyObject and its SPKI PEM. */
function keyPair() {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const point = ecdh.getPublicKey();
  const privateKey = createPrivateKey({
    format: 'jwk',
    key: { kty: 'EC', crv: 'P-256', d: ecdh.getPrivateKey().toString('base64url'), x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') },
  });
  return { ecdh, privateKey, publicKeyPem: createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString() };
}

const deviceKey = (scalarHex) => {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(scalarHex, 'hex'));
  return ecdh;
};

test('request signing input matches the shared vectors, and the sample signatures verify', () => {
  for (const r of vectors.device_request.requests) {
    const input = protocol.deviceRequestSigningInput({
      method: r.method, path: r.path, timestamp: r.timestamp, nonce: r.nonce, credentialId: r.credential_id, body: Buffer.from(r.body, 'utf8'),
    });
    assert.equal(input.toString('base64'), r.signing_input_base64, r.name);
    assert.ok(verify('sha256', input, { key: vectors.device_request.auth_public_key_pem, dsaEncoding: 'der' },
      Buffer.from(r.sample_signature_der_base64, 'base64')), r.name);
  }
});

test('offline key, tag, code and QR payload match the shared vectors', () => {
  const o = vectors.offline;
  const shared = deviceKey(o.device_private_scalar_hex).computeSecret(deviceKey(o.server_private_scalar_hex).getPublicKey());
  assert.equal(shared.toString('hex'), o.shared_secret_hex);
  const key = protocol.deriveOfflineKey(shared, o.credential_id);
  assert.equal(key.toString('hex'), o.offline_key_hex);
  for (const c of o.confirmations) {
    const canonical = Buffer.from(c.canonical_base64, 'base64');
    const tag = protocol.offlineConfirmationTag(key, canonical);
    assert.equal(tag.toString('base64'), c.tag_base64, c.name);
    assert.equal(protocol.offlineCodeFromTag(tag), c.code, c.name);
    assert.equal(protocol.offlineQrPayload(canonical), c.qr_payload, c.name);
  }
});

test('offline codes are always 8 digits and change with every payload byte', () => {
  const key = randomBytes(32);
  const seen = new Set();
  for (let i = 0; i < 2000; i += 1) {
    const code = protocol.offlineCodeFromTag(protocol.offlineConfirmationTag(key, Buffer.from(`payload-${i}`)));
    assert.match(code, /^\d{8}$/);
    seen.add(code);
  }
  assert.ok(seen.size > 1990, 'codes are spread over the 8-digit space');
});

test('enrolment derives the same offline key the device derives from the returned server key', () => {
  const env = { OFFLINE_CONFIRMATION_ENABLED: true, DEVICE_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64') };
  const stubs = { '../config/env': { env } };
  const { prepareDeviceKeys } = loadTs('services/deviceKeysService.ts', { stubs });
  const { decryptSecretBytes } = loadTs('crypto/secretBox.ts', { stubs });

  const signing = keyPair();
  const auth = keyPair();
  const offline = keyPair();
  const credentialId = '11111111-2222-4333-8444-555555555555';
  const keys = prepareDeviceKeys(credentialId, signing.publicKeyPem, {
    authPublicKeyPem: auth.publicKeyPem,
    offlinePublicKeyPem: offline.publicKeyPem,
  });
  assert.ok(keys.authPublicKeyPem && keys.offlineServerPublicKeyPem && keys.offlineSecretEncrypted);

  // Device side: ECDH with the server public key returned at enrolment.
  const serverPoint = createPublicKey(keys.offlineServerPublicKeyPem).export({ format: 'jwk' });
  const serverRaw = Buffer.concat([Buffer.from([4]), Buffer.from(serverPoint.x, 'base64url'), Buffer.from(serverPoint.y, 'base64url')]);
  const deviceDerived = protocol.deriveOfflineKey(offline.ecdh.computeSecret(serverRaw), credentialId);
  assert.deepEqual(decryptSecretBytes(keys.offlineSecretEncrypted, 'device', credentialId), deviceDerived);
  assert.throws(() => decryptSecretBytes(keys.offlineSecretEncrypted, 'device', '99999999-2222-4333-8444-555555555555'),
    'a ciphertext copied to another credential does not decrypt');

  assert.throws(() => prepareDeviceKeys(credentialId, signing.publicKeyPem, { authPublicKeyPem: signing.publicKeyPem }), /distinct/);
  env.OFFLINE_CONFIRMATION_ENABLED = false;
  assert.equal(prepareDeviceKeys(credentialId, signing.publicKeyPem, { offlinePublicKeyPem: offline.publicKeyPem }).offlineSecretEncrypted, null,
    'offline keys are ignored while the feature is disabled');
});

test('device-signed requests: valid, replayed, stale, tampered and unknown-key cases', async () => {
  const { privateKey, publicKeyPem: authPem } = keyPair();
  const credentialId = '00000000-0000-4000-8000-000000000002';
  const usedNonces = new Set();
  let identityStatus = 'ACTIVE';
  const stubs = {
    '../config/env': { env: { DEVICE_REQUEST_MAX_SKEW_SECONDS: 300, DEVICE_REQUEST_PATH_PREFIX: '' } },
    '../db/redis': { redis: { set: async (key) => (usedNonces.has(key) ? null : (usedNonces.add(key), 'OK')) } },
    // DEVICE_NONCE_STORE=postgres (default): the primary key of
    // device_request_nonces; here a set with ON CONFLICT DO NOTHING semantics.
    '../db/pool': { pool: { query: async (sql, [credential, nonce]) => {
      assert.match(sql, /INSERT INTO device_request_nonces .* ON CONFLICT \(credential_id, nonce\) DO NOTHING/s);
      const key = `${credential}:${nonce}`;
      return { rowCount: usedNonces.has(key) ? 0 : (usedNonces.add(key), 1) };
    } } },
    '../services/mobileSessionService': { resolveMobileSession: async () => null },
    '../services/nexusIdentityService': { getNexusIdentityStatus: async () => identityStatus },
    '../services/clientService': { getClientRecord: async () => ({ status: 'ACTIVE' }) },
    '../services/credentialService': {
      getActiveDeviceCredential: async (id) => (id === credentialId ? { credentialId, nexusId: '123456789', clientId: 'bank-a', authPublicKeyPem: authPem } : null),
    },
    '../services/credentialIntegrity': integrityStub(() => intact),
  };
  let intact = true;
  const { authenticateMobileSession } = loadTs('middleware/mobileAuth.ts', { stubs });

  const signedRequest = ({ method = 'POST', path = '/v1/mobile/authorizations/x/signature', body = '{"a":1}', timestamp = String(Math.floor(Date.now() / 1000)), nonce = randomBytes(16).toString('base64url'), cred = credentialId, tamper } = {}) => {
    const input = protocol.deviceRequestSigningInput({ method, path, timestamp, nonce, credentialId: cred, body: Buffer.from(body) });
    const headers = {
      'x-nexus-credential': cred, 'x-nexus-timestamp': timestamp, 'x-nexus-nonce': nonce,
      'x-nexus-signature': sign('sha256', input, { key: privateKey, dsaEncoding: 'der' }).toString('base64'),
    };
    return { method, originalUrl: path, rawBody: Buffer.from(tamper ?? body), header: (n) => headers[n.toLowerCase()] };
  };
  const run = async (req) => {
    const out = { status: 200, body: null, next: false };
    const res = { status(c) { out.status = c; return this; }, json(b) { out.body = b; } };
    await authenticateMobileSession(req, res, (err) => { if (err) throw err; out.next = true; });
    return { ...out, req };
  };

  const ok = await run(signedRequest());
  assert.equal(ok.next, true);
  assert.equal(ok.req.mobileNexusId, '123456789');
  assert.equal(ok.req.mobileSessionPurpose, 'DEVICE');

  const once = signedRequest();
  assert.equal((await run(once)).next, true);
  assert.equal((await run(once)).status, 401, 'a replayed request is refused');

  const stale = await run(signedRequest({ timestamp: String(Math.floor(Date.now() / 1000) - 3600) }));
  assert.equal(stale.status, 401);
  assert.ok(stale.body.serverTime, 'the device gets the server time to correct its clock');

  assert.equal((await run(signedRequest({ tamper: '{"a":2}' }))).status, 401, 'a changed body breaks the signature');
  const moved = signedRequest();
  moved.originalUrl = '/v1/mobile/authorizations/y/signature';
  assert.equal((await run(moved)).status, 401, 'the signature covers the path');
  assert.equal((await run(signedRequest({ cred: '00000000-0000-4000-8000-000000000009' }))).status, 401, 'unknown credential');

  intact = false;
  assert.equal((await run(signedRequest())).status, 401, 'keys that differ from the sealed enrolment are refused');
  intact = true;

  identityStatus = 'SUSPENDED';
  assert.equal((await run(signedRequest())).status, 403, 'a suspended identity is refused');
});

function integrityStub(isIntact) {
  class CredentialIntegrityError extends Error {}
  return {
    CredentialIntegrityError,
    assertCredentialIntegrity: async () => { if (!isIntact()) throw new CredentialIntegrityError('mismatch'); return 'hash'; },
  };
}
