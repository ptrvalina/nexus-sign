// Offline confirmation v3 (audit finding D-01). On iOS the Secure Enclave
// returns the ECDH secret to the app process. With one key agreed at
// enrolment, a secret taken once from a compromised app would compute codes
// for every later QR code. With offlineKeyAgreement PER_AUTHORIZATION Auth
// Core keeps no key from enrolment and puts a fresh key of its own into each
// authorization's QR code, so a taken secret serves that authorization only.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, hkdfSync } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, call, offlineCode, offlineCodeV3, signDer } from './support/actors.mjs';

/** The code an attacker computes for a QR code with a secret taken earlier from the app. */
function codeWithTakenSecret(sharedSecret, credentialId, authorizationId, canonical) {
  const info = Buffer.concat([Buffer.from(credentialId), Buffer.from([0]), Buffer.from(authorizationId)]);
  const key = Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.from('NEXUS-SIGN/OFFLINE/v3'), info, 32));
  const tag = createHmac('sha256', key)
    .update(Buffer.concat([Buffer.from('NEXUS-SIGN/OFFLINE-CODE/v1'), Buffer.from([0]), createHash('sha256').update(canonical).digest()]))
    .digest();
  const offset = tag[31] & 0x0f;
  const bin = ((tag[offset] & 0x7f) << 24) | (tag[offset + 1] << 16) | (tag[offset + 2] << 8) | tag[offset + 3];
  return String(bin % 100000000).padStart(8, '0');
}

describe('offline confirmation v3: an Auth Core key per authorization (finding D-01)', { skip: skipWithoutServices }, () => {
  let server; let bank;
  before(async () => {
    server = await startAuthCore();
    bank = await bankSession(server, await server.registerBank('bank-offline-v3'));
  });
  after(async () => { await server?.stop(); });

  const q = (sql, args) => server.db.query(sql, args);
  const iPhone = async () => bank.enrolDevice((await bank.createIdentity()).nexusId, {}, { extraBody: { offlineKeyAgreement: 'PER_AUTHORIZATION' } });
  const challenge = async (id) => bank.call('GET', `/v1/authorizations/${id}/offline-challenge`);
  const submitCode = (id, code) => bank.call('POST', `/v1/authorizations/${id}/offline-confirmation`, { body: { code } });

  test('enrolment keeps no offline key; the device is still offline-capable', async () => {
    const device = await iPhone();
    assert.equal(device.response.offlineKeyAgreement, 'PER_AUTHORIZATION');
    assert.equal(device.response.offlineServerPublicKeyPem, null, 'no server key from enrolment');
    const row = (await q(`SELECT offline_key_agreement, offline_secret_encrypted, offline_server_public_key_pem, offline_public_key_pem IS NOT NULL AS has_device_key
      FROM credentials WHERE credential_id = $1`, [device.credentialId])).rows[0];
    assert.deepEqual(row, { offline_key_agreement: 'PER_AUTHORIZATION', offline_secret_encrypted: null, offline_server_public_key_pem: null, has_device_key: true });
    const credential = await bank.call('GET', `/v1/credentials/${device.credentialId}`);
    if (credential.status === 200 && 'offlineEnabled' in credential.json) assert.equal(credential.json.offlineEnabled, true);
    // Fixed at enrolment: even the application role cannot switch it back.
    await assert.rejects(q(`UPDATE credentials SET offline_key_agreement = 'STATIC' WHERE credential_id = $1`, [device.credentialId]), /fixed at enrolment|credentials_offline_key_agreement_check/);
  });

  test('the QR code carries a key for this authorization; the code confirms it, then the signature', async () => {
    const device = await iPhone();
    const auth = await bank.createAuthorization(device);
    const first = await challenge(auth.authorizationId);
    assert.equal(first.status, 200, first.text);
    assert.match(first.json.qrPayload, /^NXS3\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    assert.equal((await challenge(auth.authorizationId)).json.qrPayload, first.json.qrPayload, 'the same key for every QR code of one authorization');
    const { code, canonical } = offlineCodeV3(device, first.json.qrPayload);
    const accepted = await submitCode(auth.authorizationId, code);
    assert.equal(accepted.json.status, 'PROVISIONAL', accepted.text);
    const uploaded = await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${auth.authorizationId}/deferred-signature`,
      { device, body: { signature: signDer(device.signingKey, canonical), signatureFormat: 'der' } });
    assert.equal(uploaded.status, 200, uploaded.text);
    assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}`)).json.state, 'VERIFIED');
  });

  test('a secret taken for one authorization computes no valid code for another', async () => {
    const device = await iPhone();
    const first = await bank.createAuthorization(device);
    const taken = offlineCodeV3(device, (await challenge(first.authorizationId)).json.qrPayload).sharedSecret;
    const second = await bank.createAuthorization(device);
    const qr = (await challenge(second.authorizationId)).json.qrPayload;
    const canonical = Buffer.from(qr.split('.')[1], 'base64url');
    const forged = codeWithTakenSecret(taken, device.credentialId, second.authorizationId, canonical);
    assert.notEqual(forged, offlineCodeV3(device, qr).code);
    const refused = await submitCode(second.authorizationId, forged);
    assert.equal(refused.json.status, 'FAILED', refused.text);
    assert.equal(refused.json.attempts, 1, 'counted as a wrong code');
    // A code from the static agreement (the old protocol) is refused too.
    assert.equal((await submitCode(second.authorizationId, offlineCode({ ...device, offlineServerPublicKeyPem: device.offlineKey.publicKeyPem }, canonical))).json.status, 'FAILED');
    // The device itself still confirms it.
    assert.equal((await submitCode(second.authorizationId, offlineCodeV3(device, qr).code)).json.status, 'PROVISIONAL');
  });

  test('no code is accepted before the bank asked for the QR code', async () => {
    const device = await iPhone();
    const auth = await bank.createAuthorization(device);
    const r = await submitCode(auth.authorizationId, '12345678');
    assert.equal(r.json.status, 'FAILED');
    assert.match(r.json.reason, /No offline challenge was issued/);
  });

  test('a challenge key is stored encrypted, bound to its authorization, and never changed or deleted', async () => {
    const device = await iPhone();
    const auth = await bank.createAuthorization(device);
    await challenge(auth.authorizationId);
    const row = (await q(`SELECT server_private_key_encrypted FROM offline_challenges WHERE authorization_id = $1`, [auth.authorizationId])).rows[0];
    assert.match(row.server_private_key_encrypted, /^k1\$/);
    await assert.rejects(q(`UPDATE offline_challenges SET server_public_key_pem = 'x' WHERE authorization_id = $1`, [auth.authorizationId]), /written once/);
    await assert.rejects(q(`UPDATE offline_challenges SET server_private_key_encrypted = 'k1$x' WHERE authorization_id = $1`, [auth.authorizationId]), /written once/);
    await assert.rejects(q(`DELETE FROM offline_challenges WHERE authorization_id = $1`, [auth.authorizationId]), /not deleted/);
  });

  test('a device enrolled with the static agreement (Android) keeps v2 QR codes', async () => {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    assert.equal(device.response.offlineKeyAgreement, 'STATIC');
    const auth = await bank.createAuthorization(device);
    const qr = (await challenge(auth.authorizationId)).json.qrPayload;
    assert.ok(qr.startsWith('NXS2.'), qr.slice(0, 5));
    assert.equal((await submitCode(auth.authorizationId, offlineCode(device, Buffer.from(qr.slice(5), 'base64url')))).json.status, 'PROVISIONAL');
  });
});
