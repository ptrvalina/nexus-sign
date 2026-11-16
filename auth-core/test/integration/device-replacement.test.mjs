// Enrolling a new device for an identity that already has one must not
// silently take the identity over: it needs the bank's explicit
// replacement authorization, which is audited, sealed into the evidence
// chain, reported by webhook and announced on the replaced device. Since the
// A2-01 fix the bank's request is held until the enrolled device approves it
// (or the hold passes; device-replacement-hold.test.mjs), so these tests
// approve it from the old device first.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, call, enrolWithToken, newKey } from './support/actors.mjs';

const fcmServiceAccount = () => JSON.stringify({
  type: 'service_account',
  project_id: 'bank-app-test',
  client_email: 'push@bank-app-test.iam.gserviceaccount.com',
  private_key: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  token_uri: 'https://oauth2.googleapis.com/token',
});

describe('device replacement', { skip: skipWithoutServices }, () => {
  let server; let bank;

  before(async () => {
    server = await startAuthCore({ env: { PUSH_DELIVERY_ENABLED: 'true', FCM_PROJECT_ID: 'bank-app-test', FCM_SERVICE_ACCOUNT_JSON: fcmServiceAccount() } });
    bank = await bankSession(server, await server.registerBank('bank-replace', { webhookUrl: 'https://hooks.bank.example/nexus', pushMode: 'NEXUS' }));
  });
  after(async () => { await server?.stop(); });

  async function approveOnDevice(device, replacementId) {
    const listed = await call(server.baseUrl, 'GET', '/v1/mobile/device-replacements', { device });
    assert.equal(listed.status, 200, listed.text);
    assert.ok(listed.json.replacements.some((r) => r.replacementId === replacementId));
    const approved = await call(server.baseUrl, 'POST', `/v1/mobile/device-replacements/${replacementId}/approve`, { device, body: {} });
    assert.equal(approved.status, 200, approved.text);
    assert.equal(approved.json.state, 'APPROVED');
  }

  test('a bootstrap token for an identity with an enrolled device is refused without a replacement authorization', async () => {
    const { nexusId } = await bank.createIdentity();
    await bank.enrolDevice(nexusId);
    const again = await bank.bootstrapToken(nexusId);
    assert.equal(again.status, 409, again.text);
    assert.equal(again.json.code, 'ACTIVE_CREDENTIAL_EXISTS');
  });

  test('enrolled devices have no bearer token: no SESSION tokens, and enrolment needs an authentication key', async () => {
    const { nexusId } = await bank.createIdentity();
    const session = await bank.call('POST', '/v1/mobile/sessions', { body: { nexusId, purpose: 'SESSION' } });
    assert.equal(session.status, 400, session.text);
    const token = await bank.bootstrapToken(nexusId);
    const withoutAuthKey = await call(server.baseUrl, 'POST', '/v1/mobile/bootstrap', {
      token: token.json.accessToken,
      body: { publicKeyPem: newKey().publicKeyPem, platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', deviceAttestation: { supported: false } },
    });
    assert.equal(withoutAuthKey.status, 400, withoutAuthKey.text);
    // A refused request does not use up the single-use token.
    const device = await enrolWithToken(server, nexusId, token.json.accessToken);
    assert.equal(device.response.requestAuthentication, 'DEVICE_SIGNATURE');
    assert.equal(device.response.accessToken, undefined);
    const bearer = await call(server.baseUrl, 'GET', '/v1/mobile/recovery/setup', { token: token.json.accessToken });
    assert.equal(bearer.status, 401, 'the consumed bootstrap token gives no access');
  });

  test('two concurrent first enrolments: exactly one device is enrolled', async () => {
    const { nexusId } = await bank.createIdentity();
    const tokens = await Promise.all([bank.bootstrapToken(nexusId), bank.bootstrapToken(nexusId)]);
    tokens.forEach((t) => assert.equal(t.status, 201, t.text));
    const results = await Promise.allSettled(tokens.map((t) => enrolWithToken(server, nexusId, t.json.accessToken)));
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    const refused = results.find((r) => r.status === 'rejected');
    assert.equal(refused.reason.response.status, 409);
    const active = await server.db.query(`SELECT count(*)::int AS n FROM credentials WHERE nexus_id = $1 AND state = 'ACTIVE'`, [nexusId]);
    assert.equal(active.rows[0].n, 1);
  });

  test('an authorized replacement revokes the old device, is audited, sealed, reported and announced on the old device', async () => {
    const { nexusId } = await bank.createIdentity();
    const first = await bank.bootstrapToken(nexusId);
    const oldDevice = await enrolWithToken(server, nexusId, first.json.accessToken, { extraBody: { platform: 'ANDROID', securityLevel: 'TEE' } });
    const ephemeral = newKey();
    const registered = await call(server.baseUrl, 'POST', '/v1/mobile/push-registration', {
      device: oldDevice, body: { provider: 'FCM', deviceToken: `fXo2:APA91b${'x'.repeat(140)}`, devicePublicKeyPem: ephemeral.publicKeyPem },
    });
    assert.equal(registered.status, 200, registered.text);

    const invalid = await bank.bootstrapToken(nexusId, { replacement: { method: 'SOMETHING', reference: 'x' } });
    assert.equal(invalid.status, 400);
    const held = await bank.bootstrapToken(nexusId, { replacement: { method: 'BRANCH_VISIT', reference: 'case-2026-0042' } });
    assert.equal(held.status, 202, held.text);
    assert.equal(held.json.status, 'REPLACEMENT_PENDING');
    await approveOnDevice(oldDevice, held.json.replacementId);
    const token = await bank.bootstrapToken(nexusId, { replacement: { method: 'BRANCH_VISIT', reference: 'case-2026-0042' } });
    assert.equal(token.status, 201, token.text);
    const newDevice = await enrolWithToken(server, nexusId, token.json.accessToken);

    const oldState = await server.db.query(`SELECT state FROM credentials WHERE credential_id = $1`, [oldDevice.credentialId]);
    assert.equal(oldState.rows[0].state, 'REVOKED');
    assert.equal((await call(server.baseUrl, 'GET', '/v1/mobile/push-messages/00000000-0000-4000-8000-000000000000', { device: oldDevice })).status, 401);

    const audit = await server.db.query(`SELECT event_type, details FROM audit_logs WHERE nexus_id = $1 ORDER BY "timestamp"`, [nexusId]);
    const authorized = audit.rows.find((r) => r.event_type === 'credential_replacement_authorized');
    assert.equal(authorized?.details.method, 'BRANCH_VISIT');
    assert.equal(authorized?.details.reference, 'case-2026-0042');
    assert.ok(audit.rows.some((r) => r.event_type === 'credential_replaced'));

    const chain = await server.db.query(`SELECT sealed_payload FROM evidence_records WHERE nexus_id = $1 AND record_type = 'CREDENTIAL_ENROLLED' ORDER BY chain_sequence`, [nexusId]);
    const replacement = chain.rows.at(-1).sealed_payload;
    assert.equal(replacement.reason, 'REPLACEMENT');
    assert.equal(replacement.credentialId, newDevice.credentialId);
    assert.deepEqual(replacement.replacedCredentialIds, [oldDevice.credentialId]);
    assert.equal(replacement.replacementAuthorization.reference, 'case-2026-0042');

    const webhook = await server.db.query(`SELECT payload FROM webhook_deliveries WHERE event_type = 'credential.replaced' AND payload->>'nexusId' = $1`, [nexusId]);
    assert.equal(webhook.rows.length, 1);
    assert.equal(webhook.rows[0].payload.newCredentialId, newDevice.credentialId);

    const notice = await server.db.query(
      `SELECT m.category, m.status, m.replacement_notice FROM push_messages m WHERE m.credential_id = $1`, [oldDevice.credentialId]);
    assert.equal(notice.rows.length, 1, 'one security notice for the replaced device');
    assert.equal(notice.rows[0].category, 'SECURITY');
    assert.equal(notice.rows[0].replacement_notice, true);
    assert.notEqual(notice.rows[0].status, 'FAILED', 'the notice is not failed by the revocation');
    const registration = await server.db.query(`SELECT 1 FROM push_registrations WHERE credential_id = $1`, [oldDevice.credentialId]);
    assert.equal(registration.rows.length, 1, 'the old registration is kept until the notice is sent');
  });

  test('a replacement token cannot be used for another identity', async () => {
    const first = await bank.createIdentity();
    const firstDevice = await bank.enrolDevice(first.nexusId);
    const held = await bank.bootstrapToken(first.nexusId, { replacement: { method: 'VIDEO_IDENTIFICATION', reference: 'v-1' } });
    assert.equal(held.status, 202, held.text);
    await approveOnDevice(firstDevice, held.json.replacementId);
    const token = await bank.bootstrapToken(first.nexusId, { replacement: { method: 'VIDEO_IDENTIFICATION', reference: 'v-1' } });
    assert.equal(token.status, 201, token.text);
    const second = await bank.createIdentity();
    const credentialsBefore = await server.db.query(`SELECT count(*)::int AS n FROM credentials WHERE nexus_id = $1`, [second.nexusId]);
    const device = await enrolWithToken(server, first.nexusId, token.json.accessToken);
    assert.equal(device.nexusId, first.nexusId);
    const credentialsAfter = await server.db.query(`SELECT count(*)::int AS n FROM credentials WHERE nexus_id = $1`, [second.nexusId]);
    assert.equal(credentialsAfter.rows[0].n, credentialsBefore.rows[0].n);
  });
});
