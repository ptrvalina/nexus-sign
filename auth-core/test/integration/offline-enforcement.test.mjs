// no path turns an offline code into an executable
// authorization without the device's signature. Covers the service boundary
// (called directly, without the HTTP layer), every other endpoint that could
// confirm, the bank commit (which now re-verifies the sealed evidence instead
// of the state column), database-only forgeries, a code-only record sealed by
// a v1 process, a replaced device and the configuration gate for v1.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { ROOT, createDatabase, skipWithoutServices, startAuthCore, startExpectingFailure } from './support/harness.mjs';
import { bankSession, call, deviceSignature, enrolWithToken, offlineCode, signDer, submitSignature } from './support/actors.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Runs submitDeferredSignature from dist/ in a separate process, against the
 * test database, bypassing the HTTP routes and their scope checks. */
function callServiceDirectly(env, { authorizationId, clientId, requestCredentialId, signature }) {
  const script = `
    const { submitDeferredSignature } = require(${JSON.stringify(join(ROOT, 'dist/services/authorizationConfirmation.js'))});
    const { SoftwareHsmAdapter } = require(${JSON.stringify(join(ROOT, 'dist/crypto/softwareHsmAdapter.js'))});
    const { configureEvidenceKeyring } = require(${JSON.stringify(join(ROOT, 'dist/services/credentialIntegrity.js'))});
    const { pool } = require(${JSON.stringify(join(ROOT, 'dist/db/pool.js'))});
    (async () => {
      const hsm = new SoftwareHsmAdapter();
      configureEvidenceKeyring(hsm);
      try {
        const r = await submitDeferredSignature(hsm, process.argv[1], process.argv[2], process.argv[3], process.argv[4], 'der');
        console.log(JSON.stringify({ ok: true, result: r }));
      } catch (e) {
        console.log(JSON.stringify({ ok: false, name: e.name, code: e.code ?? null, message: e.message }));
      } finally { await pool.end(); }
    })();`;
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['-e', script, authorizationId, clientId, requestCredentialId, signature], { env, cwd: ROOT }, (error, stdout, stderr) => {
      const line = stdout.trim().split('\n').filter((l) => l.startsWith('{')).at(-1);
      if (!line) return reject(new Error(`service script failed: ${error?.message}\n${stderr}`));
      resolve(JSON.parse(line));
    });
  });
}

describe('enforcement: no execution without the device signature', { skip: skipWithoutServices }, () => {
  let server; let bank; let client;
  before(async () => {
    server = await startAuthCore({ env: { AUTHORIZATION_EXPIRY_SWEEP_MS: '500' } });
    client = await server.registerBank('bank-enforcement', { webhookUrl: 'https://bank.example/hooks' });
    bank = await bankSession(server, client);
  });
  after(async () => { await server?.stop(); });

  const q = (sql, args) => server.db.query(sql, args);
  const newDevice = async () => bank.enrolDevice((await bank.createIdentity()).nexusId);
  const stateOf = async (id) => (await bank.call('GET', `/v1/authorizations/${id}`)).json;
  const commit = (id, ref = `B-${randomBytes(4).toString('hex')}`) => bank.call('POST', `/v1/authorizations/${id}/bank-commit-request`, { body: { bankTransactionReference: ref } });

  async function provisional(device) {
    const auth = await bank.createAuthorization(device);
    const { canonical } = await deviceSignature(server, device, auth.authorizationId);
    const r = await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(device, canonical) } });
    assert.equal(r.json.status, 'PROVISIONAL', r.text);
    return { id: auth.authorizationId, canonical, signature: signDer(device.signingKey, canonical) };
  }

  test('the service itself refuses a signature from a credential other than the bound one (no HTTP layer)', async () => {
    const device = await newDevice();
    const other = await newDevice();
    const p = await provisional(device);
    const serviceEnv = { ...server.env };
    // Mismatched requester, with a signature that is otherwise valid.
    const refused = await callServiceDirectly(serviceEnv, { authorizationId: p.id, clientId: client.clientId, requestCredentialId: other.credentialId, signature: p.signature });
    assert.equal(refused.ok, false, JSON.stringify(refused));
    assert.equal(refused.name, 'ForbiddenError');
    assert.equal((await stateOf(p.id)).state, 'OFFLINE_PROVISIONAL', 'nothing changed');
    // Control: the same call with the bound credential reaches the signature
    // check and finalizes, so the refusal above came from the credential check.
    // The server's evidence key, so the child process can check the sealed enrolment.
    const online = await bank.createAuthorization(device);
    const s = await deviceSignature(server, device, online.authorizationId);
    assert.equal((await submitSignature(server, device, online.authorizationId, s.signature)).json.status, 'VERIFIED');
    const evidenceKey = (await bank.call('GET', `/v1/authorizations/${online.authorizationId}/evidence`)).json.evidencePublicKeyPem;
    const accepted = await callServiceDirectly({ ...serviceEnv, EVIDENCE_RETIRED_PUBLIC_KEYS_PEM: evidenceKey },
      { authorizationId: p.id, clientId: client.clientId, requestCredentialId: device.credentialId, signature: p.signature });
    assert.equal(accepted.ok, true, JSON.stringify(accepted));
    assert.equal(accepted.result.status, 'VERIFIED');
  });

  test('a provisional authorization is confirmed by no other endpoint, is reported as not confirmed and cannot be committed', async () => {
    const device = await newDevice();
    const p = await provisional(device);
    const view = await stateOf(p.id);
    assert.equal(view.state, 'OFFLINE_PROVISIONAL');
    assert.equal(view.confirmed, false);
    const online = await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${p.id}/signature`, { device, body: { signature: p.signature, signatureFormat: 'der' } });
    assert.equal(online.json.status, 'FAILED', `device signature endpoint: ${online.text}`);
    const viaBank = await bank.call('POST', `/v1/authorizations/${p.id}/signature`, { body: { signature: p.signature, signatureFormat: 'der' } });
    assert.equal(viaBank.json.status, 'FAILED', `bank signature endpoint: ${viaBank.text}`);
    const escalate = await bank.call('POST', `/v1/authorizations/${p.id}/verification/escalate`, { body: { reason: 'RISK_POLICY' } });
    assert.ok(escalate.status >= 400, `escalation: ${escalate.status}`);
    const refused = await commit(p.id);
    assert.equal(refused.status, 409, refused.text);
    assert.equal((await stateOf(p.id)).state, 'OFFLINE_PROVISIONAL');
    const hook = (await q(`SELECT payload FROM webhook_deliveries WHERE event_type = 'authorization.offline_provisional' AND payload->>'authorizationId' = $1`, [p.id])).rows;
    assert.equal(hook[0].payload.confirmed, false);
  });

  test('a VERIFIED state written straight to the database is not committable', async () => {
    const device = await newDevice();
    const auth = await bank.createAuthorization(device);
    // The trigger permits PENDING_USER -> VERIFIED with any signature value.
    await q(`UPDATE authorization_requests SET state = 'VERIFIED', signature = 'forged', signature_format = 'der', confirmation_method = 'DEVICE_SIGNATURE', verified_at = now()
             WHERE authorization_id = $1`, [auth.authorizationId]);
    const view = await stateOf(auth.authorizationId);
    assert.equal(view.state, 'VERIFIED', 'the row itself says VERIFIED');
    assert.equal(view.confirmed, false, 'confirmed is derived from the evidence, not from the state column');
    assert.match(view.evidenceProblem, /no sealed evidence/);
    const r = await commit(auth.authorizationId);
    assert.equal(r.status, 409, r.text);
    assert.equal(r.json.code, 'EVIDENCE_INVALID');
    assert.match(r.json.error, /no sealed evidence/);
    const audit = await q(`SELECT details FROM audit_logs WHERE event_type = 'integrity_violation' AND details->>'authorizationId' = $1`, [auth.authorizationId]);
    assert.equal(audit.rows.length, 1);
  });

  test('a copied or altered evidence record is not accepted for a commit', async () => {
    const device = await newDevice();
    const genuine = await bank.createAuthorization(device);
    const s = await deviceSignature(server, device, genuine.authorizationId);
    assert.equal((await submitSignature(server, device, genuine.authorizationId, s.signature)).json.status, 'VERIFIED');
    const target = await bank.createAuthorization(device);
    await q(`UPDATE authorization_requests SET state = 'VERIFIED', signature = $2, signature_format = 'der', confirmation_method = 'DEVICE_SIGNATURE', verified_at = now()
             WHERE authorization_id = $1`, [target.authorizationId, s.signature]);
    // Another authorization's genuine record, re-pointed at the target.
    await q(`INSERT INTO evidence_records (record_type, authorization_id, nexus_id, credential_id, chain_sequence, transaction_reference, canonical_payload_hash,
               signature, signature_algorithm, key_version, policy_version, attestation_verdict, verified_at, consumed_at, result, correlation_id,
               previous_evidence_hash, evidence_hash, hsm_signature, hsm_key_version, seal_key_id, schema_version, verification_factors, sealed_payload, created_at)
             SELECT record_type, $2, nexus_id, credential_id, 9000, transaction_reference, canonical_payload_hash, signature, signature_algorithm, key_version,
               policy_version, attestation_verdict, verified_at, consumed_at, result, correlation_id, md5(random()::text) || md5(random()::text), evidence_hash,
               hsm_signature, hsm_key_version, seal_key_id, schema_version, verification_factors, sealed_payload, now()
             FROM evidence_records WHERE authorization_id = $1`, [genuine.authorizationId, target.authorizationId]);
    const r = await commit(target.authorizationId);
    assert.equal(r.status, 409, r.text);
    assert.match(r.json.error, /names another authorization/);
    // The genuine one still commits (positive control), once; a second
    // reference is refused, the same one is idempotent.
    const ok = await commit(genuine.authorizationId, 'B-genuine');
    assert.equal(ok.status, 202, ok.text);
    assert.equal((await commit(genuine.authorizationId, 'B-genuine')).status, 202);
    assert.equal((await commit(genuine.authorizationId, 'B-other')).status, 409);
  });

  test('an OFFLINE_SIGNED confirmation commits; a replacement device cannot sign for the replaced one', async () => {
    const device = await newDevice();
    const p = await provisional(device);
    assert.equal((await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${p.id}/deferred-signature`, { device, body: { signature: p.signature, signatureFormat: 'der' } })).json.status, 'VERIFIED');
    assert.equal((await stateOf(p.id)).confirmed, true);
    assert.equal((await commit(p.id)).status, 202);

    const old = await newDevice();
    const pending = await provisional(old);
    const replacement = await bank.replaceDevice(old, { method: 'BRANCH_VISIT', reference: `case-${randomBytes(3).toString('hex')}` });
    const fromNew = await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${pending.id}/deferred-signature`,
      { device: replacement, body: { signature: signDer(replacement.signingKey, pending.canonical), signatureFormat: 'der' } });
    assert.equal(fromNew.status, 403, fromNew.text);
    const fromOld = await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${pending.id}/deferred-signature`,
      { device: old, body: { signature: pending.signature, signatureFormat: 'der' } });
    assert.equal(fromOld.status, 401, `the replaced device cannot authenticate: ${fromOld.text}`);
    for (let i = 0; i < 60 && (await stateOf(pending.id)).state !== 'OFFLINE_UNSIGNED'; i += 1) await sleep(100);
    const end = await stateOf(pending.id);
    assert.equal(end.state, 'OFFLINE_UNSIGNED');
    assert.equal(end.offlineUnsignedReason, 'credential_not_active');
    assert.equal((await commit(pending.id)).status, 409);
  });
});

describe('enforcement: v1 records and configuration', { skip: skipWithoutServices }, () => {
  test('a code-only record sealed by a v1 process is not committable once the deployment runs v2', async () => {
    const database = await createDatabase();
    let v1; let v2;
    try {
      v1 = await startAuthCore({ database, env: { OFFLINE_CONFIRMATION_MODE: 'immediate' } });
      const client = await v1.registerBank('bank-v1-record');
      const bank = await bankSession(v1, client);
      const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
      const auth = await bank.createAuthorization(device);
      const { canonical } = await deviceSignature(v1, device, auth.authorizationId);
      assert.equal((await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(device, canonical) } })).json.status, 'VERIFIED');
      const evidenceKey = (await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/evidence`)).json.evidencePublicKeyPem;
      const keys = Object.fromEntries(['DEVICE_SECRET_ENCRYPTION_KEY', 'WEBHOOK_SECRET_ENCRYPTION_KEY', 'ADMIN_SECRET_ENCRYPTION_KEY'].map((k) => [k, v1.env[k]]));
      await v1.stop(); v1 = null;
      v2 = await startAuthCore({ database, env: { ...keys, EVIDENCE_RETIRED_PUBLIC_KEYS_PEM: evidenceKey } });
      const bank2 = await bankSession(v2, client);
      const r = await bank2.call('POST', `/v1/authorizations/${auth.authorizationId}/bank-commit-request`, { body: { bankTransactionReference: 'B-v1' } });
      assert.equal(r.status, 409, r.text);
      assert.equal(r.json.code, 'EVIDENCE_INVALID');
      assert.match(r.json.error, /code-only offline confirmation is not accepted/);
    } finally {
      await v1?.stop(); await v2?.stop(); await database.drop();
    }
  });

  test('v1 is never implicit: it needs ALLOW_INSECURE_DEVELOPMENT outside production', async () => {
    const { code, log } = await startExpectingFailure({ ALLOW_INSECURE_DEVELOPMENT: 'false', HSM_ADAPTER: undefined, REQUIRE_VALID_ATTESTATION: undefined, OFFLINE_CONFIRMATION_MODE: 'immediate' });
    assert.notEqual(code, 0);
    assert.match(log, /OFFLINE_CONFIRMATION_MODE=immediate is a development setting/);
  });
});
