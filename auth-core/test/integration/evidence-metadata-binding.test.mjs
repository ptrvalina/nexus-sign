// Phase 11: the database columns of an evidence record that repeat values of
// its sealed payload (nexus_id, credential_id, authorization_id, record_type,
// chain position, seal key, schema version) must agree with the payload.
// Records here are genuine: sealed by Auth Core on SoftHSM through the normal
// confirmation path. Only their metadata columns are changed afterwards, by
// the table owner with the append-only trigger disabled (an application role
// cannot update evidence at all). The seal stays valid in every case.
//
// Expected: the bank commit is refused with EVIDENCE_INVALID and an
// integrity_violation event, the bank transaction stays PENDING, GET reports
// confirmed: false, and the independent verifier reports the mismatch.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, submitSignature } from './support/actors.mjs';
import { SOFTHSM_MODULE, generateKeyPair, initToken, skipWithoutSoftHsm, softHsmDirectory } from './support/softhsm.mjs';
import { verifyEvidenceChain, verifyEvidenceRecord } from '../../scripts/lib/evidence.mjs';

describe('evidence record metadata must match the sealed payload (SoftHSM)', { skip: skipWithoutServices || skipWithoutSoftHsm }, () => {
  let server; let bank;
  before(async () => {
    const conf = softHsmDirectory();
    generateKeyPair(conf, initToken(conf, 'nexus-main'), { label: 'nexus-evidence' });
    server = await startAuthCore({ env: {
      SOFTHSM2_CONF: conf, HSM_ADAPTER: 'pkcs11', PKCS11_MODULE_PATH: SOFTHSM_MODULE, PKCS11_PIN: '12345678',
      PKCS11_TOKEN_LABEL: 'nexus-main', PKCS11_EVIDENCE_KEY_LABEL: 'nexus-evidence',
    } });
    bank = await bankSession(server, await server.registerBank('bank-metadata'));
  });
  after(async () => { await server?.stop(); });

  const q = (sql, args) => server.db.query(sql, args);
  /** Owner-level change of one evidence row, bypassing the append-only trigger. */
  const tamper = async (evidenceId, assignments, args = []) => {
    const client = await server.db.connect();
    try {
      await client.query('BEGIN');
      await client.query('ALTER TABLE evidence_records DISABLE TRIGGER trg_evidence_append_only');
      await client.query(`UPDATE evidence_records SET ${assignments} WHERE evidence_id = $1`, [evidenceId, ...args]);
      await client.query('ALTER TABLE evidence_records ENABLE TRIGGER trg_evidence_append_only');
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK'); throw error;
    } finally { client.release(); }
  };

  /** A device, a genuinely confirmed authorization (sealed through the API) and its record. */
  async function confirmed() {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const auth = await bank.createAuthorization(device);
    const s = await deviceSignature(server, device, auth.authorizationId);
    assert.equal((await submitSignature(server, device, auth.authorizationId, s.signature)).json.status, 'VERIFIED');
    const record = (await q(`SELECT evidence_id, chain_sequence FROM evidence_records WHERE authorization_id = $1`, [auth.authorizationId])).rows[0];
    return { device, id: auth.authorizationId, evidenceId: record.evidence_id, chainSequence: Number(record.chain_sequence) };
  }
  const commit = (id) => bank.call('POST', `/v1/authorizations/${id}/bank-commit-request`, { body: { bankTransactionReference: `B-${randomBytes(4).toString('hex')}` } });
  const exportOf = async (id) => (await bank.call('GET', `/v1/authorizations/${id}/evidence`)).json;

  async function expectRefused(id, reason) {
    const view = (await bank.call('GET', `/v1/authorizations/${id}`)).json;
    assert.equal(view.confirmed, false, `GET must not report confirmed: ${JSON.stringify(view.evidenceProblem)}`);
    assert.match(view.evidenceProblem ?? '', reason);
    const r = await commit(id);
    assert.equal(r.status, 409, r.text);
    assert.equal(r.json.code, 'EVIDENCE_INVALID');
    assert.match(r.json.error, reason);
    const row = (await q(`SELECT state, bank_transaction_state FROM authorization_requests WHERE authorization_id = $1`, [id])).rows[0];
    assert.equal(row.state, 'VERIFIED', 'the authorization itself is unchanged');
    assert.equal(row.bank_transaction_state, 'PENDING', 'no commit recorded');
    const audit = await q(`SELECT 1 FROM audit_logs WHERE event_type = 'integrity_violation' AND details->>'authorizationId' = $1`, [id]);
    assert.equal(audit.rows.length, 1, 'security event');
  }

  test('1. a genuine record with consistent metadata is accepted (positive control)', async () => {
    const c = await confirmed();
    const e = await exportOf(c.id);
    assert.deepEqual(verifyEvidenceRecord(e, e.evidencePublicKeys ?? e.evidencePublicKeyPem, { standalone: true }), []);
    assert.equal((await bank.call('GET', `/v1/authorizations/${c.id}`)).json.confirmed, true);
    assert.equal((await commit(c.id)).status, 202);
  });

  test('2. only nexus_id changed in the row', async () => {
    const c = await confirmed();
    const other = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    await tamper(c.evidenceId, 'nexus_id = $2', [other.nexusId]);
    await expectRefused(c.id, /metadata does not match the sealed payload/);
    const e = await exportOf(c.id);
    assert.ok(verifyEvidenceRecord(e, e.evidencePublicKeyPem).some((p) => /metadata does not match/.test(p)), 'verifier');
    const chain = (await bank.call('GET', `/v1/nexus-identities/${c.device.nexusId}/evidence`)).json;
    assert.ok(verifyEvidenceChain(chain.records, e.evidencePublicKeyPem).length > 0, 'the owner chain shows the record missing');
  });

  test('3. only credential_id changed in the row', async () => {
    const c = await confirmed();
    const other = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    await tamper(c.evidenceId, 'credential_id = $2', [other.credentialId]);
    await expectRefused(c.id, /metadata does not match the sealed payload/);
    const e = await exportOf(c.id);
    assert.ok(verifyEvidenceRecord(e, e.evidencePublicKeyPem).some((p) => /metadata does not match/.test(p)), 'verifier');
  });

  test('4. nexus_id and credential_id both changed (record moved to another registration)', async () => {
    const c = await confirmed();
    const other = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    await tamper(c.evidenceId, 'nexus_id = $2, credential_id = $3', [other.nexusId, other.credentialId]);
    await expectRefused(c.id, /metadata does not match the sealed payload/);
    const e = await exportOf(c.id);
    assert.ok(verifyEvidenceRecord(e, e.evidencePublicKeyPem).some((p) => /metadata does not match/.test(p)), 'verifier');
  });

  test('5. authorization_id moved to another authorization of the same device', async () => {
    const c = await confirmed();
    const target = await bank.createAuthorization(c.device);
    await q(`UPDATE authorization_requests SET state = 'VERIFIED', signature = 'x', signature_format = 'der', confirmation_method = 'DEVICE_SIGNATURE', verified_at = now() WHERE authorization_id = $1`, [target.authorizationId]);
    await tamper(c.evidenceId, 'authorization_id = $2', [target.authorizationId]);
    await expectRefused(target.authorizationId, /names another authorization/);
    const e = await exportOf(target.authorizationId);
    assert.ok(verifyEvidenceRecord(e, e.evidencePublicKeyPem).some((p) => /metadata does not match/.test(p)), 'verifier');
  });

  test('6. record_type, chain position, seal key or schema version changed in the row', async () => {
    for (const [assignments, reason] of [
      [`record_type = 'RECOVERY_CONFIGURED'`, /no sealed evidence/],
      [`chain_sequence = chain_sequence + 100`, /position in the chain|metadata does not match/],
      [`seal_key_id = repeat('a', 64)`, /unknown evidence key|metadata does not match/],
      [`schema_version = '2'`, /not schema 3|metadata does not match/],
    ]) {
      const c = await confirmed();
      await tamper(c.evidenceId, assignments);
      await expectRefused(c.id, reason);
    }
  });

  test('8. enrolment record of the signing credential with a changed credential_id column', async () => {
    const c = await confirmed();
    const enrolment = (await q(`SELECT enrolment_evidence_id FROM credentials WHERE credential_id = $1`, [c.device.credentialId])).rows[0].enrolment_evidence_id;
    const other = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    await tamper(enrolment, 'credential_id = $2', [other.credentialId]);
    // The device's key is no longer accepted: its enrolment record is inconsistent.
    const next = await bank.createAuthorization(c.device);
    const s = await deviceSignature(server, c.device, next.authorizationId).catch((e) => ({ error: e }));
    if (!s.error) {
      const r = await submitSignature(server, c.device, next.authorizationId, s.signature);
      assert.notEqual(r.json?.status, 'VERIFIED', `confirmation with an inconsistent enrolment record: ${r.text}`);
    }
    const view = (await bank.call('GET', `/v1/authorizations/${c.id}`)).json;
    assert.equal(view.confirmed, false, 'the earlier authorization is no longer reported confirmed');
    const r = await commit(c.id);
    assert.equal(r.status, 409, r.text);
  });

  test('7. the original seal still verifies over the untouched payload in every case above', async () => {
    const c = await confirmed();
    const other = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    await tamper(c.evidenceId, 'nexus_id = $2, credential_id = $3', [other.nexusId, other.credentialId]);
    const e = await exportOf(c.id);
    // Only the metadata problems, not the seal or the device signature.
    const problems = verifyEvidenceRecord(e, e.evidencePublicKeyPem);
    assert.ok(problems.length > 0);
    assert.ok(problems.every((p) => /metadata does not match|enrolment/.test(p)), JSON.stringify(problems));
  });
});
