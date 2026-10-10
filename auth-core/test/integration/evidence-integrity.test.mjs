// A privileged database writer is part of the threat model: database rows
// are not cryptographic truth. These tests change rows directly and check
// that Auth Core refuses to act on them and that the offline verifier
// detects what Auth Core cannot prevent.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { ROOT, skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, call, deviceSignature, newKey, signDer, submitSignature } from './support/actors.mjs';

const { verifyEvidenceChain, verifyEvidenceRecord } = await import(join(ROOT, 'scripts/lib/evidence.mjs'));

describe('evidence and credential integrity against a database writer', { skip: skipWithoutServices }, () => {
  let server; let bank;

  before(async () => {
    server = await startAuthCore();
    bank = await bankSession(server, await server.registerBank('bank-integrity'));
  });
  after(async () => { await server?.stop(); });

  test('a credential key replaced in the database cannot approve a transaction', async () => {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const authorization = await bank.createAuthorization(device);
    const { canonical } = await deviceSignature(server, device, authorization.authorizationId);

    const attackerSigning = newKey();
    const attackerAuth = newKey();
    const swap = `UPDATE credentials SET public_key_pem = $2, auth_public_key_pem = $3 WHERE credential_id = $1`;
    const swapArgs = [device.credentialId, attackerSigning.publicKeyPem, attackerAuth.publicKeyPem];
    // First layer: the credential lifecycle trigger refuses the write.
    await assert.rejects(server.db.query(swap, swapArgs), /keys and identity binding are immutable/);
    // A table owner can disable the trigger; the sealed enrolment still catches it.
    const tx = await server.db.connect();
    try {
      await tx.query('BEGIN');
      await tx.query('ALTER TABLE credentials DISABLE TRIGGER credential_lifecycle');
      await tx.query(swap, swapArgs);
      await tx.query('ALTER TABLE credentials ENABLE TRIGGER credential_lifecycle');
      await tx.query('COMMIT');
    } finally { tx.release(); }
    const attacker = { ...device, signingKey: attackerSigning, authKey: attackerAuth };

    const fetched = await call(server.baseUrl, 'GET', `/v1/mobile/authorizations/${authorization.authorizationId}`, { device: attacker });
    assert.equal(fetched.status, 401, `device requests with a swapped key are refused: ${fetched.text}`);

    const result = await bank.call('POST', `/v1/authorizations/${authorization.authorizationId}/signature`,
      { body: { signature: signDer(attackerSigning, canonical), signatureFormat: 'der' } });
    assert.notEqual(result.json?.status, 'VERIFIED', `the swapped key must not approve: ${result.text}`);
    const audit = await server.db.query(`SELECT count(*)::int AS n FROM audit_logs WHERE event_type = 'integrity_violation'`);
    assert.ok(audit.rows[0].n >= 1, 'the violation is audited');
  });

  test('the offline verifier rejects a chain whose device key does not match its sealed enrolment', async () => {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const authorization = await bank.createAuthorization(device);
    const { signature } = await deviceSignature(server, device, authorization.authorizationId);
    assert.equal((await submitSignature(server, device, authorization.authorizationId, signature)).json.status, 'VERIFIED');
    const exported = (await bank.call('GET', `/v1/nexus-identities/${device.nexusId}/evidence`)).json;
    assert.deepEqual(verifyEvidenceChain(exported.records, exported.evidencePublicKeys), []);

    // An export rewritten to carry another key no longer verifies.
    const forged = structuredClone(exported.records);
    const enrolment = forged.find((r) => r.recordType === 'CREDENTIAL_ENROLLED');
    enrolment.sealedPayload.keys.signingPublicKeyPem = newKey().publicKeyPem;
    assert.ok(verifyEvidenceChain(forged, exported.evidencePublicKeys).length > 0);
  });

  test('deleting the newest records is detected against the head the bank received', async () => {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    let head;
    for (let i = 0; i < 3; i += 1) {
      const authorization = await bank.createAuthorization(device);
      const { signature } = await deviceSignature(server, device, authorization.authorizationId);
      const confirmed = await submitSignature(server, device, authorization.authorizationId, signature);
      assert.equal(confirmed.json.status, 'VERIFIED');
      const record = (await bank.call('GET', `/v1/authorizations/${authorization.authorizationId}`)).json;
      head = record.evidence;
      assert.ok(head?.chainSequence && head?.evidenceHash, `the bank receives the chain head: ${JSON.stringify(record)}`);
    }
    const exported = (await bank.call('GET', `/v1/nexus-identities/${device.nexusId}/evidence`)).json;
    assert.deepEqual(verifyEvidenceChain(exported.records, exported.evidencePublicKeys, { expectedHead: head }), []);
    const truncated = exported.records.slice(0, -1);
    assert.ok(verifyEvidenceChain(truncated, exported.evidencePublicKeys, { expectedHead: head }).some((p) => /missing|truncat/i.test(p)));
    assert.ok(verifyEvidenceChain([], exported.evidencePublicKeys, { expectedHead: head }).length > 0);
  });

  test('a single authorization export carries the enrolment that proves its key', async () => {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const authorization = await bank.createAuthorization(device);
    const { signature } = await deviceSignature(server, device, authorization.authorizationId);
    await submitSignature(server, device, authorization.authorizationId, signature);
    const exported = (await bank.call('GET', `/v1/authorizations/${authorization.authorizationId}/evidence`)).json;
    assert.deepEqual(verifyEvidenceRecord(exported, exported.evidencePublicKeys), []);
    exported.credentialEnrolment.sealedPayload.keys.signingPublicKeyPem = newKey().publicKeyPem;
    assert.ok(verifyEvidenceRecord(exported, exported.evidencePublicKeys).length > 0);
  });

  test('evidence rows cannot be changed or deleted by the application role', async () => {
    await assert.rejects(() => server.db.query(`UPDATE evidence_records SET result = 'X'`), /append-only/);
    await assert.rejects(() => server.db.query(`DELETE FROM evidence_records`), /append-only/);
  });
});
