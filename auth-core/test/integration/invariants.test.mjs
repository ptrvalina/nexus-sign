// Core security invariants against a live Auth Core, PostgreSQL and Redis:
// transaction binding, single use under concurrency, replay, expiry, state
// transitions and tenant isolation.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, call, deviceSignature, offlineCode, signDer, submitSignature } from './support/actors.mjs';

describe('security invariants', { skip: skipWithoutServices }, () => {
  let server; let bankA; let bankB; let deviceA; let deviceB;

  before(async () => {
    // Offline confirmation v1 for the concurrent-code invariant; the v2
    // equivalent is in offline-deferred-signature.test.mjs.
    server = await startAuthCore({ env: { OFFLINE_CONFIRMATION_MODE: 'immediate' } });
    bankA = await bankSession(server, await server.registerBank('bank-a'));
    bankB = await bankSession(server, await server.registerBank('bank-b'));
    deviceA = await bankA.enrolDevice((await bankA.createIdentity()).nexusId);
    deviceB = await bankB.enrolDevice((await bankB.createIdentity()).nexusId);
  });
  after(async () => { await server?.stop(); });

  test('a signature for transaction A never authorizes transaction B', async () => {
    const a = await bankA.createAuthorization(deviceA);
    const b = await bankA.createAuthorization(deviceA);
    const { signature } = await deviceSignature(server, deviceA, a.authorizationId);
    const crossed = await submitSignature(server, deviceA, b.authorizationId, signature);
    assert.equal(crossed.json.status, 'FAILED');
    assert.equal((await submitSignature(server, deviceA, a.authorizationId, signature)).json.status, 'VERIFIED');
  });

  test('a signature over altered amount or recipient bytes is rejected', async () => {
    const auth = await bankA.createAuthorization(deviceA);
    const { canonical } = await deviceSignature(server, deviceA, auth.authorizationId);
    const fields = JSON.parse(canonical.toString('utf8'));
    for (const altered of [{ ...fields, amount_minor: '1' }, { ...fields, beneficiary: { ...fields.beneficiary, iban: 'PL00000000000000000000000000' } }]) {
      const bytes = Buffer.from(JSON.stringify(altered, Object.keys(altered).sort()), 'utf8');
      const r = await submitSignature(server, deviceA, auth.authorizationId, signDer(deviceA.signingKey, bytes));
      assert.equal(r.json.status, 'FAILED');
    }
  });

  test('100 concurrent submissions of one valid signature consume the authorization exactly once', async () => {
    const auth = await bankA.createAuthorization(deviceA);
    const { signature } = await deviceSignature(server, deviceA, auth.authorizationId);
    const results = await Promise.all(Array.from({ length: 100 }, () => submitSignature(server, deviceA, auth.authorizationId, signature)));
    const verified = results.filter((r) => r.json?.status === 'VERIFIED');
    assert.equal(verified.length, 1, JSON.stringify(results.map((r) => r.status)));
    for (const r of results.filter((x) => x.json?.status !== 'VERIFIED')) {
      assert.ok(r.status === 200 && r.json.status === 'FAILED', `deterministic rejection, got ${r.status} ${r.text}`);
    }
    const evidence = await server.db.query(`SELECT count(*)::int AS n FROM evidence_records WHERE authorization_id = $1`, [auth.authorizationId]);
    assert.equal(evidence.rows[0].n, 1);
  });

  test('100 concurrent submissions of one valid offline code consume the authorization exactly once', async () => {
    const auth = await bankA.createAuthorization(deviceA);
    const { canonical } = await deviceSignature(server, deviceA, auth.authorizationId);
    const code = offlineCode(deviceA, canonical);
    const results = await Promise.all(Array.from({ length: 100 }, () =>
      bankA.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code } })));
    assert.equal(results.filter((r) => r.json?.status === 'VERIFIED').length, 1);
    assert.ok(results.every((r) => r.status === 200));
  });

  test('a replayed device request is refused', async () => {
    const auth = await bankA.createAuthorization(deviceA);
    const path = `/v1/mobile/authorizations/${auth.authorizationId}`;
    const { deviceHeaders } = await import('./support/actors.mjs');
    const headers = deviceHeaders(deviceA, 'GET', path, '');
    assert.equal((await call(server.baseUrl, 'GET', path, { headers })).status, 200);
    assert.equal((await call(server.baseUrl, 'GET', path, { headers })).status, 401);
  });

  test('expired, cancelled and already verified authorizations cannot be authorized', async () => {
    const expired = await bankA.createAuthorization(deviceA);
    const expiredSig = await deviceSignature(server, deviceA, expired.authorizationId);
    await server.db.query(`UPDATE authorization_requests SET expires_at = now() - interval '1 second' WHERE authorization_id = $1`, [expired.authorizationId]);
    assert.equal((await submitSignature(server, deviceA, expired.authorizationId, expiredSig.signature)).json.status, 'EXPIRED');
    assert.equal((await submitSignature(server, deviceA, expired.authorizationId, expiredSig.signature)).json.status, 'EXPIRED');

    const verified = await bankA.createAuthorization(deviceA);
    const sig = await deviceSignature(server, deviceA, verified.authorizationId);
    assert.equal((await submitSignature(server, deviceA, verified.authorizationId, sig.signature)).json.status, 'VERIFIED');
    assert.equal((await submitSignature(server, deviceA, verified.authorizationId, sig.signature)).json.status, 'FAILED');

    const identity = await bankA.createIdentity();
    const device = await bankA.enrolDevice(identity.nexusId);
    const cancelled = await bankA.createAuthorization(device);
    const cancelledSig = await deviceSignature(server, device, cancelled.authorizationId);
    const revoke = await bankA.call('POST', `/v1/credentials/${device.credentialId}/revoke`, { body: { reason: 'lost device' } });
    assert.equal(revoke.status, 200);
    const afterRevoke = await bankA.call('POST', `/v1/authorizations/${cancelled.authorizationId}/signature`, { body: { signature: cancelledSig.signature, signatureFormat: 'der' } });
    assert.equal(afterRevoke.json.status, 'FAILED');
  });

  test('bank B cannot read or act on bank A objects', async () => {
    const auth = await bankA.createAuthorization(deviceA);
    const sig = await deviceSignature(server, deviceA, auth.authorizationId);
    await submitSignature(server, deviceA, auth.authorizationId, sig.signature);
    const id = auth.authorizationId;
    const probes = [
      ['GET', `/v1/authorizations/${id}`],
      ['GET', `/v1/authorizations/${id}/evidence`],
      ['GET', `/v1/authorizations/${id}/verification-plan`],
      ['GET', `/v1/authorizations/${id}/offline-challenge`],
      ['GET', `/v1/authorizations/${id}/bank-transaction`],
      ['POST', `/v1/authorizations/${id}/bank-commit-request`, { bankTransactionReference: 'x' }],
      ['POST', `/v1/authorizations/${id}/signature`, { signature: sig.signature, signatureFormat: 'der' }],
      ['POST', `/v1/authorizations/${id}/verification/escalate`, { reason: 'RISK_POLICY' }],
      ['GET', `/v1/nexus-identities/${deviceA.nexusId}`],
      ['GET', `/v1/nexus-identities/${deviceA.nexusId}/evidence`],
      ['GET', `/v1/credentials/${deviceA.credentialId}`],
      ['POST', `/v1/credentials/${deviceA.credentialId}/revoke`, { reason: 'x' }],
      ['POST', '/v1/mobile/sessions', { nexusId: deviceA.nexusId, purpose: 'BOOTSTRAP' }],
      ['POST', '/v1/recovery/sessions', { bankCustomerRef: 'anything' }],
    ];
    for (const [method, path, body] of probes) {
      const r = await bankB.call(method, path, body ? { body } : {});
      assert.ok([404, 409].includes(r.status) && r.json?.status !== 'VERIFIED', `${method} ${path} -> ${r.status} ${r.text}`);
    }
    const commit = await bankA.call('GET', `/v1/authorizations/${id}/bank-transaction`);
    assert.equal(commit.status, 200, 'bank A still owns its authorization');
  });

  test('a device of bank A cannot read or sign bank B authorizations', async () => {
    const authB = await bankB.createAuthorization(deviceB);
    const fetch = await call(server.baseUrl, 'GET', `/v1/mobile/authorizations/${authB.authorizationId}`, { device: deviceA });
    assert.ok([403, 404].includes(fetch.status), fetch.text);
    const sig = await deviceSignature(server, deviceB, authB.authorizationId);
    const sign = await submitSignature(server, deviceA, authB.authorizationId, sig.signature);
    assert.ok([403, 404].includes(sign.status), sign.text);
    const stillPending = await bankB.call('GET', `/v1/authorizations/${authB.authorizationId}`);
    assert.equal(stillPending.json.state, 'PENDING_USER');
  });

  test('the same transaction reference cannot be authorized twice', async () => {
    const reference = `tx-${randomUUID()}`;
    await bankA.createAuthorization(deviceA, { transactionReference: reference });
    const duplicate = await bankA.call('POST', '/v1/authorizations', {
      headers: { 'Idempotency-Key': randomUUID() },
      body: { nexusId: deviceA.nexusId, credentialId: deviceA.credentialId, transactionReference: reference, operationType: 'TRANSFER', amountMinor: '1', currency: 'PLN', beneficiary: {}, policyReference: 'p', policyVersion: '1' },
    });
    assert.equal(duplicate.status, 409, duplicate.text);
  });

  test('A confirmation cannot be committed after the identity is suspended or when it is too old', async () => {
    const auth = await bankA.createAuthorization(deviceA);
    const { signature } = await deviceSignature(server, deviceA, auth.authorizationId);
    assert.equal((await submitSignature(server, deviceA, auth.authorizationId, signature)).json.status, 'VERIFIED');
    await server.db.query(`UPDATE nexus_identities SET status = 'SUSPENDED' WHERE nexus_id = $1`, [deviceA.nexusId]);
    const suspended = await bankA.call('POST', `/v1/authorizations/${auth.authorizationId}/bank-commit-request`, { body: { bankTransactionReference: 'B-1' } });
    assert.equal(suspended.status, 409);
    assert.equal(suspended.json.code, 'IDENTITY_NOT_ACTIVE');
    await server.db.query(`UPDATE nexus_identities SET status = 'ACTIVE' WHERE nexus_id = $1`, [deviceA.nexusId]);

    const old = await bankA.createAuthorization(deviceA);
    const signed = await deviceSignature(server, deviceA, old.authorizationId);
    await submitSignature(server, deviceA, old.authorizationId, signed.signature);
    // verified_at is immutable for the application; age it as a table owner would.
    const tx = await server.db.connect();
    try {
      await tx.query('BEGIN');
      await tx.query('ALTER TABLE authorization_requests DISABLE TRIGGER authorization_lifecycle');
      await tx.query(`UPDATE authorization_requests SET verified_at = now() - interval '2 hours' WHERE authorization_id = $1`, [old.authorizationId]);
      await tx.query('ALTER TABLE authorization_requests ENABLE TRIGGER authorization_lifecycle');
      await tx.query('COMMIT');
    } finally { tx.release(); }
    const stale = await bankA.call('POST', `/v1/authorizations/${old.authorizationId}/bank-commit-request`, { body: { bankTransactionReference: 'B-2' } });
    assert.equal(stale.status, 409);
    assert.equal(stale.json.code, 'CONFIRMATION_TOO_OLD');
    assert.equal((await bankA.call('POST', `/v1/authorizations/${auth.authorizationId}/bank-commit-request`, { body: { bankTransactionReference: 'B-1' } })).status, 202);
  });
});
