// Phase 13: the bank-side execution boundary (bank-integration/). Every path
// to the payment adapter goes through ExecutionBoundary.execute(), which
// claims the payment in the bank's journal, asks Auth Core for the evidence,
// runs bankExecutionDecision with the bank's own registry, re-checks the
// device's trust under a lock and only then calls the adapter, with a
// one-time permit. Auth Core runs on SoftHSM; a compromised Auth Core is
// played by its own compiled code (support/compromise.mjs) and by an Auth
// Core client that alters what Auth Core returns.
//
// Each negative case checks the answer, that the adapter was not called,
// and that the bank recorded nothing as executed. SoftHSM is not the bank's
// vendor HSM; the recording adapter is a test double, not a payment system.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, newKey, submitSignature } from './support/actors.mjs';
import { SOFTHSM_MODULE, generateKeyPair, initToken, skipWithoutSoftHsm, softHsmDirectory } from './support/softhsm.mjs';
import { asCompromisedAuthCore } from './support/compromise.mjs';
import { canonicalJson } from '../../scripts/lib/evidence.mjs';
import { approvalStatement, revocationStatement, signStatement, signingKeyFingerprint } from '../../scripts/lib/bankTrust.mjs';

const integration = () => import('../../../bank-integration/index.mjs');

/** A payment system double: records every call; idempotent by key, as the contract requires. */
function recordingAdapter() {
  const done = new Map();
  const raw = {
    calls: [],
    beforeExecute: null,
    failAfterExecuting: false,
    async execute(order) {
      raw.calls.push(order);
      if (raw.beforeExecute) await raw.beforeExecute(order);
      const existing = done.get(order.idempotencyKey);
      const result = existing ?? { providerReference: `PAY-${raw.calls.length}` };
      done.set(order.idempotencyKey, result);
      if (raw.failAfterExecuting) { raw.failAfterExecuting = false; throw new Error('timeout waiting for the payment system'); }
      return result;
    },
    async lookup(idempotencyKey) {
      const r = done.get(idempotencyKey);
      return r ? { status: 'EXECUTED', ...r } : { status: 'NOT_FOUND' };
    },
  };
  return raw;
}

describe('bank execution boundary (SoftHSM, PostgreSQL)', { skip: skipWithoutServices || skipWithoutSoftHsm }, () => {
  let server; let bank; let client; let bankDb; let store; let lib;
  let evidenceKeys;
  const bankKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const bankTrustKeys = [bankKey.publicKey.export({ type: 'spki', format: 'pem' }).toString()];

  before(async () => {
    const conf = softHsmDirectory();
    generateKeyPair(conf, initToken(conf, 'nexus-main'), { label: 'nexus-evidence' });
    server = await startAuthCore({ env: {
      SOFTHSM2_CONF: conf, HSM_ADAPTER: 'pkcs11', PKCS11_MODULE_PATH: SOFTHSM_MODULE, PKCS11_PIN: '12345678',
      PKCS11_TOKEN_LABEL: 'nexus-main', PKCS11_EVIDENCE_KEY_LABEL: 'nexus-evidence',
    } });
    client = await server.registerBank('bank-boundary');
    bank = await bankSession(server, client);
    lib = await integration();
    bankDb = await createDatabase({ schema: false }); // the bank's own database
    store = lib.createPostgresTrustStore(bankDb.pool, { bankTrustKeys });
    await store.migrate();
    // Key ceremony: the evidence public key, recorded once by the bank.
    const probe = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const auth = await bank.createAuthorization(probe);
    const s = await deviceSignature(server, probe, auth.authorizationId);
    await submitSignature(server, probe, auth.authorizationId, s.signature);
    evidenceKeys = Object.values((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/evidence`)).json.evidencePublicKeys);
  });
  after(async () => { await server?.stop(); await bankDb?.drop(); });

  const authCoreClient = () => lib.createAuthCoreClient({ baseUrl: server.baseUrl, accessToken: async () => bank.token, timeoutMs: 5_000 });
  const boundary = ({ authCore = authCoreClient(), trust = store, adapter = recordingAdapter() } = {}) => {
    const guarded = lib.guardPaymentAdapter(adapter);
    return { adapter, guarded, boundary: lib.createExecutionBoundary({ store: trust, authCore, payments: guarded, evidenceKeys, bankTrustKeys, leaseMs: 30_000 }) };
  };

  const approve = (device, nexusId = device.nexusId, fingerprint = signingKeyFingerprint(device.signingKey.publicKeyPem)) =>
    store.approve(signStatement(approvalStatement({ nexusId, credentialId: device.credentialId, signingKeySha256: fingerprint, reference: 'app' }), bankKey.privateKey));
  const revoke = (device, reason = 'lost') =>
    store.revoke(signStatement(revocationStatement({ nexusId: device.nexusId, credentialId: device.credentialId, reason }), bankKey.privateKey));

  const TERMS = { operationType: 'TRANSFER', amountMinor: '125000', currency: 'PLN', beneficiary: { name: 'Anna Nowak', iban: 'PL61109010140000071219812874' } };

  /** The bank creates the payment in its own system and the authorization at Auth Core; the device confirms. */
  async function payment(device, { atAuthCore = {}, inBank = {} } = {}) {
    const transactionReference = `tx-${randomUUID()}`;
    const auth = await bank.createAuthorization(device, { transactionReference, ...atAuthCore });
    const s = await deviceSignature(server, device, auth.authorizationId);
    assert.equal((await submitSignature(server, device, auth.authorizationId, s.signature)).json.status, 'VERIFIED');
    const paymentId = randomUUID();
    await store.createPayment({
      paymentId, authorizationId: auth.authorizationId, bankTransactionReference: `CORE-${paymentId.slice(0, 8)}`,
      terms: { authorizationId: auth.authorizationId, nexusId: device.nexusId, transactionReference, ...TERMS, ...inBank },
    });
    return { paymentId, authorizationId: auth.authorizationId };
  }

  const approvedDevice = async () => {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    await approve(device);
    return device;
  };

  async function expectNotExecuted(result, adapter, paymentId, status, reason) {
    assert.equal(result.status, status, JSON.stringify(result));
    if (reason) assert.ok((result.problems ?? [result.reason]).some((p) => reason.test(String(p))), JSON.stringify(result));
    assert.equal(adapter.calls.length, 0, 'the payment adapter was not called');
    const execution = await store.execution(paymentId);
    assert.notEqual(execution?.state, 'EXECUTED');
    assert.equal(execution?.providerReference ?? null, null);
  }

  test('positive: approved, not revoked, valid evidence, same terms, valid head — executed once; a repeat does not execute again', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const { adapter, boundary: b } = boundary();
    const r = await b.execute(p.paymentId);
    assert.equal(r.status, 'EXECUTED', JSON.stringify(r));
    assert.equal(adapter.calls.length, 1);
    assert.equal(adapter.calls[0].amountMinor, '125000');
    assert.equal(adapter.calls[0].idempotencyKey, (await store.payment(p.paymentId)).bankTransactionReference);
    const view = (await bank.call('GET', `/v1/authorizations/${p.authorizationId}/bank-transaction`)).json;
    assert.equal(view.bankTransactionState, 'COMMITTED', 'reported to Auth Core after execution');
    const head = await store.head(device.nexusId);
    assert.ok(head && head.chainSequence >= 2, 'the bank kept the chain head');
    const again = await b.execute(p.paymentId);
    assert.equal(again.status, 'EXECUTED');
    assert.equal(again.repeated, true);
    assert.equal(adapter.calls.length, 1, 'not executed twice');
  });

  test('Auth Core reports VERIFIED for a key the bank never approved (enrolled by Auth Core alone)', async () => {
    const device = await approvedDevice();
    const attacker = { signingKey: newKey(), authKey: newKey(), offlineKey: newKey(), nexusId: device.nexusId };
    attacker.credentialId = (await asCompromisedAuthCore(server, { kind: 'enrol', nexusId: device.nexusId, clientId: client.clientId,
      signingPublicKeyPem: attacker.signingKey.publicKeyPem, authPublicKeyPem: attacker.authKey.publicKeyPem, offlinePublicKeyPem: attacker.offlineKey.publicKeyPem })).credentialId;
    const p = await payment(attacker);
    assert.equal((await bank.call('GET', `/v1/authorizations/${p.authorizationId}`)).json.confirmed, true, 'Auth Core says confirmed');
    const { adapter, boundary: b } = boundary();
    await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'REFUSED', /not approved by the bank/);
    assert.equal((await bank.call('GET', `/v1/authorizations/${p.authorizationId}/bank-transaction`)).json.bankTransactionState, 'CANCELLED');
  });

  test('the key of an approved credential substituted after approval', async () => {
    const device = await approvedDevice();
    const attacker = { ...device, signingKey: newKey(), authKey: newKey(), offlineKey: newKey() };
    await asCompromisedAuthCore(server, { kind: 'substitute-keys', nexusId: device.nexusId, credentialId: device.credentialId,
      signingPublicKeyPem: attacker.signingKey.publicKeyPem, authPublicKeyPem: attacker.authKey.publicKeyPem, offlinePublicKeyPem: attacker.offlineKey.publicKeyPem });
    const p = await payment(attacker);
    const { adapter, boundary: b } = boundary();
    await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'REFUSED', /differs from the key the bank approved/);
  });

  test('a key the bank revoked (Auth Core still reports it ACTIVE)', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    await revoke(device);
    const { adapter, boundary: b } = boundary();
    await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'REFUSED', /revoked by the bank/);
  });

  test('an approval that belongs to another customer', async () => {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    await approve(device, '999999999');
    const p = await payment(device);
    const { adapter, boundary: b } = boundary();
    await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'REFUSED', /not approved by the bank/);
    // The registry binds a credential to one customer.
    await assert.rejects(approve(device), /another customer/);
  });

  test('amount, beneficiary, currency, reference or operation type other than the bank recorded', async () => {
    const device = await approvedDevice();
    for (const [field, inBank, re] of [
      ['amount', { amountMinor: '100' }, /amount_minor/],
      ['beneficiary', { beneficiary: { name: 'Anna Nowak', iban: 'PL27114020040000300201355387' } }, /beneficiary/],
      ['currency', { currency: 'EUR' }, /currency/],
      ['reference', { transactionReference: 'tx-other' }, /transaction_reference/],
      ['operation type', { operationType: 'BILL_PAYMENT' }, /operation_type/],
    ]) {
      const p = await payment(device, { inBank });
      const { adapter, boundary: b } = boundary();
      await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'REFUSED', re);
      void field;
    }
  });

  /** An Auth Core client that hands the boundary something else than Auth Core sent. */
  const altering = (changes) => {
    const real = authCoreClient();
    return { ...real, evidence: async (id) => changes.evidence ? changes.evidence(await real.evidence(id)) : real.evidence(id),
      chain: async (n) => changes.chain ? changes.chain(await real.chain(n)) : real.chain(n) };
  };

  test('evidence that verifies only with the key shipped in the export', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const own = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const ownId = createHash('sha256').update(own.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    const reseal = (record) => {
      record.sealedPayload.sealKeyId = ownId; record.sealKeyId = ownId;
      record.evidenceHash = createHash('sha256').update(canonicalJson(record.sealedPayload)).digest('hex');
      record.hsmSignature = sign('sha256', Buffer.from(record.evidenceHash, 'hex'), { key: own.privateKey, dsaEncoding: 'der' }).toString('base64');
    };
    const { adapter, boundary: b } = boundary({ authCore: altering({ evidence: (e) => {
      reseal(e.credentialEnrolment);
      e.sealedPayload.enrolmentEvidenceHash = e.credentialEnrolment.evidenceHash;
      reseal(e);
      e.evidencePublicKeys = { [ownId]: own.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
      return e;
    } }) });
    await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'REFUSED', /HSM seal does not verify/);
  });

  test('damaged evidence, or a broken chain', async () => {
    const device = await approvedDevice();
    for (const changes of [
      { evidence: (e) => { e.sealedPayload.signature = Buffer.from('x'.repeat(70)).toString('base64'); return e; } },
      { chain: (c) => ({ ...c, records: c.records.filter((r) => r.chainSequence !== 1) }) },
    ]) {
      const p = await payment(device);
      const { adapter, boundary: b } = boundary({ authCore: altering(changes) });
      await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'REFUSED');
    }
  });

  test('a kept chain head that was changed, or a chain that ends before it', async () => {
    const device = await approvedDevice();
    const first = await payment(device);
    assert.equal((await boundary().boundary.execute(first.paymentId)).status, 'EXECUTED');
    const kept = await store.head(device.nexusId);
    // Changed: the bank's head names another record at that position.
    const p1 = await payment(device);
    const { boundary: b1, adapter: a1 } = boundary({ authCore: altering({ chain: (c) => {
      const r = c.records.find((x) => x.chainSequence === kept.chainSequence); r.evidenceHash = 'f'.repeat(64); return c; } }) });
    await expectNotExecuted(await b1.execute(p1.paymentId), a1, p1.paymentId, 'REFUSED');
    // Stale: Auth Core returns the chain as it was before the kept head.
    const p2 = await payment(device);
    const { boundary: b2, adapter: a2 } = boundary({ authCore: altering({ chain: (c) => ({ ...c, records: c.records.filter((x) => x.chainSequence < kept.chainSequence) }) }) });
    await expectNotExecuted(await b2.execute(p2.paymentId), a2, p2.paymentId, 'REFUSED', /records missing at the end of the chain|not in the chain/);
  });

  test('the trust registry or Auth Core unavailable: held, not executed; executed once it is back', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const broken = { ...store, loadTrust: async () => { throw new Error('connection refused'); } };
    const { adapter, boundary: b } = boundary({ trust: broken });
    await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'HELD', /connection refused|unavailable/);
    const unreachable = lib.createAuthCoreClient({ baseUrl: 'http://127.0.0.1:9', accessToken: async () => bank.token, timeoutMs: 1_000 });
    const { adapter: a2, boundary: b2 } = boundary({ authCore: unreachable });
    await expectNotExecuted(await b2.execute(p.paymentId), a2, p.paymentId, 'HELD');
    const slow = { ...authCoreClient(), evidence: () => new Promise(() => {}) };
    const { adapter: a3, boundary: b3 } = boundary({ authCore: lib.withTimeouts(slow, 500) });
    await expectNotExecuted(await b3.execute(p.paymentId), a3, p.paymentId, 'HELD', /timed out/);
    const { adapter: a4, boundary: b4 } = boundary();
    assert.equal((await b4.execute(p.paymentId)).status, 'EXECUTED');
    assert.equal(a4.calls.length, 1);
  });

  test('parallel requests for one payment, through two boundary instances with separate connections: executed once', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const otherPool = new pg.Pool({ connectionString: bankDb.url, max: 4 });
    try {
      const adapter = recordingAdapter();
      const one = boundary({ adapter }).boundary;
      const two = boundary({ adapter, trust: lib.createPostgresTrustStore(otherPool, { bankTrustKeys }) }).boundary;
      const results = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? one : two).execute(p.paymentId)));
      assert.equal(adapter.calls.length, 1, JSON.stringify(results.map((r) => r.status)));
      assert.equal(results.filter((r) => r.status === 'EXECUTED' && !r.repeated).length, 1);
      assert.ok(results.every((r) => ['EXECUTED', 'IN_PROGRESS'].includes(r.status)), JSON.stringify(results.map((r) => r.status)));
    } finally { await otherPool.end(); }
  });

  test('an old genuine evidence record replayed for another payment', async () => {
    const device = await approvedDevice();
    const old = await payment(device);
    const p = await payment(device);
    const real = authCoreClient();
    const { adapter, boundary: b } = boundary({ authCore: { ...real, evidence: () => real.evidence(old.authorizationId) } });
    await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'REFUSED', /authorization_id|not what the bank asked for/);
    // One authorization pays one payment only.
    await assert.rejects(store.createPayment({ paymentId: randomUUID(), authorizationId: old.authorizationId, bankTransactionReference: `CORE-${randomUUID().slice(0, 8)}`, terms: {} }), /already|unique|duplicate/i);
  });

  test('the payment adapter cannot be called around the boundary', async () => {
    const adapter = recordingAdapter();
    const guarded = lib.guardPaymentAdapter(adapter);
    const order = { idempotencyKey: 'CORE-x', amountMinor: '1', currency: 'PLN', beneficiary: {}, reference: 'r' };
    await assert.rejects(guarded.adapter.execute(undefined, order), lib.BoundaryBypassError);
    await assert.rejects(guarded.adapter.execute('forged-permit', order), lib.BoundaryBypassError);
    const permit = guarded.issuePermit(order);
    await assert.rejects(guarded.adapter.execute(permit, { ...order, amountMinor: '999' }), lib.BoundaryBypassError, 'permit is for exactly one order');
    await assert.rejects(guarded.adapter.execute(permit, order), lib.BoundaryBypassError, 'and is used up even by a failed attempt');
    assert.equal(adapter.calls.length, 0);
    assert.equal(typeof guarded.adapter.execute, 'function');
    assert.equal(Object.isFrozen(guarded.adapter), true);
  });

  test('revocation while the payment is being checked: refused at the final check', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const real = authCoreClient();
    const { adapter, boundary: b } = boundary({ authCore: { ...real, evidence: async (id) => { const e = await real.evidence(id); await revoke(device); return e; } } });
    await expectNotExecuted(await b.execute(p.paymentId), adapter, p.paymentId, 'REFUSED', /revoked/);
  });

  test('revocation after the final check: the payment in flight is reported to the revoking side', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const adapter = recordingAdapter();
    let inFlight;
    adapter.beforeExecute = async () => { inFlight = await revoke(device); };
    const r = await boundary({ adapter }).boundary.execute(p.paymentId);
    assert.equal(r.status, 'EXECUTED', 'ordered before the revocation');
    assert.deepEqual(inFlight.map((x) => x.paymentId), [p.paymentId], 'the revocation names the payment in flight');
  });

  test('timeout after the payment system executed: reconciled by lookup, never executed twice', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const adapter = recordingAdapter();
    adapter.failAfterExecuting = true;
    const first = await boundary({ adapter }).boundary.execute(p.paymentId);
    assert.equal(first.status, 'OUTCOME_UNKNOWN', JSON.stringify(first));
    const again = await boundary({ adapter }).boundary.execute(p.paymentId);
    assert.equal(again.status, 'EXECUTED', JSON.stringify(again));
    assert.equal(adapter.calls.length, 1, 'only one execute call reached the payment system');
    // Not found by the payment system: held for review, not retried blindly.
    const q = await payment(device);
    const lost = recordingAdapter();
    lost.execute = async (order) => { lost.calls.push(order); throw new Error('connection reset'); };
    assert.equal((await boundary({ adapter: lost }).boundary.execute(q.paymentId)).status, 'OUTCOME_UNKNOWN');
    const review = await boundary({ adapter: lost }).boundary.execute(q.paymentId);
    assert.equal(review.status, 'REVIEW', JSON.stringify(review));
    assert.equal(lost.calls.length, 1);
  });

  test('two payments of one customer at once: the kept head only moves forward', async () => {
    const device = await approvedDevice();
    const a = await payment(device); const c = await payment(device);
    const [ra, rc] = await Promise.all([boundary().boundary.execute(a.paymentId), boundary().boundary.execute(c.paymentId)]);
    assert.equal(ra.status, 'EXECUTED'); assert.equal(rc.status, 'EXECUTED');
    const chain = (await bank.call('GET', `/v1/nexus-identities/${device.nexusId}/evidence`)).json.records;
    const head = await store.head(device.nexusId);
    assert.equal(head.chainSequence, Math.max(...chain.map((r) => r.chainSequence)));
  });
});
