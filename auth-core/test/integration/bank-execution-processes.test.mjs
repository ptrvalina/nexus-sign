// Phase 14: the execution boundary with the payment gateway in its own
// process (its own database role, mutual TLS), the provider double behind
// HTTP, several boundary instances, deterministic barriers at each step of an
// attempt, simulated crashes at each transition, a killed gateway process,
// and the provider's answers: pending, failed, nonsense, lost, late, none.
//
// The provider double is not a payment provider: it shows how the boundary
// behaves for each answer a provider can give, and that it never sends a
// payment again only because no answer came. Whether a real provider is
// idempotent and offers a lookup is a property of its contract, not of these
// tests. SoftHSM is not the bank's vendor HSM.
//
// Phase 15: the database is in the schema `bank`; no role writes a table; the
// gateway checks the approval again and records the provider's answers.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto';
import { request } from 'node:https';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, newKey, submitSignature } from './support/actors.mjs';
import { SOFTHSM_MODULE, generateKeyPair, initToken, skipWithoutSoftHsm, softHsmDirectory } from './support/softhsm.mjs';
import { asCompromisedAuthCore } from './support/compromise.mjs';
import { bankDatabase, certificates, providerDouble, providerServer, startGatewayProcess } from './support/bankSide.mjs';
import { approvalStatement, revocationStatement, signStatement, signingKeyFingerprint } from '../../scripts/lib/bankTrust.mjs';

const integration = () => import('../../../bank-integration/index.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A point an attempt stops at until the test releases it. */
function barrier() {
  let release; let reached;
  const gate = new Promise((r) => { release = r; });
  const atGate = new Promise((r) => { reached = r; });
  return { atGate, release: () => release(), wait: async () => { reached(); await gate; } };
}

describe('execution boundary across processes (SoftHSM, PostgreSQL, mutual TLS)', { skip: skipWithoutServices || skipWithoutSoftHsm }, () => {
  let server; let bank; let client; let lib; let bankDb; let store; let registry; let operator; let certs; let provider; let providerHttp; let gatewayProc;
  let evidenceKeys;
  const bankKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const bankTrustKeys = [bankKey.publicKey.export({ type: 'spki', format: 'pem' }).toString()];
  const webhookSecret = 'test-webhook-secret-not-real';

  before(async () => {
    const conf = softHsmDirectory();
    generateKeyPair(conf, initToken(conf, 'nexus-main'), { label: 'nexus-evidence' });
    server = await startAuthCore({ env: {
      SOFTHSM2_CONF: conf, HSM_ADAPTER: 'pkcs11', PKCS11_MODULE_PATH: SOFTHSM_MODULE, PKCS11_PIN: '12345678',
      PKCS11_TOKEN_LABEL: 'nexus-main', PKCS11_EVIDENCE_KEY_LABEL: 'nexus-evidence',
    } });
    client = await server.registerBank('bank-processes');
    bank = await bankSession(server, client);
    lib = await integration();
    bankDb = await bankDatabase(lib);
    store = lib.createTrustStore(bankDb.pools.boundary);
    registry = lib.createRegistry(bankDb.pools.registry, { bankTrustKeys });
    operator = lib.createOperatorTools(bankDb.pools.operator);
    const probe = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const auth = await bank.createAuthorization(probe);
    const s = await deviceSignature(server, probe, auth.authorizationId);
    await submitSignature(server, probe, auth.authorizationId, s.signature);
    evidenceKeys = Object.values((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/evidence`)).json.evidencePublicKeys);
    certs = certificates();
    provider = providerDouble({ idempotent: true });
    providerHttp = await providerServer(provider);
    gatewayProc = await startGateway(providerHttp.url);
  });
  const startGateway = (providerUrl) => startGatewayProcess({ databaseUrl: bankDb.urls.gateway, providerUrl, certs, evidenceKeys, bankTrustKeys });
  after(async () => { await gatewayProc?.stop().catch(() => undefined); await providerHttp?.close(); await server?.stop(); await bankDb?.drop(); });

  const authCoreClient = () => lib.createAuthCoreClient({ baseUrl: server.baseUrl, accessToken: async () => bank.token, timeoutMs: 5_000 });
  const gatewayClient = ({ cert = certs.boundary, timeoutMs = 5_000, url = gatewayProc.url } = {}) =>
    lib.createGatewayClient({ url, tls: { ...cert, ca: certs.ca, servername: 'localhost' }, timeoutMs });
  const boundary = ({ hooks = {}, leaseMs = 30_000, capabilities = { lookup: true, idempotentSubmit: true }, gateway = gatewayClient(), authCore = authCoreClient(), trust = store } = {}) =>
    lib.createExecutionBoundary({ store: trust, authCore, gateway, evidenceKeys, bankTrustKeys, providerCapabilities: capabilities, leaseMs, hooks });

  const approve = (device) => registry.approve(signStatement(approvalStatement({ nexusId: device.nexusId, credentialId: device.credentialId,
    signingKeySha256: signingKeyFingerprint(device.signingKey.publicKeyPem), reference: 'app' }), bankKey.privateKey));
  const revoke = (device) => registry.revoke(signStatement(revocationStatement({ nexusId: device.nexusId, credentialId: device.credentialId, reason: 'lost' }), bankKey.privateKey));
  const approvedDevice = async () => { const d = await bank.enrolDevice((await bank.createIdentity()).nexusId); await approve(d); return d; };

  /** CREATED in the bank, then the authorization at Auth Core (AWAITING_AUTHORIZATION), then the device confirms. */
  async function payment(device) {
    const paymentId = randomUUID();
    const transactionReference = `tx-${randomUUID()}`;
    const terms = { nexusId: device.nexusId, transactionReference, operationType: 'TRANSFER', amountMinor: '125000', currency: 'PLN', beneficiary: { name: 'Anna Nowak', iban: 'PL61109010140000071219812874' } };
    await store.createPayment({ paymentId, bankTransactionReference: `CORE-${paymentId.slice(0, 8)}`, terms });
    const auth = await bank.createAuthorization(device, { transactionReference });
    await store.attachAuthorization(paymentId, auth.authorizationId);
    const s = await deviceSignature(server, device, auth.authorizationId);
    assert.equal((await submitSignature(server, device, auth.authorizationId, s.signature)).json.status, 'VERIFIED');
    return { paymentId, authorizationId: auth.authorizationId, operationId: `CORE-${paymentId.slice(0, 8)}` };
  }
  const state = async (paymentId) => (await store.execution(paymentId))?.state;

  /** One HTTPS request to the gateway with a chosen client certificate (or none). */
  const rawGateway = (path, body, cert) => new Promise((resolve) => {
    const u = new URL(gatewayProc.url);
    const payload = body ? JSON.stringify(body) : undefined;
    const req = request({ hostname: u.hostname, port: u.port, path, method: body ? 'POST' : 'GET', ca: certs.ca, servername: 'localhost', ...(cert ?? {}),
      headers: payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {} }, (res) => {
      let t = ''; res.on('data', (d) => { t += d; }); res.on('end', () => resolve({ status: res.statusCode, text: t }));
    });
    req.on('error', (e) => resolve({ status: 0, error: e.message }));
    if (payload) req.write(payload);
    req.end();
  });

  test('the state machine: CREATED, AWAITING_AUTHORIZATION, CHECKING, APPROVED, SUBMITTED (by the gateway\'s role), EXECUTED', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const before = provider.totalExecutions();
    const r = await boundary().execute(p.paymentId);
    assert.equal(r.status, 'EXECUTED', JSON.stringify(r));
    assert.equal(provider.totalExecutions() - before, 1);
    const t = await store.transitions(p.paymentId);
    assert.deepEqual(t.map((x) => x.to), ['CHECKING', 'APPROVED', 'SUBMITTED', 'EXECUTED']);
    const actors = (await bankDb.owner.query(`SELECT to_state, actor FROM bank.execution_transitions WHERE payment_id = $1 ORDER BY id`, [p.paymentId])).rows;
    assert.equal(actors.find((a) => a.to_state === 'SUBMITTED').actor, bankDb.roles.gateway, 'only the gateway\'s role submitted');
    assert.equal(actors.find((a) => a.to_state === 'APPROVED').actor, bankDb.roles.boundary);
    assert.equal(actors.find((a) => a.to_state === 'EXECUTED').actor, bankDb.roles.gateway, 'the outcome is recorded by the gateway');
    // Auth Core's COMMITTED is what the bank reported after the provider confirmed, not proof of a transfer.
    assert.equal((await bank.call('GET', `/v1/authorizations/${p.authorizationId}/bank-transaction`)).json.bankTransactionState, 'COMMITTED');
    // A payment without its authorization cannot be executed.
    const lone = randomUUID();
    await store.createPayment({ paymentId: lone, bankTransactionReference: `CORE-${lone.slice(0, 8)}`, terms: (await store.payment(p.paymentId)).terms });
    assert.equal((await boundary().execute(lone)).status, 'NOT_AUTHORIZED');
  });

  test('forbidden transitions are refused by the database, for every role', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    assert.equal((await boundary().execute(p.paymentId)).status, 'EXECUTED');
    for (const to of ['CHECKING', 'APPROVED', 'SUBMITTED', 'OUTCOME_UNKNOWN', 'REVIEW', 'REFUSED']) {
      await assert.rejects(bankDb.owner.query(`UPDATE bank.executions SET state = $2 WHERE payment_id = $1`, [p.paymentId, to]), /not a permitted transition/, `EXECUTED -> ${to}`);
      for (const role of ['boundary', 'gateway', 'registry', 'operator']) {
        await assert.rejects(bankDb.pools[role].query(`UPDATE bank.executions SET state = $2 WHERE payment_id = $1`, [p.paymentId, to]), /permission denied/, `${role}: EXECUTED -> ${to}`);
      }
    }
    await assert.rejects(bankDb.owner.query(`DELETE FROM bank.executions WHERE payment_id = $1`, [p.paymentId]), /append-only/);
    await assert.rejects(bankDb.owner.query(`TRUNCATE bank.execution_transitions`), /append-only/);
    await assert.rejects(bankDb.owner.query(`UPDATE bank.payments SET terms = '{}' WHERE payment_id = $1`, [p.paymentId]), /immutable/);
  });

  test('the gateway refuses callers without the boundary\'s client certificate', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const before = provider.calls.length;
    const body = { paymentId: p.paymentId, attemptId: randomUUID() };
    assert.equal((await rawGateway('/v1/submit', body, undefined)).status, 0, 'no client certificate: TLS refuses');
    assert.equal((await rawGateway('/v1/submit', body, certs.rogue)).status, 0, 'certificate from another CA: TLS refuses');
    assert.equal((await rawGateway('/v1/submit', body, certs.otherService)).status, 403, 'bank CA, but not an allowed service');
    assert.equal((await rawGateway('/v1/submit', body, certs.boundary)).status, 409, 'allowed caller, nothing approved');
    assert.equal(provider.calls.length, before);
    assert.equal(await state(p.paymentId), undefined);
  });

  test('an approval is for one attempt and one order: another attempt, a replay, a changed amount get nothing', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const stop = barrier();
    let attemptId;
    const running = boundary({ hooks: { approved: async (c) => { attemptId = c.attemptId; await stop.wait(); } } }).execute(p.paymentId);
    await stop.atGate;
    const before = provider.calls.length;
    // The boundary's own role cannot submit, even for the approved attempt.
    await assert.rejects(bankDb.pools.boundary.query(`UPDATE bank.executions SET state = 'SUBMITTED' WHERE payment_id = $1`, [p.paymentId]), /permission denied/);
    await assert.rejects(bankDb.pools.boundary.query(`SELECT * FROM bank.submit($1, $2)`, [p.paymentId, attemptId]), /permission denied/);
    // Another instance, another attempt id: refused. The order in a request is ignored.
    assert.equal((await rawGateway('/v1/submit', { paymentId: p.paymentId, attemptId: randomUUID() }, certs.boundary)).status, 409);
    // The approved attempt, sent with a changed amount by whoever holds the client certificate:
    const sent = await rawGateway('/v1/submit', { paymentId: p.paymentId, attemptId, amountMinor: '1', beneficiary: { iban: 'XX00' } }, certs.boundary);
    assert.equal(sent.status, 200, sent.text);
    assert.equal(provider.calls.length, before + 1);
    assert.equal(provider.calls.at(-1).amountMinor, '125000', 'the stored order is sent, not the caller\'s');
    assert.equal(provider.calls.at(-1).beneficiary.iban, 'PL61109010140000071219812874');
    // The same approval again: refused (no longer APPROVED).
    assert.equal((await rawGateway('/v1/submit', { paymentId: p.paymentId, attemptId }, certs.boundary)).status, 409);
    stop.release();
    const r = await running;
    assert.notEqual(r.status, 'EXECUTED', 'the boundary\'s own submission was refused: the approval was used');
    assert.equal(provider.executions(p.operationId), 1, 'one transfer');
    // The approved order cannot be changed in the database either.
    await assert.rejects(bankDb.pools.boundary.query(`UPDATE bank.executions SET order_hash = $2 WHERE payment_id = $1`, [p.paymentId, 'a'.repeat(64)]), /permission denied/);
    await assert.rejects(bankDb.owner.query(`UPDATE bank.executions SET order_hash = $2 WHERE payment_id = $1`, [p.paymentId, 'a'.repeat(64)]), /not a permitted|immutable/);
  });

  test('an attempt still checking has no approval: its attempt id gets nothing from the gateway', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const stop = barrier();
    let attemptId;
    const running = boundary({ hooks: { beforeApprove: async (c) => { attemptId = c.attemptId; await stop.wait(); } } }).execute(p.paymentId);
    await stop.atGate;
    assert.equal(await state(p.paymentId), 'CHECKING');
    const before = provider.calls.length;
    assert.equal((await rawGateway('/v1/submit', { paymentId: p.paymentId, attemptId }, certs.boundary)).status, 409, 'CHECKING is not APPROVED');
    assert.equal(provider.calls.length, before);
    stop.release();
    assert.equal((await running).status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
    // Nor does a reconciling attempt's id: /v1/submit is only for APPROVED (a resubmission is the boundary's decision).
    const q = await payment(device);
    provider.modes.push('lose');
    assert.equal((await boundary().execute(q.paymentId)).status, 'OUTCOME_UNKNOWN');
    const hold = barrier();
    let reconciling;
    const running2 = boundary({ hooks: { reconciling: async (c) => { reconciling = c.attemptId; await hold.wait(); } } }).execute(q.paymentId);
    await hold.atGate;
    assert.equal(await state(q.paymentId), 'RECONCILING');
    const calls = provider.calls.length;
    assert.equal((await rawGateway('/v1/submit', { paymentId: q.paymentId, attemptId: reconciling }, certs.boundary)).status, 409);
    assert.equal(provider.calls.length, calls);
    hold.release();
    assert.equal((await running2).status, 'EXECUTED');
    assert.equal(provider.executions(q.operationId), 1);
  });

  test('terms changed in the database after the approval (by the owner, around the trigger): nothing sent, REVIEW', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const stop = barrier();
    const running = boundary({ hooks: { approved: () => stop.wait() } }).execute(p.paymentId);
    await stop.atGate;
    const c = await bankDb.owner.connect();
    try {
      await c.query('BEGIN'); await c.query('ALTER TABLE bank.payments DISABLE TRIGGER payments_lifecycle');
      await c.query(`UPDATE bank.payments SET terms = jsonb_set(terms, '{amountMinor}', '"990000"') WHERE payment_id = $1`, [p.paymentId]);
      await c.query('ALTER TABLE bank.payments ENABLE TRIGGER payments_lifecycle'); await c.query('COMMIT');
    } finally { c.release(); }
    const before = provider.calls.length;
    stop.release();
    const r = await running;
    assert.equal(r.status, 'REVIEW', JSON.stringify(r));
    assert.equal(provider.calls.length, before, 'the gateway compared the stored order with the approved hash and sent nothing');
  });

  test('while reconciling, the approved order hash cannot be changed; a mismatch would send nothing', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    provider.modes.push('drop'); // not received: the reconciliation will resubmit (idempotent contract)
    assert.equal((await boundary().execute(p.paymentId)).status, 'OUTCOME_UNKNOWN');
    let tamper; let ownerTamper;
    const r = await boundary({ hooks: { reconciling: async () => {
      tamper = await bankDb.pools.boundary.query(`UPDATE bank.executions SET order_hash = $2 WHERE payment_id = $1`, [p.paymentId, 'b'.repeat(64)]).then(() => 'changed', (e) => e.message);
      // Not the owner either, outside the functions.
      ownerTamper = await bankDb.owner.query(`UPDATE bank.executions SET order_hash = $2 WHERE payment_id = $1`, [p.paymentId, 'b'.repeat(64)]).then(() => 'changed', (e) => e.message);
    } } }).execute(p.paymentId);
    assert.match(tamper, /permission denied/);
    assert.match(ownerTamper, /not a permitted transition|approved order is immutable/);
    assert.equal(r.status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
    assert.equal(provider.calls.at(-1).amountMinor, '125000');
  });

  test('provider answers: pending then settled, failed, nonsense, lost, late', async () => {
    const device = await approvedDevice();
    // pending: PENDING_PROVIDER; the provider settles; the reconciliation job finds it.
    let p = await payment(device);
    provider.modes.push('pending');
    assert.equal((await boundary().execute(p.paymentId)).status, 'PENDING_PROVIDER');
    assert.equal((await boundary().execute(p.paymentId)).status, 'PENDING_PROVIDER', 'still pending: asked again, not sent again');
    provider.settle(p.operationId, 'succeeded');
    const due = await boundary().reconcileDue();
    assert.equal(due.find((d) => d.paymentId === p.paymentId)?.status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
    // failed: final, reported to Auth Core, never retried.
    p = await payment(device);
    provider.modes.push('fail');
    assert.equal((await boundary().execute(p.paymentId)).status, 'PROVIDER_FAILED');
    const calls = provider.calls.length;
    assert.equal((await boundary().execute(p.paymentId)).status, 'PROVIDER_FAILED');
    assert.equal(provider.calls.length, calls);
    assert.equal((await bank.call('GET', `/v1/authorizations/${p.authorizationId}/bank-transaction`)).json.bankTransactionState, 'FAILED');
    // nonsense: unknown, then the lookup settles it.
    p = await payment(device);
    provider.modes.push('garbage');
    assert.equal((await boundary().execute(p.paymentId)).status, 'OUTCOME_UNKNOWN');
    assert.equal((await boundary().execute(p.paymentId)).status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
    // lost: executed, answer lost; the lookup finds it.
    p = await payment(device);
    provider.modes.push('lose');
    assert.equal((await boundary().execute(p.paymentId)).status, 'OUTCOME_UNKNOWN');
    assert.equal((await boundary().execute(p.paymentId)).status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
    // late: the boundary stops waiting; the provider executes after; reconciled once.
    p = await payment(device);
    const slow = barrier();
    provider.beforeAnswer = () => slow.wait();
    const r = await boundary({ gateway: gatewayClient({ timeoutMs: 500 }) }).execute(p.paymentId);
    assert.equal(r.status, 'OUTCOME_UNKNOWN', JSON.stringify(r));
    provider.beforeAnswer = null; slow.release();
    await sleep(100);
    assert.equal((await boundary().execute(p.paymentId)).status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
  });

  test('the gateway process killed after the provider executed: unknown, reconciled after restart, one transfer', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    provider.beforeAnswer = async () => { provider.beforeAnswer = null; await gatewayProc.kill(); };
    const r = await boundary().execute(p.paymentId);
    assert.equal(r.status, 'OUTCOME_UNKNOWN', JSON.stringify(r));
    assert.equal(await state(p.paymentId), 'OUTCOME_UNKNOWN');
    assert.equal((await boundary().execute(p.paymentId)).status, 'OUTCOME_UNKNOWN', 'gateway down: still unknown, nothing sent');
    gatewayProc = await startGateway(providerHttp.url);
    assert.equal((await boundary().execute(p.paymentId)).status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
  });

  test('no answer and not found: without an idempotent submission or a lookup in the contract, a person decides', async () => {
    const device = await approvedDevice();
    // Not received by the provider; the contract says resubmission is not safe: REVIEW, nothing sent again.
    let p = await payment(device);
    provider.modes.push('drop');
    const noResubmit = { lookup: true, idempotentSubmit: false };
    assert.equal((await boundary({ capabilities: noResubmit }).execute(p.paymentId)).status, 'OUTCOME_UNKNOWN');
    const calls = provider.calls.length;
    const review = await boundary({ capabilities: noResubmit }).execute(p.paymentId);
    assert.equal(review.status, 'REVIEW', JSON.stringify(review));
    assert.equal(provider.calls.length, calls, 'not sent again');
    assert.equal((await boundary({ capabilities: noResubmit }).execute(p.paymentId)).status, 'REVIEW', 'stays for a person');
    await assert.rejects(operator.resolveReview(p.paymentId, 'succeeded'), /needs a note/);
    assert.equal(await operator.resolveReview(p.paymentId, 'failed', 'provider statement 2026-10-19: no such operation'), true);
    assert.equal(await state(p.paymentId), 'PROVIDER_FAILED');
    assert.equal((await store.execution(p.paymentId)).resolvedBy, bankDb.roles.operator, 'the operator\'s database login, not a name the caller gives');
    // The contract declares an idempotent submission: resubmitted with the same operation id, once.
    p = await payment(device);
    provider.modes.push('drop');
    assert.equal((await boundary().execute(p.paymentId)).status, 'OUTCOME_UNKNOWN');
    assert.equal((await boundary().execute(p.paymentId)).status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
    // No lookup in the contract: an unknown outcome goes to a person at once.
    p = await payment(device);
    provider.modes.push('lose');
    const lookups = provider.lookups.length;
    const noLookup = { lookup: false, idempotentSubmit: false };
    assert.equal((await boundary({ capabilities: noLookup }).execute(p.paymentId)).status, 'OUTCOME_UNKNOWN');
    assert.equal((await boundary({ capabilities: noLookup }).execute(p.paymentId)).status, 'REVIEW');
    assert.equal(provider.lookups.length, lookups);
    // Lookup unavailable: stays unknown until it works.
    p = await payment(device);
    provider.modes.push('lose');
    assert.equal((await boundary().execute(p.paymentId)).status, 'OUTCOME_UNKNOWN');
    provider.lookupMode = 'error';
    assert.equal((await boundary().execute(p.paymentId)).status, 'OUTCOME_UNKNOWN');
    provider.lookupMode = null;
    assert.equal((await boundary().execute(p.paymentId)).status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
  });

  test('a provider that is not idempotent: the boundary never resubmits when the contract does not allow it', async () => {
    const strict = providerDouble({ idempotent: false });
    const strictHttp = await providerServer(strict);
    const strictGateway = await startGateway(strictHttp.url);
    try {
      const device = await approvedDevice();
      const p = await payment(device);
      strict.modes.push('lose'); // executed, answer lost
      const b = () => boundary({ gateway: gatewayClient({ url: strictGateway.url }), capabilities: { lookup: true, idempotentSubmit: false } });
      assert.equal((await b().execute(p.paymentId)).status, 'OUTCOME_UNKNOWN');
      for (let i = 0; i < 3; i += 1) await b().execute(p.paymentId);
      assert.equal(strict.executions(p.operationId), 1, 'one transfer although the provider would execute a resubmission again');
      assert.equal(strict.calls.length, 1);
      assert.equal(await state(p.paymentId), 'EXECUTED');
    } finally { await strictGateway.stop(); await strictHttp.close(); }
  });

  test('local and provider disagree: recorded as a finding, the final state is not changed automatically', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    assert.equal((await boundary().execute(p.paymentId)).status, 'EXECUTED');
    assert.deepEqual(await boundary().audit(p.paymentId), { checked: true, agrees: true });
    provider.settle(p.operationId, 'failed'); // the provider later reverses or reports otherwise
    const audit = await boundary().audit(p.paymentId);
    assert.equal(audit.agrees, false);
    assert.equal(await state(p.paymentId), 'EXECUTED');
    assert.deepEqual((await store.findings(p.paymentId)).map((f) => [f.local_state, f.provider_status]), [['EXECUTED', 'failed']]);
  });

  test('revocation at each step, with barriers: refused before the approval, in flight after it', async () => {
    for (const step of ['checking', 'beforeApprove']) {
      const device = await approvedDevice();
      const p = await payment(device);
      const r = await boundary({ hooks: { [step]: async () => { await revoke(device); } } }).execute(p.paymentId);
      assert.equal(r.status, 'REFUSED', `${step}: ${JSON.stringify(r)}`);
      assert.equal(provider.executions(p.operationId), 0);
    }
    // After APPROVED (the cut-off) the revocation does not stop the payment; it reports it.
    const device = await approvedDevice();
    const p = await payment(device);
    let inFlight;
    const r = await boundary({ hooks: { approved: async () => { inFlight = await revoke(device); } } }).execute(p.paymentId);
    assert.equal(r.status, 'EXECUTED');
    assert.deepEqual(inFlight, [{ paymentId: p.paymentId, state: 'APPROVED' }]);
  });

  test('a crash at each transition: the next attempt finishes it, exactly one transfer', async () => {
    for (const step of ['checking', 'beforeApprove', 'approved', 'submitted']) {
      const device = await approvedDevice();
      const p = await payment(device);
      const crashed = await boundary({ leaseMs: 300, hooks: { [step]: () => { throw new lib.SimulatedCrash(step); } } }).execute(p.paymentId).catch((e) => e);
      assert.ok(crashed instanceof lib.SimulatedCrash, step);
      const left = await state(p.paymentId);
      // After the submission the gateway has recorded the provider's answer itself: a crash of the boundary loses nothing.
      assert.equal(left, { checking: 'CHECKING', beforeApprove: 'CHECKING', approved: 'APPROVED', submitted: 'EXECUTED' }[step], `${step}: state after the crash`);
      if (step !== 'submitted') assert.equal((await boundary().execute(p.paymentId)).status, 'IN_PROGRESS', `${step}: lease still running`);
      await sleep(400);
      const r = await boundary().execute(p.paymentId);
      assert.equal(r.status, 'EXECUTED', `${step}: ${JSON.stringify(r)}`);
      assert.equal(provider.executions(p.operationId), 1, `${step}: one transfer`);
    }
  });

  test('two instances, one held at the approval by a barrier: the other gets IN_PROGRESS; one transfer', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const stop = barrier();
    const first = boundary({ hooks: { approved: () => stop.wait() } }).execute(p.paymentId);
    await stop.atGate;
    assert.equal((await boundary().execute(p.paymentId)).status, 'IN_PROGRESS');
    stop.release();
    assert.equal((await first).status, 'EXECUTED');
    assert.equal(provider.executions(p.operationId), 1);
  });

  test('stress: 40 requests over 4 instances and a reconciliation job, with lost answers: one transfer per payment', async () => {
    const device = await approvedDevice();
    const ps = [await payment(device), await payment(device), await payment(device)];
    provider.modes.push('lose', 'succeed', 'lose');
    const instances = [boundary(), boundary(), boundary({ leaseMs: 1_000 }), boundary()];
    const jobs = [];
    for (let i = 0; i < 40; i += 1) jobs.push(instances[i % 4].execute(ps[i % 3].paymentId));
    jobs.push(instances[0].reconcileDue());
    await Promise.all(jobs);
    for (let round = 0; round < 5; round += 1) { await sleep(300); await instances[1].reconcileDue(); }
    for (const p of ps) {
      assert.equal(provider.executions(p.operationId), 1, p.paymentId);
      assert.equal(await state(p.paymentId), 'EXECUTED');
    }
  });

  test('repeated and forged webhooks only ask the boundary; one transfer', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const handle = lib.createAuthCoreWebhookHandler({ secret: webhookSecret, store, boundary: boundary() });
    const body = JSON.stringify({ eventId: randomUUID(), eventType: 'authorization.verified', authorizationId: p.authorizationId });
    const ts = String(Math.floor(Date.now() / 1000));
    const headers = { 'X-NEXUS-SIGN-Timestamp': ts, 'X-NEXUS-SIGN-Signature': `v1=${createHmac('sha256', webhookSecret).update(`${ts}.${body}`).digest('hex')}` };
    const results = await Promise.all(Array.from({ length: 5 }, () => handle({ headers, rawBody: body })));
    assert.ok(results.every((r) => r.status === 202));
    assert.equal(provider.executions(p.operationId), 1);
    assert.equal((await handle({ headers: { ...headers, 'X-NEXUS-SIGN-Signature': 'v1=00' }, rawBody: body })).status, 401);
    assert.equal((await handle({ headers, rawBody: body.replace('verified', 'expired') })).status, 401, 'body changed after signing');
    // A correctly signed webhook for a key the bank never approved changes nothing: the boundary decides.
    const attacker = { signingKey: newKey(), authKey: newKey(), offlineKey: newKey(), nexusId: device.nexusId };
    attacker.credentialId = (await asCompromisedAuthCore(server, { kind: 'enrol', nexusId: device.nexusId, clientId: client.clientId,
      signingPublicKeyPem: attacker.signingKey.publicKeyPem, authPublicKeyPem: attacker.authKey.publicKeyPem, offlinePublicKeyPem: attacker.offlineKey.publicKeyPem })).credentialId;
    const q = await payment(attacker);
    const forged = JSON.stringify({ eventId: randomUUID(), eventType: 'authorization.verified', authorizationId: q.authorizationId });
    const fh = { 'X-NEXUS-SIGN-Timestamp': ts, 'X-NEXUS-SIGN-Signature': `v1=${createHmac('sha256', webhookSecret).update(`${ts}.${forged}`).digest('hex')}` };
    const r = await handle({ headers: fh, rawBody: forged });
    assert.equal(r.result.status, 'REFUSED');
    assert.equal(provider.executions(q.operationId), 0);
  });

  test('device replaced while a payment is being checked: the old device\'s payment is refused', async () => {
    const device = await approvedDevice();
    const p = await payment(device);
    const replace = async () => {
      const next = await bank.enrolDevice(device.nexusId, { replacement: { method: 'BRANCH_VISIT', reference: 'R-14' } });
      await approve(next);
      await revoke(device);
    };
    const r = await boundary({ hooks: { beforeApprove: replace } }).execute(p.paymentId);
    assert.equal(r.status, 'REFUSED', JSON.stringify(r));
    assert.equal(provider.executions(p.operationId), 0);
  });

  test('chain head: a payment checked on an older chain finishes last; the kept head does not go back', async () => {
    const device = await approvedDevice();
    const a = await payment(device);
    const stop = barrier();
    const first = boundary({ hooks: { approved: () => stop.wait() } }).execute(a.paymentId);
    await stop.atGate;
    const c = await payment(device); // a newer record
    assert.equal((await boundary().execute(c.paymentId)).status, 'EXECUTED');
    const newer = await store.head(device.nexusId);
    stop.release();
    assert.equal((await first).status, 'EXECUTED');
    assert.deepEqual(await store.head(device.nexusId), newer);
    await assert.rejects(bankDb.pools.boundary.query(`UPDATE bank.chain_heads SET chain_sequence = 1 WHERE nexus_id = $1`, [device.nexusId]), /permission denied/);
    await assert.rejects(bankDb.owner.query(`UPDATE bank.chain_heads SET chain_sequence = 1 WHERE nexus_id = $1`, [device.nexusId]), /only moves forward/);
    assert.equal(await store.keepHead(device.nexusId, { chainSequence: 1, evidenceHash: newer.evidenceHash }), false, 'the function does not move it back either');
  });

  test('a compromised Auth Core: its answers, keys and events give it nothing', async () => {
    const device = await approvedDevice();
    // An approval cannot be brought back by replaying it after the revocation.
    const entry = signStatement(approvalStatement({ nexusId: device.nexusId, credentialId: device.credentialId, signingKeySha256: signingKeyFingerprint(device.signingKey.publicKeyPem), reference: 'replay' }), bankKey.privateKey);
    await revoke(device);
    await assert.rejects(registry.approve(entry), /revoked/);
    // Answers carrying keys, a registry or heads are not read as the bank's.
    const fresh = await approvedDevice();
    const p = await payment(fresh);
    const own = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const real = authCoreClient();
    const lying = { ...real, evidence: async (id) => ({ ...(await real.evidence(id)), evidencePublicKeys: { x: own.publicKey.export({ type: 'spki', format: 'pem' }).toString() }, registry: [entry], bankTrustKeys: ['x'], head: null }) };
    const errored = { ...real, evidence: async () => null };
    const r1 = await boundary({ authCore: errored }).execute(p.paymentId);
    assert.notEqual(r1.status, 'EXECUTED', 'an error in the check does not let it through');
    assert.equal(provider.executions(p.operationId), 0);
    // The extra fields change nothing: the same approved device's next payment executes once, checked with the pinned keys only.
    const q = await payment(fresh);
    const r2 = await boundary({ authCore: lying }).execute(q.paymentId);
    assert.equal(r2.status, 'EXECUTED', JSON.stringify(r2));
    assert.equal(provider.executions(q.operationId), 1);
    // And for a device the bank never approved, the forged approval inside the answer is not read.
    const stranger = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const u = await payment(stranger);
    const r3 = await boundary({ authCore: lying }).execute(u.paymentId);
    assert.equal(r3.status, 'REFUSED', JSON.stringify(r3));
    // Auth Core holds no client certificate for the gateway: its requests do not get through TLS.
    assert.equal((await rawGateway('/v1/submit', { paymentId: p.paymentId, attemptId: randomUUID() }, undefined)).status, 0);
  });
});
