// the bank database's authorization. Every application role gets
// only EXECUTE on its own functions and SELECT where it must read; every state
// change, every trust change and every log row is made by a SECURITY DEFINER
// function of the schema owner, with a fixed search_path and qualified names.
// Reproduced on 3cbea86: the boundary role approved a
// payment with a direct UPDATE (any credential, any order hash) and the
// gateway sent it; it inserted any row into the transition log; it wrote an
// APPROVED trust row without a statement (p15/repro/repro-3cbea86.log).
//
// Each negative case checks the SQL error, that the payment's state did not
// change, and that the provider was not called. The confirmation evidence is
// a synthetic fixture (support/syntheticEvidence.mjs), not Auth Core output.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import pg from 'pg';
import { skipWithoutServices } from './support/harness.mjs';
import { bankDatabase, providerDouble } from './support/bankSide.mjs';
import { evidenceMaker } from './support/syntheticEvidence.mjs';
import { approvalStatement, revocationStatement, signStatement } from '../../scripts/lib/bankTrust.mjs';

const integration = () => import('../../../bank-integration/index.mjs');

describe('bank database authorization (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let lib; let db; let store; let registry; let operator;
  const maker = evidenceMaker();
  const { evidenceKeys } = maker;
  const bankKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const bankTrustKeys = [bankKey.publicKey.export({ type: 'spki', format: 'pem' }).toString()];
  const nexus = () => String(100000000 + Math.floor(Math.random() * 899999999));

  before(async () => {
    lib = await integration();
    db = await bankDatabase(lib, { bankTrustKeys });
    store = lib.createTrustStore(db.pools.boundary);
    registry = lib.createRegistry(db.pools.registry, { bankTrustKeys });
    operator = lib.createOperatorTools(db.pools.operator);
  });
  after(async () => { await db?.drop(); });

  const approveDevice = (device, nexusId = device.nexusId) => registry.approve(signStatement(approvalStatement({ nexusId, credentialId: device.credentialId, signingKeySha256: device.fingerprint, reference: 'app' }), bankKey.privateKey));
  const revocation = (credentialId, nexusId) => signStatement(revocationStatement({ nexusId, credentialId, reason: 'lost' }), bankKey.privateKey);
  const revokeCredential = (credentialId, nexusId) => registry.revoke(revocation(credentialId, nexusId));

  /** A payment awaiting execution, its customer's approved device, the device's confirmation, and a claim. */
  async function claimed({ leaseMs = 30_000 } = {}) {
    const nexusId = nexus(); const paymentId = randomUUID(); const authorizationId = randomUUID();
    const device = maker.device(nexusId);
    await approveDevice(device);
    const terms = { nexusId, transactionReference: `tx-${paymentId.slice(0, 6)}`, operationType: 'TRANSFER', amountMinor: '125000', currency: 'PLN', beneficiary: { name: 'Anna Nowak', iban: 'PL61109010140000071219812874' } };
    await store.createPayment({ paymentId, bankTransactionReference: `CORE-${paymentId.slice(0, 8)}`, terms });
    await store.attachAuthorization(paymentId, authorizationId);
    const claim = await store.claim(paymentId, leaseMs);
    assert.equal(claim.outcome, 'CHECKING');
    const evidence = maker.confirm(device, { authorizationId, terms });
    return { paymentId, nexusId, credentialId: device.credentialId, attemptId: claim.attemptId, device, evidence, terms, authorizationId };
  }
  const state = async (paymentId) => (await store.execution(paymentId)).state;
  const gatewayWith = (provider = providerDouble()) => ({ provider, gateway: lib.createPaymentGateway({ pool: db.pools.gateway, provider, evidenceKeys, bankTrustKeys }) });

  test('the boundary role cannot approve, or change an approval, with SQL: only through bank.approve', async () => {
    const p = await claimed();
    for (const sql of [
      [`UPDATE bank.executions SET state = 'APPROVED', lease_until = now() + interval '1 minute' WHERE payment_id = $1`, [p.paymentId]],
      [`UPDATE bank.executions SET credential_id = $2 WHERE payment_id = $1`, [p.paymentId, randomUUID()]],
      [`UPDATE bank.executions SET order_hash = $2 WHERE payment_id = $1`, [p.paymentId, 'b'.repeat(64)]],
      [`INSERT INTO bank.executions (payment_id, state, attempt_id) VALUES ($1, 'APPROVED', $2)`, [randomUUID(), randomUUID()]],
      [`DELETE FROM bank.executions WHERE payment_id = $1`, [p.paymentId]],
      [`INSERT INTO bank.credential_trust (credential_id, nexus_id, state) VALUES ($1, $2, 'APPROVED')`, [randomUUID(), p.nexusId]],
      [`UPDATE bank.payments SET terms = '{}'::jsonb WHERE payment_id = $1`, [p.paymentId]],
      [`INSERT INTO bank.trust_statements (credential_id, nexus_id, type, entry) VALUES ($1, $2, 'NEXUS_CREDENTIAL_APPROVAL', '{}')`, [randomUUID(), p.nexusId]],
    ]) {
      await assert.rejects(db.pools.boundary.query(...sql), /permission denied/, sql[0]);
    }
    assert.equal(await state(p.paymentId), 'CHECKING');
    const { provider, gateway } = gatewayWith();
    await assert.rejects(gateway.submit(p.paymentId, p.attemptId), lib.GatewayRefusedError);
    assert.equal(provider.calls.length, 0);
    assert.equal(await state(p.paymentId), 'CHECKING');
  });

  test('the transition log: only real transitions, by the role that made them; no forged, changed or deleted rows', async () => {
    const p = await claimed();
    for (const pool of [db.pools.boundary, db.pools.gateway, db.pools.registry, db.pools.operator]) {
      await assert.rejects(pool.query(`INSERT INTO bank.execution_transitions (payment_id, from_state, to_state, attempt_id, actor, via) VALUES ($1, 'SUBMITTED', 'EXECUTED', $2, 'x', 'report')`, [p.paymentId, p.attemptId]), /permission denied/);
      await assert.rejects(pool.query(`UPDATE bank.execution_transitions SET actor = 'x' WHERE payment_id = $1`, [p.paymentId]), /permission denied/);
      await assert.rejects(pool.query(`DELETE FROM bank.execution_transitions WHERE payment_id = $1`, [p.paymentId]), /permission denied/);
    }
    // Not even the owner changes or removes rows (the trigger), and the sequence is not usable by any role.
    await assert.rejects(db.owner.query(`UPDATE bank.execution_transitions SET actor = 'x' WHERE payment_id = $1`, [p.paymentId]), /append-only/);
    await assert.rejects(db.owner.query(`DELETE FROM bank.execution_transitions WHERE payment_id = $1`, [p.paymentId]), /append-only/);
    const { provider, gateway } = gatewayWith();
    assert.equal((await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000)).ok, true);
    assert.equal((await gateway.submit(p.paymentId, p.attemptId)).outcome, 'succeeded');
    assert.equal(provider.calls.length, 1);
    const log = await store.transitions(p.paymentId);
    assert.deepEqual(log.map((t) => [t.from, t.to, t.via, t.actor]), [
      [null, 'CHECKING', 'claim', db.roles.boundary],
      ['CHECKING', 'APPROVED', 'approve', db.roles.boundary],
      ['APPROVED', 'SUBMITTED', 'submit', db.roles.gateway],
      ['SUBMITTED', 'EXECUTED', 'report', db.roles.gateway],
    ]);
    assert.ok(log.every((t) => t.attemptId === p.attemptId));
    // A direct update by the owner, outside the functions, is not a permitted transition either.
    await assert.rejects(db.owner.query(`UPDATE bank.executions SET state = 'REVIEW' WHERE payment_id = $1`, [p.paymentId]), /not a permitted transition/);
  });

  test('the owner\'s own SQL: no approval without bank.approve; an announcement covers one row; an approved order stays as approved', async () => {
    const p = await claimed();
    await assert.rejects(db.owner.query(`UPDATE bank.executions SET state = 'APPROVED' WHERE payment_id = $1`, [p.paymentId]), /not a permitted transition/);
    // After a function's change, the same transaction cannot ride on its announcement.
    const c = await db.owner.connect();
    try {
      await c.query('BEGIN');
      await c.query(`SELECT * FROM bank.claim($1, 30000)`, [p.paymentId]).catch(() => undefined);
      const q = await claimed();
      await c.query(`SELECT bank.via('claim')`);
      await c.query(`UPDATE bank.executions SET state = 'CHECKING', attempt_id = $2 WHERE payment_id = $1`, [q.paymentId, randomUUID()]);
      await assert.rejects(c.query(`UPDATE bank.executions SET state = 'CHECKING', attempt_id = $2 WHERE payment_id = $1`, [q.paymentId, randomUUID()]), /not a permitted transition/);
      await c.query('ROLLBACK');
    } finally { c.release(); }
    // bank.via is a label, not an authority: whoever can UPDATE the table (only the owner) can announce a function,
    // and the trigger still keeps the approved order, credential and evidence.
    assert.equal((await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000)).ok, true);
    const d = await db.owner.connect();
    try {
      await d.query('BEGIN');
      await d.query(`SELECT set_config('bank.via', 'hold', true)`);
      await assert.rejects(d.query(`UPDATE bank.executions SET state = 'HELD', order_hash = $2 WHERE payment_id = $1`, [p.paymentId, 'b'.repeat(64)]), /approved order is immutable/);
      await d.query('ROLLBACK');
    } finally { d.release(); }
    assert.equal(await state(p.paymentId), 'APPROVED');
  });

  test('the gateway role\'s functions check for themselves, without the gateway\'s own check before them', async () => {
    const p = await claimed();
    const gw = db.pools.gateway;
    // Still CHECKING; an attempt that holds nothing; a lookup before any submission.
    await assert.rejects(gw.query(`SELECT * FROM bank.submit($1, $2)`, [p.paymentId, p.attemptId]), /nothing is approved for this attempt/);
    assert.equal((await gw.query(`SELECT bank.report($1, $2, 'succeeded', 'PAY-x', null) AS ok`, [p.paymentId, p.attemptId])).rows[0].ok, false);
    assert.equal((await gw.query(`SELECT bank.operation_for_lookup($1) AS id`, [p.paymentId])).rows[0].id, null);
    assert.equal((await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000)).ok, true);
    await assert.rejects(gw.query(`SELECT * FROM bank.submit($1, $2)`, [p.paymentId, randomUUID()]), /nothing is approved for this attempt/);
    await assert.rejects(gw.query(`SELECT * FROM bank.resubmit($1, $2)`, [p.paymentId, p.attemptId]), /no reconciliation by this attempt/);
    // The reference (the provider's operation id) changed after the approval by the owner: the order is not the approved one.
    const c = await db.owner.connect();
    try {
      await c.query('BEGIN'); await c.query('ALTER TABLE bank.payments DISABLE TRIGGER payments_lifecycle');
      await c.query(`UPDATE bank.payments SET bank_transaction_reference = bank_transaction_reference || '-X' WHERE payment_id = $1`, [p.paymentId]);
      await assert.rejects(c.query(`SELECT * FROM bank.submit($1, $2)`, [p.paymentId, p.attemptId]), /not the approved order/);
      await c.query('ROLLBACK');
    } finally { c.release(); }
    // The right attempt: once.
    const sent = (await gw.query(`SELECT * FROM bank.submit($1, $2)`, [p.paymentId, p.attemptId])).rows[0];
    assert.equal(sent.payment_order.amountMinor, '125000');
    await assert.rejects(gw.query(`SELECT * FROM bank.submit($1, $2)`, [p.paymentId, p.attemptId]), /nothing is approved for this attempt/);
    assert.equal((await gw.query(`SELECT bank.report($1, $2, 'succeeded', 'PAY-x', null) AS ok`, [p.paymentId, randomUUID()])).rows[0].ok, false, 'another attempt');
    assert.equal((await gw.query(`SELECT bank.report($1, $2, 'succeeded', 'PAY-x', null) AS ok`, [p.paymentId, p.attemptId])).rows[0].ok, true);
    assert.equal((await gw.query(`SELECT bank.report($1, $2, 'failed', null, null) AS ok`, [p.paymentId, p.attemptId])).rows[0].ok, false, 'a final state stays');
    assert.equal(await state(p.paymentId), 'EXECUTED');
  });

  test('bank.approve checks the attempt, the lease, the registry, the revocation and the customer; it binds the order itself', async () => {
    const { provider, gateway } = gatewayWith();
    // Lease expired.
    let p = await claimed({ leaseMs: 200 });
    await new Promise((r) => setTimeout(r, 300));
    assert.deepEqual(await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000), { ok: false, lost: true, reason: 'the claim was lost (lease expired or taken over)' });
    assert.equal(await state(p.paymentId), 'CHECKING');
    // Revoked credential.
    p = await claimed();
    await revokeCredential(p.credentialId, p.nexusId);
    let r = await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000);
    assert.equal(r.ok, false); assert.match(r.reason, /revoked/);
    // A credential approved for another customer, and one never approved.
    p = await claimed();
    const elsewhere = maker.device(nexus());
    await approveDevice(elsewhere);
    const asThisCustomer = { ...elsewhere, nexusId: p.nexusId };
    r = await store.approveExecution(p.paymentId, p.attemptId, maker.confirm(asThisCustomer, { authorizationId: p.authorizationId, terms: p.terms }), 30_000);
    assert.equal(r.ok, false); assert.match(r.reason, /another customer/);
    r = await store.approveExecution(p.paymentId, p.attemptId, maker.confirm(maker.device(p.nexusId), { authorizationId: p.authorizationId, terms: p.terms }), 30_000);
    assert.equal(r.ok, false); assert.match(r.reason, /not in the bank's registry/);
    // A trust row written without a statement (only the owner can): not an approval.
    const bare = maker.device(p.nexusId);
    await db.owner.query(`INSERT INTO bank.credential_trust (credential_id, nexus_id, state) VALUES ($1, $2, 'APPROVED')`, [bare.credentialId, p.nexusId]);
    r = await store.approveExecution(p.paymentId, p.attemptId, maker.confirm(bare, { authorizationId: p.authorizationId, terms: p.terms }), 30_000);
    assert.equal(r.ok, false); assert.match(r.reason, /no stored approval statement/);
    // Evidence for other terms, another authorization or another customer; no evidence.
    for (const [evidence, why] of [
      [maker.confirm(p.device, { authorizationId: p.authorizationId, terms: p.terms, signedOverride: { amount_minor: '990000' } }), /signed terms/],
      [maker.confirm(p.device, { authorizationId: randomUUID(), terms: p.terms }), /another authorization/],
      [maker.confirm(maker.device(nexus()), { authorizationId: p.authorizationId, terms: p.terms }), /another customer/],
      [null, /not a schema 3 AUTHORIZATION/],
      [{ ...p.evidence, sealedPayload: { ...p.evidence.sealedPayload, canonicalPayloadHash: 'c'.repeat(64) } }, /canonicalPayloadHash/],
    ]) {
      r = await store.approveExecution(p.paymentId, p.attemptId, evidence, 30_000);
      assert.equal(r.ok, false); assert.match(r.reason, why);
    }
    assert.equal(await state(p.paymentId), 'CHECKING');
    // An old attempt after the claim was taken over; a second approval of the same attempt.
    p = await claimed({ leaseMs: 200 });
    await new Promise((x) => setTimeout(x, 300));
    const again = await store.claim(p.paymentId, 30_000);
    assert.equal(again.outcome, 'CHECKING');
    assert.equal((await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000)).lost, true, 'the old attempt');
    assert.equal((await store.approveExecution(p.paymentId, again.attemptId, p.evidence, 30_000)).ok, true);
    assert.equal((await store.approveExecution(p.paymentId, again.attemptId, p.evidence, 30_000)).ok, false, 'no second approval');
    // A lease longer than the bank allows is refused.
    const q = await claimed();
    await assert.rejects(store.approveExecution(q.paymentId, q.attemptId, q.evidence, 86_400_000), /lease/);
    // The order hash is computed by the database from the stored terms.
    const hash = (await db.owner.query(`SELECT order_hash FROM bank.executions WHERE payment_id = $1`, [p.paymentId])).rows[0].order_hash;
    const expected = (await db.owner.query(`SELECT bank.order_hash(bank.order_document($1)) AS h`, [p.paymentId])).rows[0].h;
    assert.equal(hash, expected);
    // Only the approved attempt's order is sent, once.
    assert.equal((await gateway.submit(p.paymentId, p.attemptId).catch((e) => e)) instanceof lib.GatewayRefusedError, true, 'old attempt');
    assert.equal((await gateway.submit(p.paymentId, again.attemptId)).outcome, 'succeeded');
    await assert.rejects(gateway.submit(p.paymentId, again.attemptId), lib.GatewayRefusedError, 'once');
    assert.equal(provider.calls.length, 1);
  });

  test('an approval on evidence the boundary forged: the database cannot check signatures, the gateway does, and sends nothing', async () => {
    const p = await claimed();
    // The boundary's role holder makes evidence for the customer's approved credential without the device:
    // right shape, right terms, signature by another key.
    const impostor = maker.device(p.nexusId);
    const forged = maker.confirm({ ...impostor, credentialId: p.credentialId, enrolment: p.device.enrolment }, { authorizationId: p.authorizationId, terms: p.terms });
    assert.equal((await store.approveExecution(p.paymentId, p.attemptId, forged, 30_000)).ok, true, 'the database binds, it does not verify signatures');
    const { provider, gateway } = gatewayWith();
    const answer = await gateway.submit(p.paymentId, p.attemptId);
    assert.equal(answer.outcome, 'review');
    assert.match(answer.reason, /gateway's check of the approval failed/);
    assert.equal(provider.calls.length, 0);
    assert.equal(await state(p.paymentId), 'REVIEW');
    assert.deepEqual((await store.transitions(p.paymentId)).map((t) => [t.to, t.via]), [['CHECKING', 'claim'], ['APPROVED', 'approve'], ['REVIEW', 'gateway_refuse']]);
    // A statement the registry role stored without the bank's signature does not count at the gateway either.
    const q = await claimed();
    const unsigned = maker.device(q.nexusId);
    await db.pools.registry.query(`SELECT bank.approve_credential($1, NULL, NULL)`, [JSON.stringify({ statement: { ...approvalStatement({ nexusId: q.nexusId, credentialId: unsigned.credentialId, signingKeySha256: unsigned.fingerprint, reference: 'x' }), bankKeyId: 'd'.repeat(64) }, signature: 'AAAA' })]);
    const evidence = maker.confirm(unsigned, { authorizationId: q.authorizationId, terms: q.terms });
    assert.equal((await store.approveExecution(q.paymentId, q.attemptId, evidence, 30_000)).ok, true);
    const second = gatewayWith();
    assert.equal((await second.gateway.submit(q.paymentId, q.attemptId)).outcome, 'review');
    assert.equal(second.provider.calls.length, 0);
  });

  test('terms changed after the approval (owner, trigger disabled): the gateway sends nothing, REVIEW', async () => {
    const p = await claimed();
    assert.equal((await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000)).ok, true);
    const c = await db.owner.connect();
    try {
      await c.query('BEGIN'); await c.query('ALTER TABLE bank.payments DISABLE TRIGGER payments_lifecycle');
      await c.query(`UPDATE bank.payments SET terms = jsonb_set(terms, '{amountMinor}', '"990000"') WHERE payment_id = $1`, [p.paymentId]);
      await c.query('ALTER TABLE bank.payments ENABLE TRIGGER payments_lifecycle'); await c.query('COMMIT');
    } finally { c.release(); }
    const { provider, gateway } = gatewayWith();
    assert.equal((await gateway.submit(p.paymentId, p.attemptId)).outcome, 'review');
    assert.equal(provider.calls.length, 0);
    assert.equal(await state(p.paymentId), 'REVIEW');
    // The reference (the provider's operation id) changed: not part of what the customer signed, but of the approved order.
    const q = await claimed();
    assert.equal((await store.approveExecution(q.paymentId, q.attemptId, q.evidence, 30_000)).ok, true);
    const d = await db.owner.connect();
    try {
      await d.query('BEGIN'); await d.query('ALTER TABLE bank.payments DISABLE TRIGGER payments_lifecycle');
      await d.query(`UPDATE bank.payments SET bank_transaction_reference = bank_transaction_reference || '-X' WHERE payment_id = $1`, [q.paymentId]);
      await d.query('ALTER TABLE bank.payments ENABLE TRIGGER payments_lifecycle'); await d.query('COMMIT');
    } finally { d.release(); }
    const answer = await gateway.submit(q.paymentId, q.attemptId);
    assert.equal(answer.outcome, 'review');
    assert.match(answer.reason, /approved order hash/);
    assert.equal(provider.calls.length, 0);
  });

  test('revocation and approval are serialized on the credential\'s trust row', async () => {
    // A revocation in progress holds the approval until it commits: then refused.
    let p = await claimed();
    const revoker = await db.pools.registry.connect();
    try {
      await revoker.query('BEGIN');
      await revoker.query(`SELECT * FROM bank.revoke_credential($1::jsonb)`, [JSON.stringify(revocation(p.credentialId, p.nexusId))]);
      let settled = false;
      const approving = store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000).then((r) => { settled = true; return r; });
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(settled, false, 'the approval waits for the revocation');
      await revoker.query('COMMIT');
      const r = await approving;
      assert.equal(r.ok, false); assert.match(r.reason, /revoked/);
    } finally { revoker.release(); }
    // An approval in progress holds the revocation: then it is reported in flight.
    p = await claimed();
    const approver = await db.pools.boundary.connect();
    try {
      await approver.query('BEGIN');
      const a = (await approver.query(`SELECT * FROM bank.approve($1, $2, $3, $4)`, [p.paymentId, p.attemptId, JSON.stringify(p.evidence), 30_000])).rows[0];
      assert.equal(a.ok, true);
      let settled = false;
      const revoking = revokeCredential(p.credentialId, p.nexusId).then((r) => { settled = true; return r; });
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(settled, false, 'the revocation waits for the approval');
      await approver.query('COMMIT');
      assert.deepEqual(await revoking, [{ paymentId: p.paymentId, state: 'APPROVED' }]);
    } finally { approver.release(); }
    // The cut-off is the approval: the gateway checks it against the registry as it stood then, and sends it.
    const { provider, gateway } = gatewayWith();
    assert.equal((await gateway.submit(p.paymentId, p.attemptId)).outcome, 'succeeded');
    assert.equal(provider.calls.length, 1);
  });

  test('an approval inside a transaction that is rolled back, or whose connection dies, leaves nothing', async () => {
    const p = await claimed();
    const c = await db.pools.boundary.connect();
    try {
      await c.query('BEGIN');
      assert.equal((await c.query(`SELECT * FROM bank.approve($1, $2, $3, $4)`, [p.paymentId, p.attemptId, JSON.stringify(p.evidence), 30_000])).rows[0].ok, true);
      await c.query('ROLLBACK');
    } finally { c.release(); }
    assert.equal(await state(p.paymentId), 'CHECKING');
    assert.deepEqual((await store.transitions(p.paymentId)).map((t) => t.to), ['CHECKING']);
    const dying = new pg.Client({ connectionString: db.urls.boundary });
    await dying.connect();
    await dying.query('BEGIN');
    await dying.query(`SELECT * FROM bank.approve($1, $2, $3, $4)`, [p.paymentId, p.attemptId, JSON.stringify(p.evidence), 30_000]);
    await dying.end(); // connection closed inside the transaction
    assert.equal(await state(p.paymentId), 'CHECKING');
    // The sanctioned path still works afterwards.
    assert.equal((await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000)).ok, true);
  });

  test('outcomes come from the gateway only: the boundary cannot record EXECUTED or a provider answer', async () => {
    const p = await claimed();
    assert.equal((await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000)).ok, true);
    await assert.rejects(db.pools.boundary.query(`SELECT bank.report($1, $2, 'succeeded', 'PAY-x', null)`, [p.paymentId, p.attemptId]), /permission denied/);
    await assert.rejects(db.pools.boundary.query(`SELECT * FROM bank.submit($1, $2)`, [p.paymentId, p.attemptId]), /permission denied/);
    assert.equal(await state(p.paymentId), 'APPROVED');
    // The gateway cannot decide anything.
    for (const sql of [`SELECT * FROM bank.claim($1, 1000)`, `SELECT * FROM bank.approve($1, $1, '{}'::jsonb, 1000)`, `SELECT * FROM bank.payments`, `SELECT * FROM bank.approve_credential('{}')`, `SELECT bank.resolve_review($1, 'succeeded', 'x')`]) {
      await assert.rejects(db.pools.gateway.query(sql, sql.includes('$1') ? [p.paymentId] : []), /permission denied/, sql);
    }
    // The registry and the operator touch neither executions nor payments.
    await assert.rejects(db.pools.registry.query(`SELECT * FROM bank.approve($1, $1, '{}'::jsonb, 1000)`, [p.paymentId]), /permission denied/);
    await assert.rejects(db.pools.operator.query(`SELECT * FROM bank.approve($1, $1, '{}'::jsonb, 1000)`, [p.paymentId]), /permission denied/);
    await assert.rejects(db.pools.operator.query(`SELECT * FROM bank.approve_credential('{}')`), /permission denied/);
  });

  test('a person settles a REVIEW under their own database identity', async () => {
    const p = await claimed();
    assert.equal((await store.approveExecution(p.paymentId, p.attemptId, p.evidence, 30_000)).ok, true);
    const provider = providerDouble(); provider.modes.push('drop');
    const { gateway } = gatewayWith(provider);
    assert.equal((await gateway.submit(p.paymentId, p.attemptId)).outcome, 'unknown');
    const rec = await store.claim(p.paymentId, 30_000);
    assert.equal(rec.outcome, 'RECONCILE');
    assert.equal(await store.markReview(p.paymentId, rec.attemptId, 'not found; not idempotent'), true);
    await assert.rejects(db.pools.boundary.query(`SELECT bank.resolve_review($1, 'succeeded', 'n')`, [p.paymentId]), /permission denied/);
    assert.equal(await operator.resolveReview(p.paymentId, 'failed', 'provider statement: no such operation'), true);
    assert.equal(await state(p.paymentId), 'PROVIDER_FAILED');
    const row = (await db.owner.query(`SELECT resolved_by FROM bank.executions WHERE payment_id = $1`, [p.paymentId])).rows[0];
    assert.equal(row.resolved_by, db.roles.operator, 'the database records who it was, not what the caller says');
  });

  test('a role that inherits the boundary role gets its functions and nothing more; nobody inherits the owner', async () => {
    const p = await claimed();
    const member = new pg.Client({ connectionString: db.urls.member });
    await member.connect();
    try {
      await assert.rejects(member.query(`UPDATE bank.executions SET state = 'APPROVED' WHERE payment_id = $1`, [p.paymentId]), /permission denied/);
      await assert.rejects(member.query(`SET ROLE ${db.ownerRole}`), /permission denied|must be able to SET ROLE/);
      await assert.rejects(member.query(`SET ROLE ${db.roles.gateway}`), /permission denied|must be able to SET ROLE/);
      const r = (await member.query(`SELECT * FROM bank.approve($1, $2, $3, $4)`, [p.paymentId, p.attemptId, JSON.stringify(p.evidence), 30_000])).rows[0];
      assert.equal(r.ok, true, 'the sanctioned function, with all its checks');
    } finally { await member.end(); }
    const owners = (await db.owner.query(`SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member WHERE m.roleid = (SELECT oid FROM pg_roles WHERE rolname = current_user)`)).rows;
    assert.deepEqual(owners, [], 'no role is a member of the owner');
  });

  test('no object can be put in the functions\' way', async () => {
    const p = await claimed();
    for (const sql of [
      `CREATE TABLE bank.executions_shadow (x int)`,
      `CREATE FUNCTION bank.now() RETURNS timestamptz LANGUAGE sql AS 'SELECT ''2000-01-01''::timestamptz'`,
      `CREATE TABLE public.executions (x int)`,
      `CREATE FUNCTION public.sha256(bytea) RETURNS bytea LANGUAGE sql AS 'SELECT ''\\x00''::bytea'`,
    ]) await assert.rejects(db.pools.boundary.query(sql), /permission denied/, sql);
    await assert.rejects(db.pools.boundary.query(`CREATE TEMP TABLE executions (state text)`), /permission denied/, 'no temporary objects either');
    // Every SECURITY DEFINER function: owned by the owner, search_path fixed, not executable by PUBLIC.
    const fns = (await db.owner.query(`SELECT p.proname, pg_get_userbyid(p.proowner) AS owner, p.proconfig, p.prosecdef,
        has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'bank'`)).rows;
    const definers = fns.filter((f) => f.prosecdef);
    assert.ok(definers.length >= 15, `definer functions: ${definers.map((f) => f.proname)}`);
    for (const f of definers) {
      assert.equal(f.owner, db.ownerRole, f.proname);
      assert.deepEqual(f.proconfig, ['search_path=pg_catalog, pg_temp'], f.proname);
    }
    for (const f of fns) assert.equal(f.public_exec, false, `${f.proname} executable by PUBLIC`);
    assert.equal(await state(p.paymentId), 'CHECKING');
  });

  test('the privilege matrix is exactly the intended one, also after the schema is installed again', async () => {
    const before = await lib.privilegeMatrix(db.owner, db.roles);
    assert.deepEqual(before, lib.intendedPrivileges(db.roles));
    // An earlier version granted more: a reinstall removes it.
    await db.owner.query(`GRANT UPDATE, INSERT ON bank.executions TO ${db.roles.boundary}`);
    await db.owner.query(`GRANT USAGE ON ALL SEQUENCES IN SCHEMA bank TO ${db.roles.boundary}`);
    await db.owner.query(`GRANT EXECUTE ON FUNCTION bank.submit(uuid, uuid) TO ${db.roles.boundary}`);
    await db.owner.query(`GRANT EXECUTE ON FUNCTION bank.report(uuid, uuid, text, text, text) TO PUBLIC`);
    await lib.installSchema(db.owner, db.roles, { bankTrustKeys });
    assert.equal((await db.owner.query(`SELECT has_function_privilege('public', 'bank.report(uuid,uuid,text,text,text)', 'EXECUTE') AS x`)).rows[0].x, false);
    assert.deepEqual(await lib.privilegeMatrix(db.owner, db.roles), lib.intendedPrivileges(db.roles));
    // The phase 14 tables in public, with their grants, if a bank upgrades in place: no grant survives.
    await db.adminQuery(`CREATE TABLE public.bank_executions (payment_id uuid); ALTER TABLE public.bank_executions OWNER TO ${db.ownerRole};
      GRANT SELECT, INSERT, UPDATE ON public.bank_executions TO ${db.roles.boundary}`);
    assert.equal((await db.owner.query(`SELECT has_table_privilege($1, 'public.bank_executions', 'UPDATE') AS x`, [db.roles.boundary])).rows[0].x, true);
    await lib.installSchema(db.owner, db.roles, { bankTrustKeys });
    for (const priv of ['SELECT', 'INSERT', 'UPDATE']) {
      assert.equal((await db.owner.query(`SELECT has_table_privilege($1, 'public.bank_executions', $2) AS x`, [db.roles.boundary, priv])).rows[0].x, false, priv);
    }
    await db.adminQuery(`DROP TABLE public.bank_executions`);
    // A table or function added later by the owner is not granted to anyone.
    await db.owner.query(`CREATE TABLE bank.later (x int)`);
    await db.owner.query(`CREATE FUNCTION bank.later_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'`);
    for (const role of Object.values(db.roles)) {
      assert.equal((await db.owner.query(`SELECT has_table_privilege($1, 'bank.later', 'SELECT') AS x`, [role])).rows[0].x, false, role);
      assert.equal((await db.owner.query(`SELECT has_function_privilege($1, 'bank.later_fn()', 'EXECUTE') AS x`, [role])).rows[0].x, false, role);
    }
    await db.owner.query(`DROP TABLE bank.later; DROP FUNCTION bank.later_fn()`);
    // The installer refuses a role that is a superuser or a member of the owner.
    const insider = `${db.roles.boundary}_insider`;
    await db.adminQuery(`CREATE ROLE ${insider} NOLOGIN; GRANT ${db.ownerRole} TO ${insider}`);
    try {
      await assert.rejects(lib.installSchema(db.owner, { ...db.roles, boundary: insider }), /member of the schema owner/);
      await assert.rejects(lib.installSchema(db.owner, { ...db.roles, operator: 'postgres' }), /superuser/);
    } finally { await db.adminQuery(`DROP ROLE ${insider}`); }
    assert.deepEqual(await lib.privilegeMatrix(db.owner, db.roles), lib.intendedPrivileges(db.roles), 'a refused install changes nothing');
  });
});
