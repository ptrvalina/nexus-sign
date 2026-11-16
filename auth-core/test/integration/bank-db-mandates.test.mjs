// Debits under a payment mandate in the bank database (bank-integration),
// on PostgreSQL. The database itself decides: the evidence is the sealed
// SIGNED event of the mandate the payment names, the customer's device
// signature over the terms verifies (in SQL, ECDSA P-256) with a key the bank
// approved, the payment is inside the terms (customer, payee, currency, limit
// per payment, validity), the mandate was not stopped, and the bank's own
// count allows one debit per period and the total limit. The evidence is a
// synthetic fixture (support/syntheticEvidence.mjs), not Auth Core output.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { skipWithoutServices } from './support/harness.mjs';
import { bankDatabase } from './support/bankSide.mjs';
import { evidenceMaker } from './support/syntheticEvidence.mjs';
import { approvalStatement, signStatement } from '../../scripts/lib/bankTrust.mjs';

const integration = () => import('../../../bank-integration/index.mjs');

describe('bank database: debits under a payment mandate (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let lib; let db; let store; let registry;
  const maker = evidenceMaker();
  const bankKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const bankTrustKeys = [bankKey.publicKey.export({ type: 'spki', format: 'pem' }).toString()];
  const nexus = () => String(100000000 + Math.floor(Math.random() * 899999999));
  const payee = { name: 'Energy Co', iban: 'PL61109010140000071219812874' };

  before(async () => {
    lib = await integration();
    db = await bankDatabase(lib, { bankTrustKeys });
    store = lib.createTrustStore(db.pools.boundary);
    registry = lib.createRegistry(db.pools.registry, { bankTrustKeys });
  });
  after(async () => { await db?.drop(); });

  async function customerWithMandate(options = {}) {
    const nexusId = nexus();
    const device = maker.device(nexusId);
    await registry.approve(signStatement(approvalStatement({ nexusId, credentialId: device.credentialId, signingKeySha256: device.fingerprint, reference: 'app' }), bankKey.privateKey));
    const mandateId = randomUUID();
    const evidence = maker.mandate(device, { mandateId, payee, currency: 'EUR', perPaymentLimitMinor: '15000', ...options });
    return { nexusId, device, mandateId, evidence };
  }
  /** A debit payment under the mandate, claimed, and the approval result. */
  async function debit(c, { amountMinor = '8420', currency = 'EUR', beneficiary = payee, evidence = c.evidence, mandateId = c.mandateId } = {}) {
    const paymentId = randomUUID();
    const terms = { nexusId: c.nexusId, transactionReference: `dd-${paymentId.slice(0, 6)}`, operationType: 'DIRECT_DEBIT', amountMinor, currency, beneficiary };
    await store.createPayment({ paymentId, bankTransactionReference: `CORE-${paymentId.slice(0, 8)}`, terms });
    await store.attachMandate(paymentId, mandateId);
    const claim = await store.claim(paymentId, 30_000);
    assert.equal(claim.outcome, 'CHECKING');
    return { paymentId, result: await store.approveExecution(paymentId, claim.attemptId, evidence, 30_000) };
  }

  test('a debit inside the signed terms is approved; a second one in the same period is refused by the bank count', async () => {
    const c = await customerWithMandate();
    const first = await debit(c);
    assert.deepEqual(first.result, { ok: true });
    assert.equal((await store.execution(first.paymentId)).state, 'APPROVED');
    const second = await debit(c, { amountMinor: '100' });
    assert.equal(second.result.ok, false); assert.match(second.result.reason, /already approved in this period/);
  });

  test('outside the terms: amount, currency, payee, another customer, another mandate, altered or unsigned terms', async () => {
    const c = await customerWithMandate();
    for (const [args, why] of [
      [{ amountMinor: '15001' }, /limit per payment/],
      [{ currency: 'USD' }, /payee or currency/],
      [{ beneficiary: { ...payee, name: 'Energy Co Ltd' } }, /payee or currency/],
      [{ mandateId: randomUUID() }, /another mandate/],
      [{ evidence: { ...c.evidence, sealedPayload: { ...c.evidence.sealedPayload, termsHash: 'a'.repeat(64) } } }, /termsHash/],
      [{ evidence: { ...c.evidence, sealedPayload: { ...c.evidence.sealedPayload, event: 'REVOKED' } } }, /not the signed event/],
    ]) {
      const { result } = await debit(c, args);
      assert.equal(result.ok, false, String(why)); assert.match(result.reason, why);
    }
    // Terms signed by a key the bank never approved for this customer.
    const stranger = maker.device(c.nexusId);
    const forged = maker.mandate(stranger, { mandateId: c.mandateId, payee, currency: 'EUR', perPaymentLimitMinor: '99999999' });
    const { result } = await debit(c, { evidence: forged, amountMinor: '99999' });
    assert.equal(result.ok, false); assert.match(result.reason, /not in the bank's registry|has not approved/);
    // Payment-domain bytes presented as mandate terms.
    const wrongDomain = maker.mandate(c.device, { mandateId: c.mandateId, payee, currency: 'EUR', perPaymentLimitMinor: '15000', termsOverride: { domain: 'NEXUS-SIGN/TRANSACTION-AUTH' } });
    assert.match((await debit(c, { evidence: wrongDomain })).result.reason, /not the terms of this mandate/);
  });

  test('the device signature over the terms is verified in the database', async () => {
    const c = await customerWithMandate();
    const tampered = structuredClone(c.evidence);
    const bytes = Buffer.from(tampered.sealedPayload.signature, 'base64'); bytes[bytes.length - 1] ^= 1;
    tampered.sealedPayload.signature = bytes.toString('base64');
    const { result } = await debit(c, { evidence: tampered });
    assert.equal(result.ok, false); assert.match(result.reason, /signature does not verify/);
  });

  test('validity and the total limit; a stopped mandate allows no debit', async () => {
    const expired = await customerWithMandate({ validFrom: new Date(Date.now() - 864e5 * 30).toISOString(), validUntil: new Date(Date.now() - 1000).toISOString() });
    assert.match((await debit(expired)).result.reason, /not valid now/);
    const capped = await customerWithMandate({ totalLimitMinor: '15000' });
    await db.owner.query(`INSERT INTO bank.mandate_debits (payment_id, mandate_id, period_start, amount_minor)
      SELECT p.payment_id, $1, '2020-01-01', 10000 FROM bank.payments p LIMIT 1`, [capped.mandateId]).catch(() => {});
    const capPayment = randomUUID();
    await store.createPayment({ paymentId: capPayment, bankTransactionReference: `CORE-${capPayment.slice(0, 8)}`, terms: { nexusId: capped.nexusId, transactionReference: 'old', operationType: 'DIRECT_DEBIT', amountMinor: '10000', currency: 'EUR', beneficiary: payee } });
    await store.attachMandate(capPayment, capped.mandateId);
    await db.owner.query(`INSERT INTO bank.mandate_debits (payment_id, mandate_id, period_start, amount_minor) VALUES ($1, $2, '2020-01-01', 10000)`, [capPayment, capped.mandateId]);
    assert.match((await debit(capped, { amountMinor: '6000' })).result.reason, /total limit/);
    const stopped = await customerWithMandate();
    await registry.recordMandateStop({ mandateId: stopped.mandateId, event: 'REVOKED', evidenceHash: 'b'.repeat(64) });
    assert.match((await debit(stopped)).result.reason, /was stopped/);
    await assert.rejects(db.owner.query(`DELETE FROM bank.mandate_stops WHERE mandate_id = $1`, [stopped.mandateId]), /append|kept|not permitted/i);
  });

  test('the boundary role cannot write the bank count, and a payment keeps its mandate', async () => {
    const c = await customerWithMandate();
    const { paymentId } = await debit(c);
    await assert.rejects(db.pools.boundary.query(`INSERT INTO bank.mandate_debits (payment_id, mandate_id, period_start, amount_minor) VALUES ($1, $2, '2020-01-01', 1)`, [randomUUID(), c.mandateId]), /permission denied/);
    await assert.rejects(db.pools.boundary.query(`SELECT bank.record_mandate_stop($1, 'REVOKED', $2)`, [c.mandateId, 'c'.repeat(64)]), /permission denied/);
    await assert.rejects(db.owner.query(`UPDATE bank.payments SET mandate_id = $2 WHERE payment_id = $1`, [paymentId, randomUUID()]), /attached once/);
  });
});
