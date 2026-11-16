// Recurring payment mandates (migration 028), on PostgreSQL with the full
// schema: the customer's device signs the terms, every debit is decided
// inside them by Auth Core and again by the database, the customer suspends,
// resumes and revokes, the bank withdraws but cannot change terms, and every
// event is sealed into the evidence chain and verified offline.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';
import { verifyEvidenceChain } from '../../scripts/lib/evidence.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
};

describe('payment mandates (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s; let hsm; const clientId = `bank-${randomBytes(4).toString('hex')}`;

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    s = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      mandates: loadTs('services/mandateService.ts', { stubs, cache }),
      requests: loadTs('services/deviceReplacementService.ts', { stubs, cache }),
      evidence: loadTs('services/evidenceService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash, max_devices_per_identity) VALUES ($1, 'x', 2)`, [clientId]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  /** The first device, or (with `approver`) a further one added through an approved addition request. */
  async function enrolDevice(nexusId, approver) {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    let replacement = null;
    if (approver) {
      const { replacement: request } = await s.requests.requestDeviceReplacement(clientId, nexusId, 'OTHER', 'tablet', 'ADDITION');
      await s.requests.decideDeviceReplacement(approver.credentialId, nexusId, request.replacementId, 'APPROVE');
      replacement = { method: 'OTHER', reference: 'tablet', replacementId: request.replacementId, kind: 'ADDITION' };
    }
    const credential = await s.credentials.createCredential({
      nexusId, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), platform: 'IOS', securityLevel: 'SECURE_ENCLAVE',
      attestationStatus: 'VERIFIED', clientId, hsm, replacement,
      enrolment: { reason: approver ? 'ADDITION' : 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    return { ...credential, privateKey, device: { clientId, nexusId, credentialId: credential.credentialId } };
  }
  async function customer() {
    const identity = await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`);
    return { nexusId: identity.nexusId, phone: await enrolDevice(identity.nexusId) };
  }
  const propose = (c, extra = {}) => s.mandates.createMandate(clientId, {
    nexusId: c.nexusId, credentialId: c.phone.credentialId, mandateReference: `MANDATE-${randomUUID()}`,
    payee: { iban: 'PL61109010140000071219812874', name: 'Energy Co' }, currency: 'EUR', perPaymentLimitMinor: '15000',
    totalLimitMinor: null, frequency: 'MONTHLY', validFrom: new Date(Date.now() - 60_000).toISOString(),
    validUntil: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(), termsVersion: '2026-11', ...extra,
  });
  const signTerms = (key, mandate, format = 'der') => sign('sha256', Buffer.from(mandate.termsBase64, 'base64'),
    { key, dsaEncoding: format === 'der' ? 'der' : 'ieee-p1363' }).toString('base64');
  const signed = async (c, extra) => {
    const m = await propose(c, extra);
    return s.mandates.signMandate(hsm, c.phone.device, m.mandateId, signTerms(c.phone.privateKey, m), 'der');
  };
  const debit = (m, amountMinor, ref = randomUUID(), currency = 'EUR') => s.mandates.requestMandateDebit(clientId, m.mandateId, { debitReference: ref, amountMinor, currency });
  const keys = async () => ({ [await hsm.evidenceKeyId()]: await hsm.evidencePublicKeyPem() });
  const chain = async (nexusId) => (await admin.query(`SELECT * FROM evidence_records WHERE nexus_id = $1 ORDER BY chain_sequence`, [nexusId])).rows.map((r) => s.evidence.mapEvidenceRow(r));

  test('the addressed device signs the exact terms; a wrong key, another device or payment bytes are refused', async () => {
    const c = await customer();
    const m = await propose(c);
    assert.equal(m.state, 'PENDING_SIGNATURE');
    const terms = JSON.parse(Buffer.from(m.termsBase64, 'base64').toString('utf8'));
    assert.equal(terms.domain, 'NEXUS-SIGN/MANDATE');
    assert.equal(terms.per_payment_limit_minor, '15000'); assert.equal(terms.nexus_id, c.nexusId);
    const stranger = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    await assert.rejects(s.mandates.signMandate(hsm, c.phone.device, m.mandateId, signTerms(stranger, m), 'der'), /does not verify/);
    // A signature over other bytes (here: payment-domain bytes) does not verify over the terms.
    const paymentBytes = Buffer.from(JSON.stringify({ ...terms, domain: 'NEXUS-SIGN/TRANSACTION-AUTH' }));
    const paymentSignature = sign('sha256', paymentBytes, { key: c.phone.privateKey, dsaEncoding: 'der' }).toString('base64');
    await assert.rejects(s.mandates.signMandate(hsm, c.phone.device, m.mandateId, paymentSignature, 'der'), /does not verify/);
    // Another device of the same customer cannot sign a mandate offered to the phone.
    const tablet = await enrolDevice(c.nexusId, c.phone);
    await assert.rejects(s.mandates.signMandate(hsm, tablet.device, m.mandateId, signTerms(tablet.privateKey, m), 'der'), /another device/);
    assert.equal((await s.mandates.getMandateForClient(clientId, m.mandateId)).state, 'PENDING_SIGNATURE');
    const active = await s.mandates.signMandate(hsm, c.phone.device, m.mandateId, signTerms(c.phone.privateKey, m, 'raw'), 'raw');
    assert.equal(active.state, 'ACTIVE');
    await assert.rejects(s.mandates.signMandate(hsm, c.phone.device, m.mandateId, signTerms(c.phone.privateKey, m), 'der'), /Mandate is ACTIVE/);
    const records = await chain(c.nexusId);
    const sealed = records.find((r) => r.recordType === 'MANDATE');
    assert.equal(sealed.sealedPayload.event, 'SIGNED'); assert.equal(sealed.sealedPayload.termsHash, m.termsHash);
    assert.deepEqual(verifyEvidenceChain(records, await keys()), []);
    // The verifier refuses a record whose terms were altered after sealing.
    const altered = records.map((r) => (r === sealed ? { ...r, sealedPayload: { ...r.sealedPayload, termsHash: 'f'.repeat(64) } } : r));
    assert.ok(verifyEvidenceChain(altered, await keys()).length > 0);
  });

  test('debits: inside the terms allowed once per period; above the limit, other currency or a second one refused; idempotent', async () => {
    const c = await customer();
    const m = await signed(c);
    assert.equal((await debit(m, '20000')).reason, 'ABOVE_PAYMENT_LIMIT');
    assert.equal((await debit(m, '5000', randomUUID(), 'USD')).reason, 'CURRENCY_MISMATCH');
    const ref = randomUUID();
    const allowed = await debit(m, '8420', ref);
    assert.equal(allowed.decision, 'ALLOWED'); assert.equal(allowed.replayed, false);
    const replay = await debit(m, '8420', ref);
    assert.equal(replay.replayed, true); assert.equal(replay.debitId, allowed.debitId);
    await assert.rejects(debit(m, '8421', ref), /another amount or currency/);
    assert.equal((await debit(m, '100')).reason, 'PERIOD_ALREADY_DEBITED');
    const refused = (await admin.query(`SELECT count(*)::int AS n FROM mandate_debits WHERE mandate_id = $1 AND decision = 'REFUSED'`, [m.mandateId])).rows[0].n;
    assert.equal(refused, 3, 'refusals are recorded');
    assert.equal((await s.mandates.getMandateForClient(clientId, m.mandateId)).usedTotalMinor, '8420');
  });

  test('concurrent debits in one period: exactly one is allowed', async () => {
    const c = await customer();
    const m = await signed(c);
    const results = await Promise.all(Array.from({ length: 6 }, () => debit(m, '1000')));
    assert.equal(results.filter((r) => r.decision === 'ALLOWED').length, 1);
  });

  test('the total limit counts the debits of earlier periods', async () => {
    const c = await customer();
    const m = await signed(c, { totalLimitMinor: '20000' });
    // A debit allowed last month, written as the table owner with the check off.
    await admin.query(`ALTER TABLE mandate_debits DISABLE TRIGGER mandate_debits_check;
      INSERT INTO mandate_debits (debit_id, mandate_id, debit_reference, amount_minor, currency, period_start, decision)
      VALUES ('${randomUUID()}', '${m.mandateId}', 'last-month', 15000, 'EUR', (date_trunc('month', now()) - interval '1 month')::date, 'ALLOWED');
      ALTER TABLE mandate_debits ENABLE TRIGGER mandate_debits_check`);
    assert.equal((await debit(m, '6000')).reason, 'ABOVE_TOTAL_LIMIT');
    assert.equal((await debit(m, '5000')).decision, 'ALLOWED');
  });

  test('the database refuses debits outside the terms, changed terms and rewritten history', async () => {
    const c = await customer();
    const m = await signed(c);
    const insert = (amount, period = `date_trunc('month', now())::date`) => admin.query(
      `INSERT INTO mandate_debits (debit_id, mandate_id, debit_reference, amount_minor, currency, period_start, decision)
       VALUES ($1, $2, $1, $3, 'EUR', ${period}, 'ALLOWED')`, [randomUUID(), m.mandateId, amount]);
    await assert.rejects(insert(99999), /outside the signed terms/);
    await assert.rejects(insert(100, `'2020-01-01'::date`), /outside the signed terms/);
    await insert(100);
    await assert.rejects(insert(100), /already allowed in this period/);
    await assert.rejects(admin.query(`UPDATE mandates SET per_payment_limit_minor = 999999 WHERE mandate_id = $1`, [m.mandateId]), /terms are immutable/);
    await assert.rejects(admin.query(`UPDATE mandates SET signature = 'AAAA' WHERE mandate_id = $1`, [m.mandateId]), /set once/);
    await assert.rejects(admin.query(`UPDATE mandate_debits SET amount_minor = 1 WHERE mandate_id = $1`, [m.mandateId]), /rows are kept/);
    await assert.rejects(admin.query(`DELETE FROM mandates WHERE mandate_id = $1`, [m.mandateId]), /rows are kept/);
    const unsigned = await propose(c);
    await assert.rejects(admin.query(`UPDATE mandates SET state = 'ACTIVE' WHERE mandate_id = $1`, [unsigned.mandateId]), /needs the customer's signature/);
    await assert.rejects(admin.query(`INSERT INTO mandate_debits (debit_id, mandate_id, debit_reference, amount_minor, currency, period_start, decision)
      VALUES ($1, $2, $1, 100, 'EUR', date_trunc('month', now())::date, 'ALLOWED')`, [randomUUID(), unsigned.mandateId]), /outside the signed terms/);
  });

  test('the customer suspends, resumes and revokes; the bank withdraws; every event is sealed and verifies', async () => {
    const c = await customer();
    const m = await signed(c);
    const tablet = await enrolDevice(c.nexusId, c.phone);
    // Any active device of the customer manages the mandate.
    assert.equal((await s.mandates.customerMandateAction(hsm, tablet.device, m.mandateId, 'SUSPEND')).state, 'SUSPENDED');
    assert.equal((await debit(m, '100')).reason, 'MANDATE_NOT_ACTIVE');
    assert.equal((await s.mandates.customerMandateAction(hsm, c.phone.device, m.mandateId, 'RESUME')).state, 'ACTIVE');
    assert.equal((await debit(m, '100')).decision, 'ALLOWED');
    assert.equal((await s.mandates.customerMandateAction(hsm, c.phone.device, m.mandateId, 'REVOKE')).state, 'REVOKED');
    await assert.rejects(s.mandates.customerMandateAction(hsm, c.phone.device, m.mandateId, 'RESUME'), /not possible/);
    await assert.rejects(s.mandates.withdrawMandate(hsm, clientId, m.mandateId, 'closing'), /Mandate is REVOKED/);
    // Another customer's device cannot touch it.
    const other = await customer();
    await assert.rejects(s.mandates.customerMandateAction(hsm, other.phone.device, m.mandateId, 'SUSPEND'), /not found/);
    const declined = await propose(c);
    assert.equal((await s.mandates.customerMandateAction(hsm, c.phone.device, declined.mandateId, 'DECLINE')).state, 'DECLINED');
    const withdrawn = await signed(c);
    assert.equal((await s.mandates.withdrawMandate(hsm, clientId, withdrawn.mandateId, 'contract ended')).state, 'WITHDRAWN');
    const records = await chain(c.nexusId);
    const events = records.filter((r) => r.recordType === 'MANDATE').map((r) => `${r.sealedPayload.mandateId === m.mandateId ? 'm' : 'x'}:${r.sealedPayload.event}`);
    assert.deepEqual(events.filter((e) => e.startsWith('m:')), ['m:SIGNED', 'm:SUSPENDED', 'm:RESUMED', 'm:REVOKED']);
    assert.ok(events.includes('x:DECLINED') && events.includes('x:WITHDRAWN'));
    assert.deepEqual(verifyEvidenceChain(records, await keys()), []);
    const dropped = records.filter((r) => !(r.recordType === 'MANDATE' && r.sealedPayload.event === 'REVOKED'));
    assert.ok(verifyEvidenceChain(dropped, await keys()).length > 0, 'a removed revocation is detected');
  });

  test('an offer nobody signed and a mandate past its validity expire, sealed', async () => {
    const c = await customer();
    const offered = await propose(c);
    const live = await signed(c);
    await admin.query(`ALTER TABLE mandates DISABLE TRIGGER mandates_lifecycle;
      UPDATE mandates SET offer_expires_at = now() - interval '1 minute' WHERE mandate_id = '${offered.mandateId}';
      UPDATE mandates SET valid_until = now() - interval '1 minute' WHERE mandate_id = '${live.mandateId}';
      ALTER TABLE mandates ENABLE TRIGGER mandates_lifecycle`);
    assert.equal((await debit(live, '100')).reason, 'VALIDITY_ENDED');
    assert.equal(await s.mandates.expireMandates(hsm), 2);
    assert.equal((await s.mandates.getMandateForClient(clientId, offered.mandateId)).stateReason, 'OFFER_NOT_SIGNED');
    assert.equal((await s.mandates.getMandateForClient(clientId, live.mandateId)).state, 'EXPIRED');
    assert.equal(await s.mandates.expireMandates(hsm), 0);
    const expiredEvents = (await chain(c.nexusId)).filter((r) => r.recordType === 'MANDATE' && r.sealedPayload.event === 'EXPIRED');
    assert.equal(expiredEvents.length, 2);
  });

  test('terms must pass the display rules; the reference is unique per bank', async () => {
    const c = await customer();
    await assert.rejects(propose(c, { payee: { name: 'Еnergy Co' } }), /Invalid/); // Cyrillic Е in a Latin name
    await assert.rejects(propose(c, { totalLimitMinor: '100' }), /not below perPaymentLimitMinor/);
    const m = await propose(c);
    await assert.rejects(propose(c, { mandateReference: m.mandateReference }), /exists for this bank client/);
  });
});
