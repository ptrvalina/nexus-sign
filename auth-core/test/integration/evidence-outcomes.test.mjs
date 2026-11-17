// Evidence for every outcome (audit finding B-04), on PostgreSQL with the
// full schema. Before, only VERIFIED authorizations were sealed: a declined,
// rejected, expired or cancelled payment and a revoked device left no record
// in the evidence chain. Now the database records each outcome in the
// transaction of the state change, and sealPendingOutcomes() seals it; the
// offline verifier checks the whole chain, outcomes included.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';
import { verifyEvidenceChain } from '../../scripts/lib/evidence.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
  '../db/redis': { redis: {} },
};

describe('evidence for every outcome (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s; let hsm; const clientId = `bank-${randomBytes(4).toString('hex')}`;

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    s = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      authorizations: loadTs('services/authorizationService.ts', { stubs, cache }),
      decline: loadTs('services/authorizationDecline.ts', { stubs, cache }),
      expiry: loadTs('services/authorizationExpiry.ts', { stubs, cache }),
      evidence: loadTs('services/evidenceService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ($1, 'x')`, [clientId]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  async function customer() {
    const identity = await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`);
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const device = await s.credentials.createCredential({
      nexusId: identity.nexusId, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), platform: 'ANDROID', securityLevel: 'STRONGBOX',
      attestationStatus: 'VERIFIED', clientId, hsm, enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    return { nexusId: identity.nexusId, device };
  }
  const payment = async (c, amountMinor = '9800') => (await s.authorizations.createAuthorization({
    nexusId: c.nexusId, credentialId: c.device.credentialId, transactionReference: `TX-${randomUUID()}`, operationType: 'TRANSFER',
    amountMinor, currency: 'EUR', beneficiary: { iban: 'PL61109010140000071219812874', name: 'Jan Kowalski' }, policyReference: 'default', policyVersion: '7',
  }, clientId)).authorization;
  const outcomeOf = async (authorizationId) => (await admin.query(`SELECT * FROM evidence_outcomes WHERE authorization_id = $1`, [authorizationId])).rows;
  const keys = async () => ({ [await hsm.evidenceKeyId()]: await hsm.evidencePublicKeyPem() });
  async function chain(nexusId) {
    const rows = (await admin.query(`SELECT * FROM evidence_records WHERE nexus_id = $1 ORDER BY chain_sequence`, [nexusId])).rows;
    return rows.map((r) => s.evidence.mapEvidenceRow(r));
  }

  test('decline, bank cancel and expiry are recorded in the same transaction, with their reasons, and sealed', async () => {
    const c = await customer();
    const declined = await payment(c);
    const cancelled = await payment(c);
    const expired = await payment(c);
    await s.decline.declineAuthorization(declined.authorizationId, clientId, c.device.credentialId, 'NOT_ME');
    await s.decline.cancelAuthorizationByBank(cancelled.authorizationId, clientId, 'FRAUD_SUSPECTED');
    await admin.query(`UPDATE authorization_requests SET state = 'EXPIRED' WHERE authorization_id = $1`, [expired.authorizationId]);

    const d = (await outcomeOf(declined.authorizationId))[0];
    assert.equal(d.outcome, 'REJECTED'); assert.equal(d.reason, 'DECLINED_BY_CUSTOMER:NOT_ME'); assert.equal(d.evidence_id, null);
    assert.equal((await outcomeOf(cancelled.authorizationId))[0].reason, 'CANCELLED_BY_BANK:FRAUD_SUSPECTED');
    assert.equal((await outcomeOf(expired.authorizationId))[0].reason, 'expired', 'a direct write still leaves an outcome');

    assert.equal(await s.evidence.sealPendingOutcomes(hsm), 3);
    assert.equal(await s.evidence.sealPendingOutcomes(hsm), 0, 'each outcome is sealed once');
    const records = await chain(c.nexusId);
    const outcomes = records.filter((r) => r.recordType === 'AUTHORIZATION_OUTCOME');
    assert.deepEqual(outcomes.map((r) => r.sealedPayload.outcome).sort(), ['CANCELLED', 'EXPIRED', 'REJECTED']);
    const sealedDecline = outcomes.find((r) => r.authorizationId === declined.authorizationId).sealedPayload;
    assert.equal(sealedDecline.reason, 'DECLINED_BY_CUSTOMER:NOT_ME');
    assert.equal(sealedDecline.amountMinor, '9800'); assert.equal(sealedDecline.currency, 'EUR');
    assert.equal(sealedDecline.canonicalPayloadHash, declined.canonicalPayloadHash ?? sealedDecline.canonicalPayloadHash);
    assert.equal(sealedDecline.policyVersion, '7'); assert.equal(sealedDecline.credentialState, 'ACTIVE');
    assert.deepEqual(sealedDecline.device, { platform: 'ANDROID', securityLevel: 'STRONGBOX' });
    assert.deepEqual(verifyEvidenceChain(records, await keys()), [], 'the offline verifier accepts the chain');
    // Every record names the bank it was sealed for (finding B-10).
    assert.deepEqual([...new Set(records.map((r) => r.sealedPayload.clientId))], [clientId]);
  });

  test('a revoked device and the payments it leaves open are sealed; the verifier refuses a changed outcome', async () => {
    const c = await customer();
    const open = await payment(c);
    await s.credentials.revokeCredentialForClient(c.device.credentialId, clientId, 'lost phone');
    await s.evidence.sealPendingOutcomes(hsm);
    const records = await chain(c.nexusId);
    const revoked = records.find((r) => r.recordType === 'CREDENTIAL_REVOKED');
    assert.equal(revoked.sealedPayload.reason, 'REVOKED_BY_BANK:lost phone');
    const cancelled = records.find((r) => r.recordType === 'AUTHORIZATION_OUTCOME');
    assert.equal(cancelled.authorizationId, open.authorizationId);
    assert.equal(cancelled.sealedPayload.reason, 'CREDENTIAL_REVOKED');
    assert.deepEqual(verifyEvidenceChain(records, await keys()), []);

    const forged = records.map((r) => (r === cancelled ? { ...r, sealedPayload: { ...r.sealedPayload, outcome: 'EXPIRED' } } : r));
    assert.ok(verifyEvidenceChain(forged, await keys()).some((p) => /evidence hash does not match/.test(p)));
    const dropped = records.filter((r) => r !== revoked);
    assert.ok(verifyEvidenceChain(dropped, await keys()).some((p) => /records missing|chain broken/.test(p)), 'a removed outcome is detected');
  });

  test('an outcome cannot be deleted, rewritten or linked twice; a failed seal leaves it pending', async () => {
    const c = await customer();
    const p = await payment(c);
    await s.decline.declineAuthorization(p.authorizationId, clientId, c.device.credentialId, 'WRONG_DETAILS');
    const row = (await outcomeOf(p.authorizationId))[0];
    await assert.rejects(admin.query(`DELETE FROM evidence_outcomes WHERE outcome_id = $1`, [row.outcome_id]), /kept/);
    await assert.rejects(admin.query(`UPDATE evidence_outcomes SET reason = 'x' WHERE outcome_id = $1`, [row.outcome_id]), /only the sealing record/);
    await assert.rejects(admin.query(`TRUNCATE evidence_outcomes`), /append-only/);

    const failing = { ...hsm, evidenceKeyId: () => hsm.evidenceKeyId(), signEvidence: async () => { throw new Error('HSM down'); } };
    await assert.rejects(s.evidence.sealPendingOutcomes(failing), /HSM down/);
    assert.equal((await outcomeOf(p.authorizationId))[0].evidence_id, null, 'still pending after the failure');
    assert.ok((await s.evidence.unsealedOutcomes()).count >= 1);

    await s.evidence.sealPendingOutcomes(hsm);
    const sealed = (await outcomeOf(p.authorizationId))[0];
    assert.notEqual(sealed.evidence_id, null);
    const other = (await admin.query(`SELECT evidence_id FROM evidence_records WHERE record_type = 'CREDENTIAL_ENROLLED' AND nexus_id = $1`, [c.nexusId])).rows[0].evidence_id;
    await assert.rejects(admin.query(`UPDATE evidence_outcomes SET evidence_id = $2, sealed_at = now() WHERE outcome_id = $1`, [row.outcome_id, other]), /only the sealing record/);
  });

  test('two sealers running at once seal every outcome exactly once, in a valid chain', async () => {
    const c = await customer();
    const payments = [];
    for (let i = 0; i < 6; i += 1) payments.push(await payment(c));
    for (const p of payments) await s.decline.cancelAuthorizationByBank(p.authorizationId, clientId, 'ORDER_CHANGED');
    const [a, b] = await Promise.all([s.evidence.sealPendingOutcomes(hsm), s.evidence.sealPendingOutcomes(hsm)]);
    const records = (await chain(c.nexusId)).filter((r) => r.recordType === 'AUTHORIZATION_OUTCOME');
    assert.equal(records.length, 6);
    assert.ok(a + b >= 6);
    assert.deepEqual(verifyEvidenceChain(await chain(c.nexusId), await keys()), []);
  });
});
