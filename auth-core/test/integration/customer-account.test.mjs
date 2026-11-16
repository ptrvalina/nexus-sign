// The customer's own section in the bank's app (presentation pages 19 to 22),
// on PostgreSQL with the full schema: devices, history with outcomes, the
// sealed evidence of a payment, the security log, the notification feed,
// settings with limits enforced when the bank creates an authorization, a
// video check above the customer's threshold, and suspension by the customer.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';
import { verifyEvidenceRecord } from '../../scripts/lib/evidence.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
  '../db/redis': { redis: {} },
};

describe('customer section: devices, history, evidence, settings, limits, suspension (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s; let hsm; const clientId = `bank-${randomBytes(4).toString('hex')}`;

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    process.env.CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS = '2';
    const cache = new Map();
    s = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      authorizations: loadTs('services/authorizationService.ts', { stubs, cache }),
      decline: loadTs('services/authorizationDecline.ts', { stubs, cache }),
      evidence: loadTs('services/evidenceService.ts', { stubs, cache }),
      account: loadTs('services/customerAccountService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash, operator_verification_channels) VALUES ($1, 'x', '{AUDIO,VIDEO}')`, [clientId]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  async function customer() {
    const identity = await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`);
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const device = await s.credentials.createCredential({
      nexusId: identity.nexusId, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), platform: 'IOS', securityLevel: 'SECURE_ENCLAVE',
      attestationStatus: 'VERIFIED', clientId, hsm, enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    return { nexusId: identity.nexusId, device };
  }
  const pay = (c, amountMinor, currency = 'EUR') => s.authorizations.createAuthorization({
    nexusId: c.nexusId, credentialId: c.device.credentialId, transactionReference: `TX-${randomUUID()}`, operationType: 'TRANSFER',
    amountMinor, currency, beneficiary: { iban: 'PL61109010140000071219812874', name: 'Jan Kowalski' }, policyReference: 'default', policyVersion: '1',
  }, clientId);
  const settings = (over = {}) => ({ currency: 'EUR', perPaymentLimitMinor: null, dailyLimitMinor: null, videoCheckAboveMinor: null, channels: { push: true, audio: true, video: true }, ...over });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  test('devices, history with outcomes and reasons, and the customer\'s sealed evidence of a declined payment', async () => {
    const c = await customer();
    const { authorization: declined } = await pay(c, '2500');
    const { authorization: open } = await pay(c, '100');
    await s.decline.declineAuthorization(declined.authorizationId, clientId, c.device.credentialId, 'NOT_ME');
    await s.evidence.sealPendingOutcomes(hsm);

    const devices = await s.account.listDevices(c.nexusId, c.device.credentialId);
    assert.deepEqual(devices.map((d) => [d.credentialId, d.state, d.thisDevice]), [[c.device.credentialId, 'ACTIVE', true]]);

    const history = await s.account.authorizationHistory(c.nexusId);
    const d = history.find((h) => h.authorizationId === declined.authorizationId);
    assert.deepEqual([d.state, d.reason, d.evidence], ['REJECTED', 'DECLINED_BY_CUSTOMER:NOT_ME', true]);
    assert.deepEqual((await s.account.authorizationHistory(c.nexusId, { filter: 'open' })).map((h) => h.authorizationId), [open.authorizationId]);
    assert.deepEqual((await s.account.authorizationHistory(c.nexusId, { filter: 'declined' })).map((h) => h.authorizationId), [declined.authorizationId]);
    const firstPage = await s.account.authorizationHistory(c.nexusId, { limit: 1 });
    const secondPage = await s.account.authorizationHistory(c.nexusId, { limit: 1, before: firstPage[0].createdAt });
    assert.notEqual(firstPage[0].authorizationId, secondPage[0].authorizationId);

    const evidence = await s.account.evidenceForCustomer(c.nexusId, declined.authorizationId);
    assert.equal(evidence.record.recordType, 'AUTHORIZATION_OUTCOME');
    const keys = { [await hsm.evidenceKeyId()]: await hsm.evidencePublicKeyPem() };
    assert.deepEqual(verifyEvidenceRecord(evidence.record, keys), []);
    assert.equal(evidence.credentialEnrolment.recordType, 'CREDENTIAL_ENROLLED');

    const other = await customer();
    await assert.rejects(s.account.evidenceForCustomer(other.nexusId, declined.authorizationId), /No sealed evidence/, 'another identity sees nothing');
    assert.deepEqual(await s.account.authorizationHistory(other.nexusId), []);
  });

  test('the security log shows what happened without operator names or addresses', async () => {
    const c = await customer();
    await admin.query(`INSERT INTO audit_logs (event_id, event_type, nexus_id, details, ip_address, actor)
      VALUES (gen_random_uuid(), 'credential_revoked', $1, '{"reason":"lost","credentialId":"x","operatorNote":"secret note"}', '10.1.2.3', 'admin:anna')`, [c.nexusId]);
    const events = await s.account.securityEvents(c.nexusId);
    const revoked = events.find((e) => e.eventType === 'credential_revoked');
    assert.deepEqual(revoked.details, { reason: 'lost', credentialId: 'x' });
    assert.equal(revoked.actor, 'OPERATOR');
    assert.ok(!JSON.stringify(events).includes('anna') && !JSON.stringify(events).includes('10.1.2.3'));
    assert.ok(events.some((e) => e.eventType === 'identity_created'));
  });

  test('a payment creates a feed entry; the feed is per identity', async () => {
    const c = await customer();
    await admin.query(`INSERT INTO push_messages (message_id, client_id, nexus_id, credential_id, category, status, expires_at, envelope)
      VALUES (gen_random_uuid(), $1, $2, $3, 'INCOMING_PAYMENT', 'DELIVERED', now() + interval '1 day', 'sealed-envelope')`, [clientId, c.nexusId, c.device.credentialId]);
    const feed = await s.account.notificationHistory(c.nexusId);
    assert.ok(feed.some((n) => n.category === 'INCOMING_PAYMENT'));
    assert.deepEqual(await s.account.notificationHistory((await customer()).nexusId), []);
  });

  test('limits: tightening applies at once and is enforced; relaxing waits for the hold', async () => {
    const c = await customer();
    const v1 = await s.account.updateSettings(clientId, c.nexusId, c.device.credentialId, settings({ perPaymentLimitMinor: '50000', dailyLimitMinor: '80000' }));
    assert.equal(v1.version, 1);
    await assert.rejects(pay(c, '50001'), (e) => e.code === 'CUSTOMER_LIMIT_EXCEEDED');
    await pay(c, '50000');
    await assert.rejects(pay(c, '30001'), (e) => e.code === 'CUSTOMER_LIMIT_EXCEEDED' && /daily/.test(e.message));
    await pay(c, '30000');
    await pay(c, '999999', 'USD'); // another currency: the customer's EUR limits do not apply

    const raised = await s.account.updateSettings(clientId, c.nexusId, c.device.credentialId, settings({ perPaymentLimitMinor: '900000', dailyLimitMinor: null }));
    assert.ok(new Date(raised.effectiveAt) > new Date(), 'a raised limit is held');
    const state = await s.account.getSettings(c.nexusId);
    assert.equal(state.current.perPaymentLimitMinor, '50000');
    assert.equal(state.pending.perPaymentLimitMinor, '900000');
    await assert.rejects(pay(c, '60000'), (e) => e.code === 'CUSTOMER_LIMIT_EXCEEDED');
    await sleep(2200);
    await pay(c, '60000');

    const webhooks = await admin.query(`SELECT payload FROM webhook_deliveries WHERE event_type = 'customer.settings_changed' AND payload->>'nexusId' = $1`, [c.nexusId]);
    assert.equal(webhooks.rowCount, 0, 'no webhook destination configured: nothing queued') ;
    const audit = await admin.query(`SELECT details FROM audit_logs WHERE event_type = 'customer_settings_changed' AND nexus_id = $1 ORDER BY timestamp`, [c.nexusId]);
    assert.deepEqual(audit.rows.map((r) => r.details.relaxes), [false, true]);
    await assert.rejects(admin.query(`UPDATE customer_settings_versions SET per_payment_limit_minor = 1 WHERE nexus_id = $1`, [c.nexusId]), /append-only/);
  });

  test('concurrent payments cannot together pass the daily limit', async () => {
    const c = await customer();
    await s.account.updateSettings(clientId, c.nexusId, c.device.credentialId, settings({ dailyLimitMinor: '10000' }));
    const results = await Promise.allSettled(Array.from({ length: 5 }, () => pay(c, '4000')));
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 2);
  });

  test('above the customer\'s threshold the plan requires a video check', async () => {
    const c = await customer();
    await s.account.updateSettings(clientId, c.nexusId, c.device.credentialId, settings({ videoCheckAboveMinor: '100000' }));
    assert.equal((await pay(c, '100000')).plan.requiredStep, 'PUSH');
    assert.equal((await pay(c, '100001')).plan.requiredStep, 'VIDEO');
    await assert.rejects(s.account.updateSettings(clientId, c.nexusId, c.device.credentialId, settings({ videoCheckAboveMinor: '1', channels: { push: true, audio: true, video: false } })), /needs the video channel/);
    await assert.rejects(s.account.updateSettings(clientId, c.nexusId, c.device.credentialId, settings({ channels: { push: false, audio: true, video: true } })), /Push cannot be switched off/);
    await assert.rejects(s.account.updateSettings(clientId, c.nexusId, c.device.credentialId, settings({ currency: null, perPaymentLimitMinor: '1' })), /need a currency/);
  });

  test('the customer suspends the NEXUS ID: open payments are cancelled with an outcome, new ones refused', async () => {
    const c = await customer();
    const { authorization } = await pay(c, '500');
    await s.account.suspendByCustomer(clientId, c.nexusId, c.device.credentialId, 'LOST_DEVICE');
    assert.equal((await admin.query(`SELECT status FROM nexus_identities WHERE nexus_id = $1`, [c.nexusId])).rows[0].status, 'SUSPENDED');
    const outcome = (await admin.query(`SELECT outcome, reason FROM evidence_outcomes WHERE authorization_id = $1`, [authorization.authorizationId])).rows[0];
    assert.deepEqual(outcome, { outcome: 'CANCELLED', reason: 'IDENTITY_SUSPENDED' });
    await assert.rejects(pay(c, '500'), /SUSPENDED/);
    const audit = await admin.query(`SELECT actor, details FROM audit_logs WHERE event_type = 'identity_suspended' AND nexus_id = $1`, [c.nexusId]);
    assert.equal(audit.rows[0].actor, `credential:${c.device.credentialId}`);
    await s.identities.reactivateNexusIdentity(c.nexusId, 'BANK:BRANCH_VISIT:case-9', `bank:${clientId}`);
    await pay(c, '500');
  });
});
