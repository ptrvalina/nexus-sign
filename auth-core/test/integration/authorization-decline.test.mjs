// The customer declines a payment on the enrolled device, and the bank
// withdraws one it no longer wants (audit finding A1-03), on PostgreSQL with
// the full schema. Before, a customer who received a payment they did not
// start could only ignore it, and the bank learned nothing until expiry.
//
// Service level: the services run in this process against a real database;
// Redis and metrics are stubbed (not used on these paths).
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
  '../db/redis': { redis: {} },
};

describe('authorization decline and bank cancel (PostgreSQL)', { skip: skipWithoutServices }, () => {
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
      confirmation: loadTs('services/authorizationConfirmation.ts', { stubs, cache }),
      decline: loadTs('services/authorizationDecline.ts', { stubs, cache }),
      record: loadTs('services/authorizationRecord.ts', { stubs, cache }),
      canonical: loadTs('services/canonicalAuthorization.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    // A webhook destination, so that webhooks are queued (never delivered here).
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash, webhook_url, webhook_secret_encrypted) VALUES ($1, 'x', 'https://hooks.bank.example/nexus', 'not-used')`, [clientId]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  async function pendingPayment() {
    const identity = await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`);
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const device = await s.credentials.createCredential({
      nexusId: identity.nexusId, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), platform: 'IOS', securityLevel: 'SECURE_ENCLAVE',
      attestationStatus: 'VERIFIED', clientId, hsm, enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    const { authorization } = await s.authorizations.createAuthorization({
      nexusId: identity.nexusId, credentialId: device.credentialId, transactionReference: `TX-${randomUUID()}`, operationType: 'TRANSFER',
      amountMinor: '125000', currency: 'PLN', beneficiary: { iban: 'PL61109010140000071219812874', name: 'Jan Kowalski' },
      policyReference: 'default', policyVersion: '1',
    }, clientId);
    const signature = () => {
      const bytes = s.canonical.canonicalizeAuthorization(s.record.authorizationObjectOf(authorization));
      return sign('sha256', bytes, { key: privateKey, dsaEncoding: 'der' }).toString('base64');
    };
    return { identity, device, authorization, signature };
  }
  const stateOf = async (id) => (await admin.query(`SELECT state FROM authorization_requests WHERE authorization_id = $1`, [id])).rows[0].state;
  const webhooks = async (id, type) => (await admin.query(`SELECT payload FROM webhook_deliveries WHERE event_type = $2 AND payload->>'authorizationId' = $1`, [id, type])).rows;

  test('the customer declines ("it wasn\'t me"): REJECTED, the bank is told, a later signature fails', async () => {
    const p = await pendingPayment();
    const declined = await s.decline.declineAuthorization(p.authorization.authorizationId, clientId, p.device.credentialId, 'NOT_ME');
    assert.equal(declined.state, 'REJECTED');
    assert.equal(await stateOf(p.authorization.authorizationId), 'REJECTED');
    const sent = await webhooks(p.authorization.authorizationId, 'authorization.declined');
    assert.equal(sent.length, 1);
    assert.equal(sent[0].payload.reason, 'NOT_ME');
    const audit = await admin.query(`SELECT details FROM audit_logs WHERE event_type = 'authorization_declined' AND details->>'authorizationId' = $1`, [p.authorization.authorizationId]);
    assert.equal(audit.rowCount, 1);
    const late = await s.confirmation.verifyAuthorization(hsm, p.authorization.authorizationId, clientId, p.signature(), 'der');
    assert.equal(late.status, 'FAILED');
    assert.equal(await stateOf(p.authorization.authorizationId), 'REJECTED');
    await assert.rejects(s.decline.declineAuthorization(p.authorization.authorizationId, clientId, p.device.credentialId, 'NOT_ME'), (e) => e.code === 'AUTHORIZATION_NOT_PENDING');
  });

  test('only the bound device declines; a confirmed payment cannot be declined', async () => {
    const p = await pendingPayment();
    await assert.rejects(s.decline.declineAuthorization(p.authorization.authorizationId, clientId, randomUUID(), 'OTHER'), (e) => e.code === 'CREDENTIAL_MISMATCH');
    const confirmed = await s.confirmation.verifyAuthorization(hsm, p.authorization.authorizationId, clientId, p.signature(), 'der');
    assert.equal(confirmed.status, 'VERIFIED', JSON.stringify(confirmed));
    await assert.rejects(s.decline.declineAuthorization(p.authorization.authorizationId, clientId, p.device.credentialId, 'NOT_ME'), (e) => e.code === 'AUTHORIZATION_NOT_PENDING');
    await assert.rejects(s.decline.cancelAuthorizationByBank(p.authorization.authorizationId, clientId, 'ORDER_CHANGED'), (e) => e.code === 'AUTHORIZATION_NOT_PENDING');
    assert.equal(await stateOf(p.authorization.authorizationId), 'VERIFIED');
  });

  test('the bank withdraws a pending payment: CANCELLED, a later signature fails; another bank cannot', async () => {
    const p = await pendingPayment();
    await assert.rejects(s.decline.cancelAuthorizationByBank(p.authorization.authorizationId, 'another-bank', 'OTHER'), /not found/);
    const cancelled = await s.decline.cancelAuthorizationByBank(p.authorization.authorizationId, clientId, 'FRAUD_SUSPECTED');
    assert.equal(cancelled.state, 'CANCELLED');
    assert.equal((await webhooks(p.authorization.authorizationId, 'authorization.cancelled')).length, 1);
    const late = await s.confirmation.verifyAuthorization(hsm, p.authorization.authorizationId, clientId, p.signature(), 'der');
    assert.equal(late.status, 'FAILED');
    assert.equal(await stateOf(p.authorization.authorizationId), 'CANCELLED');
  });
});
