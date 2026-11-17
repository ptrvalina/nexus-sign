// Who tells the customer that a verification call ended (verificationCall.ts,
// closeAs), on PostgreSQL and a real Redis. When the operator hangs up or
// decides, the session is closed in the database; a read by the phone at that
// moment notices the closed session and used to relay a server bye
// ("session_cancelled") before the operator's own bye ("operator_left"), so
// the phone showed the wrong reason. Found by test/media/webrtc-call.test.mjs
// in CI (cycle 4). The closure is now claimed in Redis before the change.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';
import { redisModule } from '../support/resp-redis.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: redisModule(),
};

describe('verification call closure: the party that ends the call gives the reason (PostgreSQL and Redis)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s; let hsm; let redis;
  const clientId = `bank-${randomBytes(4).toString('hex')}`;
  const operator = { username: 'anna', clientId };

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.REDIS_URL = process.env.INTEGRATION_REDIS_URL;
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    s = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      authorizations: loadTs('services/authorizationService.ts', { stubs, cache }),
      verification: loadTs('services/adaptiveVerificationService.ts', { stubs, cache }),
      calls: loadTs('services/verificationCall.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    redis = loadTs('db/redis.ts', { stubs, cache }).redis;
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash, operator_verification_channels) VALUES ($1, 'x', '{AUDIO,VIDEO}')`, [clientId]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await redis?.quit?.(); await db?.drop(); });

  /** An authorization that requires an audio check, with an open call claimed by the operator. */
  async function openCall() {
    const nexusId = (await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`)).nexusId;
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const credential = await s.credentials.createCredential({
      nexusId, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), platform: 'IOS', securityLevel: 'SECURE_ENCLAVE',
      attestationStatus: 'VERIFIED', clientId, hsm, enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    const created = await s.authorizations.createAuthorization({
      nexusId, credentialId: credential.credentialId, transactionReference: `TX-${randomUUID()}`, operationType: 'TRANSFER', amountMinor: '125000', currency: 'PLN',
      beneficiary: { iban: 'PL61109010140000071219812874', name: 'Jan Kowalski' }, policyReference: 'default', policyVersion: '1',
      verificationPolicy: { requireAudio: true, videoAvailable: false },
    }, clientId);
    const { sessionId } = await s.verification.openVerificationSession(created.authorization.authorizationId, clientId, 'AUDIO');
    await s.calls.claimCall(sessionId, operator);
    return { sessionId, device: { clientId, nexusId, credentialId: credential.credentialId } };
  }
  const byes = async (sessionId, device) => (await s.calls.deviceSignals(sessionId, device, 0, 0)).signals.filter((x) => x.type === 'bye').map((x) => [x.from, x.payload.reason]);
  const cancelInDb = (sessionId) => admin.query(`UPDATE verification_sessions SET status = 'CANCELLED' WHERE session_id = $1`, [sessionId]);

  test('without a claim, a read during the hang-up relays a server bye first (the defect)', async () => {
    const { sessionId, device } = await openCall();
    await cancelInDb(sessionId);
    await s.calls.deviceSignals(sessionId, device, 0, 0); // the phone reads between the change and the operator's bye
    await s.calls.sendBye(sessionId, 'operator', 'operator_left');
    assert.deepEqual((await byes(sessionId, device))[0], ['server', 'session_cancelled']);
  });

  test('with closeAs, the same interleaving delivers only the operator\'s reason', async () => {
    const { sessionId, device } = await openCall();
    await s.calls.closeAs(sessionId, 'operator', 'operator_left', async () => {
      await cancelInDb(sessionId);
      await s.calls.deviceSignals(sessionId, device, 0, 0); // the same concurrent read
    });
    assert.deepEqual(await byes(sessionId, device), [['operator', 'operator_left']]);
  });

  test('operatorRelease ends the call with the operator\'s reason and the plan goes back to PENDING', async () => {
    const { sessionId, device } = await openCall();
    await s.calls.operatorRelease(sessionId, operator);
    assert.deepEqual(await byes(sessionId, device), [['operator', 'operator_left']]);
    const status = await admin.query(`SELECT status FROM verification_sessions WHERE session_id = $1`, [sessionId]);
    assert.equal(status.rows[0].status, 'CANCELLED');
  });

  test('if the change fails, the claim is withdrawn: nothing is sent, and a later closure is still relayed', async () => {
    const { sessionId, device } = await openCall();
    await assert.rejects(s.calls.closeAs(sessionId, 'operator', 'operator_left', async () => { throw new Error('database unavailable'); }), /database unavailable/);
    assert.deepEqual(await byes(sessionId, device), []);
    await cancelInDb(sessionId);
    assert.deepEqual(await byes(sessionId, device), [['server', 'session_cancelled']]);
  });
});
