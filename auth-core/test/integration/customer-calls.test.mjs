// Calls the customer starts from the bank's app (customerCallService.ts,
// migration 030), on PostgreSQL and a real Redis server: the bank enables
// the channel, one open call per NEXUS ID, the bank's operator queue, one
// operator answers, WebRTC signalling between the device that asked and the
// operator who answered, ending by either side, a call nobody answered, a
// device revoked during the call, webhooks to the bank and the database
// keeping the record as it ended.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';
import { redisModule } from '../support/resp-redis.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: redisModule(),
};

describe('customer-initiated calls (PostgreSQL and Redis)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s; let hsm; let redis;
  const clientId = `bank-${randomBytes(4).toString('hex')}`;
  const otherBank = `bank-${randomBytes(4).toString('hex')}`;
  const anna = { username: 'anna', clientId }; const ben = { username: 'ben', clientId };
  const platform = { username: 'root', clientId: null }; const eve = { username: 'eve', clientId: otherBank };

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.REDIS_URL = process.env.INTEGRATION_REDIS_URL;
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    s = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      calls: loadTs('services/customerCallService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    redis = loadTs('db/redis.ts', { stubs, cache }).redis;
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash, webhook_url, webhook_secret_encrypted) VALUES ($1, 'x', 'https://bank.example/hooks', 'sealed'), ($2, 'x', NULL, NULL)`, [clientId, otherBank]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await redis?.quit?.(); await db?.drop(); });

  async function customer() {
    const identity = await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`);
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const credential = await s.credentials.createCredential({
      nexusId: identity.nexusId, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), platform: 'ANDROID', securityLevel: 'STRONGBOX',
      attestationStatus: 'VERIFIED', clientId, hsm, enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    return { nexusId: identity.nexusId, credentialId: credential.credentialId, device: { clientId, nexusId: identity.nexusId, credentialId: credential.credentialId } };
  }
  const hooks = async (callId) => (await admin.query(
    `SELECT event_type, payload FROM webhook_deliveries WHERE client_id = $1 AND payload->>'callId' = $2 ORDER BY created_at, event_type`, [clientId, callId])).rows;
  const enable = (channels) => admin.query(`UPDATE bank_clients SET customer_call_channels = $2 WHERE client_id = $1`, [clientId, channels]);
  const offer = { sdp: 'v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n' };

  test('the bank decides the channels; one open call per customer; the bank is told', async () => {
    const c = await customer();
    await assert.rejects(s.calls.requestCustomerCall(c.device, { channel: 'VIDEO', topic: 'Card question' }), (e) => e.code === 'CALL_CHANNEL_NOT_ENABLED');
    await enable(['AUDIO']);
    await assert.rejects(s.calls.requestCustomerCall(c.device, { channel: 'VIDEO', topic: 'Card question' }), (e) => e.code === 'CALL_CHANNEL_NOT_ENABLED');
    await assert.rejects(s.calls.requestCustomerCall(c.device, { channel: 'AUDIO', topic: 'Card‮question' }), /not shown safely/);
    const { call } = await s.calls.requestCustomerCall(c.device, { channel: 'AUDIO', topic: 'Card question' });
    assert.equal(call.state, 'WAITING'); assert.equal(call.operator, null);
    await assert.rejects(s.calls.requestCustomerCall(c.device, { channel: 'AUDIO', topic: 'Again' }), (e) => e.code === 'CALL_ALREADY_OPEN');
    // Another customer, and the same customer's call seen from another bank or by a platform account: not found.
    const other = await customer();
    await assert.rejects(s.calls.deviceCallState(call.callId, other.device), /not found/i);
    await assert.rejects(s.calls.operatorAnswer(eve, call.callId), /not found/i);
    await assert.rejects(s.calls.operatorAnswer(platform, call.callId), /not found/i);
    await assert.rejects(s.calls.bankCall(otherBank, call.callId), /not found/i);
    assert.equal((await s.calls.bankCall(clientId, call.callId)).state, 'WAITING');
    assert.ok((await s.calls.operatorCallQueue(anna)).some((q) => q.callId === call.callId));
    assert.deepEqual((await hooks(call.callId)).map((h) => h.event_type), ['customer_call.requested']);
    await s.calls.deviceEnd(call.callId, c.device);
  });

  test('one operator answers; only the two parties signal; either ends; both receive bye; the record is kept', async () => {
    await enable(['AUDIO', 'VIDEO']);
    const c = await customer();
    const { call } = await s.calls.requestCustomerCall(c.device, { channel: 'VIDEO', topic: 'Mortgage' });
    // The device prepares its offer while it waits; the operator cannot signal before answering.
    assert.equal((await s.calls.deviceSignal(call.callId, c.device, 'offer', offer, '3d3a8c6e-0000-4000-8000-000000000001')).seq, 1);
    await assert.rejects(s.calls.operatorSignal(anna, call.callId, 'answer', offer), /Answer the call/);
    const answered = await s.calls.operatorAnswer(anna, call.callId);
    assert.equal(answered.call.state, 'CONNECTED'); assert.equal(answered.call.operator, 'anna');
    assert.equal((await s.calls.operatorAnswer(anna, call.callId)).call.state, 'CONNECTED'); // a retry
    await assert.rejects(s.calls.operatorAnswer(ben, call.callId), (e) => e.code === 'CALL_NOT_WAITING');
    await assert.rejects(s.calls.operatorSignal(ben, call.callId, 'answer', offer), /Answer the call/);
    assert.ok(!(await s.calls.operatorCallQueue(ben)).some((q) => q.callId === call.callId));
    // The Lua signalling rules apply: the device cannot answer, the operator cannot offer.
    await assert.rejects(s.calls.deviceSignal(call.callId, c.device, 'answer', offer), /may not send/);
    await assert.rejects(s.calls.operatorSignal(anna, call.callId, 'offer', offer), /may not send/);
    await s.calls.operatorSignal(anna, call.callId, 'answer', offer);
    await s.calls.operatorSignal(anna, call.callId, 'candidate', { candidate: 'candidate:1 1 udp 1 192.0.2.1 3478 typ relay' });
    const toOperator = await s.calls.operatorSignals(anna, call.callId, 0, 0);
    assert.deepEqual(toOperator.signals.map((x) => [x.from, x.type]), [['device', 'offer']]);
    const toDevice = await s.calls.deviceSignals(call.callId, c.device, 0, 0);
    assert.deepEqual(toDevice.signals.map((x) => [x.from, x.type]), [['operator', 'answer'], ['operator', 'candidate']]);
    // A repeated messageId is not relayed twice.
    assert.equal((await s.calls.deviceSignal(call.callId, c.device, 'offer', offer, '3d3a8c6e-0000-4000-8000-000000000001')).duplicate, true);

    const ended = await s.calls.operatorEnd(anna, call.callId);
    assert.equal(ended.state, 'ENDED'); assert.equal(ended.endedBy, 'admin:anna'); assert.equal(ended.endReason, 'operator_ended');
    const bye = (await s.calls.deviceSignals(call.callId, c.device, toDevice.next, 0)).signals;
    assert.deepEqual(bye.map((x) => [x.from, x.type]), [['operator', 'bye']]);
    await assert.rejects(s.calls.deviceSignal(call.callId, c.device, 'candidate', {}), (e) => e.code === 'CALL_NOT_OPEN');
    await assert.rejects(s.calls.deviceEnd(call.callId, c.device), (e) => e.code === 'CALL_NOT_OPEN');
    const events = await hooks(call.callId);
    assert.deepEqual(events.map((h) => h.event_type), ['customer_call.requested', 'customer_call.answered', 'customer_call.ended']);
    assert.equal(typeof events[2].payload.durationSeconds, 'number');
    // The database keeps the call as it ended and refuses a deletion.
    await assert.rejects(admin.query(`UPDATE customer_calls SET end_reason = 'x' WHERE call_id = $1`, [call.callId]), /kept as it ended/);
    await assert.rejects(admin.query(`UPDATE customer_calls SET operator = 'ben' WHERE call_id = $1`, [call.callId]), /operator who answered/);
    await assert.rejects(admin.query(`DELETE FROM customer_calls WHERE call_id = $1`, [call.callId]), /kept as records/);
    const audit = await admin.query(`SELECT event_type, actor FROM audit_logs WHERE details->>'callId' = $1 ORDER BY timestamp`, [call.callId]);
    assert.deepEqual(audit.rows.map((r) => r.event_type), ['customer_call_requested', 'customer_call_answered', 'customer_call_ended']);
  });

  test('a call nobody answers ends MISSED and the bank is told; the customer can call again', async () => {
    await enable(['AUDIO']);
    const c = await customer();
    const { call } = await s.calls.requestCustomerCall(c.device, { channel: 'AUDIO', topic: 'Lost card' });
    await admin.query(`UPDATE customer_calls SET expires_at = now() - interval '1 second' WHERE call_id = $1`, [call.callId]);
    assert.ok(await s.calls.expireCustomerCalls() >= 1);
    const missed = await s.calls.bankCall(clientId, call.callId);
    assert.equal(missed.state, 'MISSED'); assert.equal(missed.endReason, 'no_operator_answered');
    await assert.rejects(s.calls.operatorAnswer(anna, call.callId), (e) => e.code === 'CALL_NOT_WAITING');
    const last = (await hooks(call.callId)).at(-1);
    assert.equal(last.event_type, 'customer_call.ended'); assert.equal(last.payload.state, 'MISSED');
    const bye = (await s.calls.deviceSignals(call.callId, c.device, 0, 0)).signals;
    assert.deepEqual(bye.map((x) => [x.from, x.type, x.payload.reason]), [['server', 'bye', 'no_operator_answered']]);
    assert.equal((await s.calls.requestCustomerCall(c.device, { channel: 'AUDIO', topic: 'Lost card' })).call.state, 'WAITING');
  });

  test('the customer cancels while waiting; a device revoked during a call ends it for both', async () => {
    await enable(['AUDIO']);
    const c = await customer();
    const first = (await s.calls.requestCustomerCall(c.device, { channel: 'AUDIO', topic: 'Question' })).call;
    const cancelled = await s.calls.deviceEnd(first.callId, c.device);
    assert.equal(cancelled.state, 'CANCELLED'); assert.equal(cancelled.endReason, 'cancelled');

    const { call } = await s.calls.requestCustomerCall(c.device, { channel: 'AUDIO', topic: 'Question' });
    await s.calls.operatorAnswer(ben, call.callId);
    await s.credentials.revokeCredentialForClient(c.credentialId, clientId, 'lost');
    assert.ok(await s.calls.expireCustomerCalls() >= 1);
    const ended = await s.calls.bankCall(clientId, call.callId);
    assert.equal(ended.state, 'ENDED'); assert.equal(ended.endReason, 'credential_revoked'); assert.equal(ended.endedBy, 'system');
    const toOperator = (await s.calls.operatorSignals(ben, call.callId, 0, 0)).signals;
    assert.deepEqual(toOperator.map((x) => [x.from, x.type, x.payload.reason]), [['server', 'bye', 'credential_revoked']]);
  });
});
