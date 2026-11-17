// Regression tests for LOW findings fixed in 2.0.0-rc.1 that need no
// database: (canonicalizer, see property-fuzz.test.mjs), 
// .
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { loadTs } from './support/load-ts.mjs';

const key = randomBytes(32).toString('base64');
const envStub = (overrides = {}) => ({ '../config/env': { env: { WEBHOOK_SECRET_ENCRYPTION_KEY: key, DEVICE_SECRET_ENCRYPTION_KEY: key, NODE_ENV: 'test', ...overrides } } });

test('A device nonce outlives the whole timestamp window', () => {
  const { deviceNonceTtlSeconds } = loadTs('middleware/mobileAuth.ts', {
    stubs: { '../db/redis': { redis: {} }, '../db/pool': { pool: {} }, '../config/env': { env: {} } },
  });
  for (const skew of [30, 300, 900]) {
    // First seen at T - skew, still acceptable at T + skew (+1 s rounding).
    assert.ok(deviceNonceTtlSeconds(skew) > 2 * skew + 1, String(skew));
  }
});

test('A webhook secret is bound to its bank client; 1.4 ciphertexts still decrypt', () => {
  const { encryptSecret, decryptSecret } = loadTs('crypto/secretBox.ts', { stubs: envStub() });
  const stored = encryptSecret('whsec-bank-a', 'webhook', 'bank-a');
  // 2.0.0: the ciphertext names its master key; still bound to the client.
  assert.match(stored, /^k1\$[0-9a-f]{16}\$/);
  assert.equal(decryptSecret(stored, 'webhook', 'bank-a'), 'whsec-bank-a');
  assert.throws(() => decryptSecret(stored, 'webhook', 'bank-b'), 'copied to another bank\'s row');
  assert.throws(() => encryptSecret('x', 'webhook'), /bound to their bank client/);

  // 1.4 format: iv$tag$ciphertext without associated data.
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key, 'base64'), iv);
  const ct = Buffer.concat([cipher.update('legacy-secret'), cipher.final()]);
  const legacy = [iv.toString('base64'), cipher.getAuthTag().toString('base64'), ct.toString('base64')].join('$');
  assert.equal(decryptSecret(legacy, 'webhook', 'bank-a'), 'legacy-secret');
});

test('Production refuses an APNs DEVELOPMENT registration', async () => {
  const load = (NODE_ENV) => loadTs('services/pushRegistrationService.ts', {
    stubs: {
      ...envStub({ NODE_ENV }),
      '../db/pool': { pool: { query: async () => { throw new Error('reached the database'); } }, withTransaction: async () => { throw new Error('reached the database'); } },
      './clientService': { getClientPushMode: async () => 'NEXUS' },
    },
  });
  const device = { credentialId: '00000000-0000-4000-8000-000000000002', clientId: 'bank', nexusId: '123456789', platform: 'IOS' };
  const input = { provider: 'APNS', apnsEnvironment: 'DEVELOPMENT', deviceToken: 'a'.repeat(64), keyId: 'AAAAAAAAAAAAAAAAAAAAAA' };
  await assert.rejects(load('production').registerPushDevice(device, input), /DEVELOPMENT is not accepted in production/);
  // Outside production the request gets past validation (and stops at the stubbed database).
  await assert.rejects(load('development').registerPushDevice(device, input), (error) => !/DEVELOPMENT/.test(error.message));
});

test('A failed ROLLBACK keeps the original error and destroys the connection (A1-08)', async () => {
  const { withTransaction } = loadTs('db/pool.ts', { stubs: { pg: { Pool: class { connect() {} } }, ...envStub() } });
  const fakeSource = (rollbackFails) => {
    const released = [];
    const client = {
      async query(sql) { if (sql === 'ROLLBACK' && rollbackFails) throw new Error('connection terminated'); },
      release(error) { released.push(error); },
    };
    return { released, source: { connect: async () => client } };
  };
  const work = async () => { throw new Error('unique violation'); };

  const broken = fakeSource(true);
  await assert.rejects(withTransaction(work, broken.source), /unique violation/);
  assert.equal(broken.released.length, 1);
  assert.match(String(broken.released[0]), /connection terminated/, 'the client is released with the error, so pg destroys it');

  const healthy = fakeSource(false);
  await assert.rejects(withTransaction(work, healthy.source), /unique violation/);
  assert.deepEqual(healthy.released, [undefined], 'after a clean rollback the client goes back to the pool');

  assert.equal(await withTransaction(async () => 42, fakeSource(false).source), 42);
});

test('A security event that cannot be audited is written to the log instead of vanishing (A2-10)', async () => {
  const failingPool = { pool: { query: async () => { throw new Error('database unavailable'); } } };
  const { recordSecurityEvent } = loadTs('services/auditService.ts', { stubs: { '../db/pool': failingPool, './requestContext': { currentRequestContext: () => undefined } } });
  const lines = [];
  await recordSecurityEvent('integrity_violation', { nexusId: '123456789' }, { reason: 'test' }, (line) => lines.push(line));
  assert.equal(lines.length, 1);
  const entry = JSON.parse(lines[0]);
  assert.equal(entry.level, 50);
  assert.equal(entry.eventType, 'integrity_violation');
  assert.equal(entry.context.nexusId, '123456789');
  assert.equal(entry.err, 'database unavailable');

  const okPool = { pool: { query: async () => ({ rows: [], rowCount: 1 }) } };
  const ok = loadTs('services/auditService.ts', { stubs: { '../db/pool': okPool, './requestContext': { currentRequestContext: () => undefined } } });
  const none = [];
  await ok.recordSecurityEvent('integrity_violation', {}, {}, (line) => none.push(line));
  assert.deepEqual(none, [], 'nothing is logged when the audit row is written');
});

test('pre-2.0 unbound webhook secrets stop a production start and warn elsewhere (B-11)', async () => {
  const { countUnboundWebhookSecrets, unboundWebhookSecretsProblem } = loadTs('config/legacySecrets.ts');
  assert.equal(unboundWebhookSecretsProblem(0, 'production'), null);
  assert.equal(unboundWebhookSecretsProblem(2, 'production').refuse, true);
  assert.match(unboundWebhookSecretsProblem(2, 'production').message, /rotateSecretKeys\.js webhook/);
  assert.equal(unboundWebhookSecretsProblem(2, 'development').refuse, false);
  let sql = '';
  const count = await countUnboundWebhookSecrets({ query: async (text) => { sql = text; return { rows: [{ n: 3 }] }; } });
  assert.equal(count, 3);
  assert.match(sql, /NOT LIKE 'k1\$%' AND webhook_secret_encrypted NOT LIKE 'v2\$%'/);
});

test('A webhook signed during a secret overlap verifies with either secret (finding A2-08)', async () => {
  const { createHmac } = await import('node:crypto');
  const { webhookSignatureHeader } = loadTs('services/webhookService.ts', { stubs: { '../db/pool': { pool: {} }, '../observability/metrics': { webhookDeliveryOutcomes: { inc() {} } } } });
  const { webhookSignatureMatches, createAuthCoreWebhookHandler } = await import('../../bank-integration/webhookHandler.mjs');
  const hmac = (secret, ts, body) => `v1=${createHmac('sha256', secret).update(`${ts}.${body}`, 'utf8').digest('hex')}`;
  const ts = '1763300000'; const body = '{"eventType":"identity.created"}';
  // Without a previous secret: one entry, as before.
  assert.equal(webhookSignatureHeader(ts, body, 'new-secret'), hmac('new-secret', ts, body));
  // During the overlap: the previous secret's entry first, then the new one.
  const header = webhookSignatureHeader(ts, body, 'new-secret', 'old-secret');
  assert.equal(header, `${hmac('old-secret', ts, body)},${hmac('new-secret', ts, body)}`);
  assert.equal(webhookSignatureMatches(header, ts, body, ['old-secret']), true, 'a bank that has not switched yet');
  assert.equal(webhookSignatureMatches(header, ts, body, ['new-secret']), true, 'a bank that has switched');
  assert.equal(webhookSignatureMatches(header, ts, body, ['other']), false);
  assert.equal(webhookSignatureMatches(header, ts, `${body} `, ['new-secret']), false, 'another body');
  assert.equal(webhookSignatureMatches(`${hmac('other', ts, body)},v1=00`, ts, body, ['new-secret']), false);
  // The reference handler accepts the overlap header with either secret, or both.
  const handlerFor = (secret) => createAuthCoreWebhookHandler({ secret, store: { paymentForAuthorization: async () => null }, boundary: {}, now: () => Number(ts) * 1000 });
  const request = { headers: { 'X-NEXUS-SIGN-Timestamp': ts, 'X-NEXUS-SIGN-Signature': header }, rawBody: body };
  for (const secret of ['old-secret', 'new-secret', ['new-secret', 'old-secret']]) assert.equal((await handlerFor(secret)(request)).status, 204, String(secret));
  assert.equal((await handlerFor('other')(request)).status, 401);
});
