// Webhook secret rotation with an overlap (audit finding A2-08): after a
// rotation the previous secret keeps signing deliveries until the overlap
// ends, so the bank can switch its verifier without losing webhooks.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
  '../db/redis': { redis: {} },
};

describe('webhook secret rotation with an overlap (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let clients; let poolModule;
  const clientId = `bank-${randomBytes(4).toString('hex')}`;
  const register = (webhookSecret, webhookSecretOverlapSeconds) => clients.registerBankClient({
    clientId, clientSecret: randomBytes(16).toString('hex'), webhookUrl: 'https://hooks.bank.example/nexus', webhookSecret, webhookSecretOverlapSeconds });

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.WEBHOOK_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    clients = loadTs('services/clientService.ts', { stubs, cache });
    poolModule = loadTs('db/pool.ts', { stubs, cache });
  });
  after(async () => { await poolModule?.pool.end(); await db?.drop(); });

  test('a new client has no previous secret', async () => {
    await register('first-secret');
    const destination = await clients.getWebhookDestination(clientId);
    assert.equal(destination.webhookSecret, 'first-secret');
    assert.equal(destination.previousWebhookSecret, undefined);
  });

  test('after a rotation the previous secret signs too, until the overlap ends', async () => {
    await register('second-secret');
    let destination = await clients.getWebhookDestination(clientId);
    assert.equal(destination.webhookSecret, 'second-secret');
    assert.equal(destination.previousWebhookSecret, 'first-secret');
    const row = (await poolModule.pool.query(`SELECT extract(epoch FROM webhook_secret_previous_until - now())::int AS left FROM bank_clients WHERE client_id = $1`, [clientId])).rows[0];
    assert.ok(row.left > 86_000 && row.left <= 86_400, `default overlap of 24 hours: ${row.left}`);
    // Stored encrypted and bound to the bank, like the current secret.
    const stored = (await poolModule.pool.query(`SELECT webhook_secret_previous_encrypted AS v FROM bank_clients WHERE client_id = $1`, [clientId])).rows[0].v;
    assert.match(stored, /^k1\$/);
    assert.ok(!stored.includes('first-secret'));
    // The overlap ends.
    await poolModule.pool.query(`UPDATE bank_clients SET webhook_secret_previous_until = now() - interval '1 second' WHERE client_id = $1`, [clientId]);
    destination = await clients.getWebhookDestination(clientId);
    assert.equal(destination.previousWebhookSecret, undefined);
  });

  test('a second rotation keeps only the secret it replaces; overlap 0 keeps none', async () => {
    await register('third-secret', 3600);
    assert.equal((await clients.getWebhookDestination(clientId)).previousWebhookSecret, 'second-secret');
    await register('fourth-secret', 0);
    const destination = await clients.getWebhookDestination(clientId);
    assert.equal(destination.webhookSecret, 'fourth-secret');
    assert.equal(destination.previousWebhookSecret, undefined);
    const row = (await poolModule.pool.query(`SELECT webhook_secret_previous_encrypted, webhook_secret_previous_until FROM bank_clients WHERE client_id = $1`, [clientId])).rows[0];
    assert.deepEqual(row, { webhook_secret_previous_encrypted: null, webhook_secret_previous_until: null });
  });

  test('an overlap outside 0 to 7 days is refused', async () => {
    await assert.rejects(register('x', -1), /from 0 to 604800/);
    await assert.rejects(register('x', 604_801), /from 0 to 604800/);
    await assert.rejects(poolModule.pool.query(`UPDATE bank_clients SET webhook_secret_previous_until = now() WHERE client_id = $1`, [clientId]), /bank_clients_webhook_previous_check/);
  });
});
