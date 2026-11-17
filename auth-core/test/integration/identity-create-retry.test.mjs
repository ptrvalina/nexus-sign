// Creating a NEXUS ID is safe to retry (audit finding A1-04), on PostgreSQL.
// Before the fix a retry after a lost response got 409 with no NEXUS ID, and
// the bank could neither learn the ID nor create another for that customer.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
};

describe('NEXUS ID creation retry (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s;
  const bankA = `bank-${randomBytes(4).toString('hex')}`;
  const bankB = `bank-${randomBytes(4).toString('hex')}`;

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    s = { identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }), db: loadTs('db/pool.ts', { stubs, cache }) };
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    for (const id of [bankA, bankB]) await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ($1, 'x')`, [id]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  test('a retry returns the same NEXUS ID; another bank with the same reference gets its own', async () => {
    const first = await s.identities.createNexusIdentity(bankA, 'customer-42');
    const retry = await s.identities.createNexusIdentity(bankA, 'customer-42');
    assert.equal(first.replayed, false);
    assert.equal(retry.replayed, true);
    assert.equal(retry.nexusId, first.nexusId);
    const other = await s.identities.createNexusIdentity(bankB, 'customer-42');
    assert.equal(other.replayed, false);
    assert.notEqual(other.nexusId, first.nexusId);
    const created = await admin.query(`SELECT count(*)::int AS n FROM audit_logs WHERE nexus_id = $1 AND event_type = 'identity_created'`, [first.nexusId]);
    assert.equal(created.rows[0].n, 1, 'the retry is not audited as a second creation');
  });

  test('concurrent creates for one reference end with one identity', async () => {
    const results = await Promise.all(Array.from({ length: 8 }, () => s.identities.createNexusIdentity(bankA, 'customer-race')));
    assert.equal(new Set(results.map((r) => r.nexusId)).size, 1);
    assert.equal(results.filter((r) => !r.replayed).length, 1);
  });

  test('after the identity is revoked a new one is created', async () => {
    const first = await s.identities.createNexusIdentity(bankA, 'customer-revoked');
    await admin.query(`UPDATE nexus_identities SET status = 'REVOKED' WHERE nexus_id = $1`, [first.nexusId]);
    const next = await s.identities.createNexusIdentity(bankA, 'customer-revoked');
    assert.equal(next.replayed, false);
    assert.notEqual(next.nexusId, first.nexusId);
  });
});
