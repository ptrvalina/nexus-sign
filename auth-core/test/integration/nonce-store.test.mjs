// A used device request nonce is refused even after Redis loses its
// data (failover to an asynchronous replica, restore from a snapshot). With
// DEVICE_NONCE_STORE=postgres (default) PostgreSQL remembers nonces; the
// expiry sweep deletes them after their lifetime. The redis store, kept for
// comparison, forgets them: that is why production refuses it.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceHeaders } from './support/actors.mjs';

const require = createRequire(import.meta.url);

describe('device request nonce store', { skip: skipWithoutServices }, () => {
  const servers = [];
  after(async () => { for (const s of servers) await s.stop(); });

  async function setup(env) {
    const server = await startAuthCore({ env: { AUTHORIZATION_EXPIRY_SWEEP_MS: '500', ...env } });
    servers.push(server);
    const bank = await bankSession(server, await server.registerBank(`bank-nonce-${servers.length}`));
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const auth = await bank.createAuthorization(device);
    const path = `/v1/mobile/authorizations/${auth.authorizationId}`;
    const headers = deviceHeaders(device, 'GET', path, '');
    const send = () => fetch(`${server.baseUrl}${path}`, { headers });
    const Redis = require('ioredis');
    const redis = new Redis(server.env.REDIS_URL, { maxRetriesPerRequest: 1 });
    const loseRedis = async () => { await redis.flushdb(); };
    return { server, device, headers, send, loseRedis, close: () => redis.disconnect() };
  }

  test('postgres store: a replay is refused after Redis loses its data', async () => {
    const t = await setup({});
    try {
      assert.equal((await t.send()).status, 200);
      await t.loseRedis();
      const replay = await t.send();
      assert.equal(replay.status, 401);
      assert.match((await replay.json()).error, /nonce has already been used/);
      const rows = await t.server.db.query(`SELECT expires_at > now() AS live FROM device_request_nonces WHERE credential_id = $1 AND nonce = $2`, [t.device.credentialId, t.headers['X-NEXUS-Nonce']]);
      assert.equal(rows.rows[0]?.live, true);
    } finally { t.close(); }
  });

  test('postgres store: expired nonces are deleted by the sweep', async () => {
    const t = await setup({});
    try {
      assert.equal((await t.send()).status, 200);
      await t.server.db.query(`UPDATE device_request_nonces SET expires_at = now() - interval '1 second' WHERE credential_id = $1`, [t.device.credentialId]);
      let left = 1;
      for (let i = 0; i < 60 && left > 0; i += 1) {
        await new Promise((r) => setTimeout(r, 100));
        left = (await t.server.db.query(`SELECT count(*)::int AS n FROM device_request_nonces WHERE credential_id = $1`, [t.device.credentialId])).rows[0].n;
      }
      assert.equal(left, 0);
    } finally { t.close(); }
  });

  test('redis store (not allowed in production): the same replay is accepted after the data loss', async () => {
    const t = await setup({ DEVICE_NONCE_STORE: 'redis' });
    try {
      assert.equal((await t.send()).status, 200);
      assert.equal((await t.send()).status, 401, 'refused while Redis remembers');
      await t.loseRedis();
      assert.equal((await t.send()).status, 200, 'the weakness DEVICE_NONCE_STORE=postgres removes');
    } finally { t.close(); }
  });
});
