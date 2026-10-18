// FI-030: with METRICS_BEARER_TOKEN, /metrics answers only the monitoring
// system, not every client that passes the gateway check.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';

describe('metrics access', { skip: skipWithoutServices }, () => {
  const token = 'monitoring-token-for-tests-0123456789';
  let server;
  before(async () => { server = await startAuthCore({ env: { METRICS_BEARER_TOKEN: token } }); });
  after(async () => { await server?.stop(); });

  test('without or with a wrong token: 401; with the token: metrics', async () => {
    assert.equal((await fetch(`${server.baseUrl}/metrics`)).status, 401);
    assert.equal((await fetch(`${server.baseUrl}/metrics`, { headers: { Authorization: `Bearer ${token}x` } })).status, 401);
    const ok = await fetch(`${server.baseUrl}/metrics`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(ok.status, 200);
    assert.match(await ok.text(), /# HELP/);
  });
});
