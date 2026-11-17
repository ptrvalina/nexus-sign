// With METRICS_BEARER_TOKEN, /metrics answers only the monitoring
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
    const text = await ok.text();
    assert.match(text, /# HELP/);
    // Confirmation and outcome counters and the unsealed backlog are exported (the HSM gauges only with HSM_ADAPTER=pkcs11).
    for (const name of ['nexus_authorization_confirmations_total', 'nexus_sealed_outcomes_total', 'nexus_evidence_unsealed_outcomes']) {
      assert.match(text, new RegExp(`# HELP ${name} `), name);
    }
  });
});
