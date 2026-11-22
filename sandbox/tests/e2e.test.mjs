// End-to-end tests of the running sandbox (sandbox/bin/sandbox up): the real
// Auth Core with SoftHSM, the sandbox bank, its console API and device port.
// Run: node --test sandbox/tests/e2e.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const state = new URL('../.state/', import.meta.url);
const read = (name) => readFileSync(new URL(name, state), 'utf8').trim();
const CONSOLE = `http://127.0.0.1:${process.env.SANDBOX_CONSOLE_PORT ?? 8190}`;
const DEVICE = `http://127.0.0.1:${process.env.SANDBOX_DEVICE_PORT ?? 8191}`;
const basic = `Basic ${Buffer.from(`operator:${read('console-password')}`).toString('base64')}`;

async function api(method, path, body) {
  const r = await fetch(`${CONSOLE}${path}`, { method, headers: { Authorization: basic, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, json: await r.json().catch(() => null) };
}

async function app(method, path, { token, body, headers = {} } = {}) {
  const r = await fetch(`${DEVICE}${path}`, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, json: await r.json().catch(() => null) };
}

test('Auth Core is ready behind the sandbox bank, with the SoftHSM test HSM', async () => {
  const r = await api('GET', '/api/health');
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.match(r.json.hsm, /SoftHSM/);
});

test('the console API requires the console credentials', async () => {
  const r = await fetch(`${CONSOLE}/api/scenarios`);
  assert.equal(r.status, 401);
});

test('the device port forwards device endpoints only: no bank API, no admin console', async () => {
  for (const path of ['/v1/authorizations', '/v1/nexus-identities', '/oauth/token', '/admin/', '/v1/mobile/sessions']) {
    const r = await fetch(`${DEVICE}${path}`, { method: path === '/admin/' ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json' }, body: path === '/admin/' ? undefined : '{}' });
    assert.equal(r.status, 404, `${path} must not be reachable from the device port`);
  }
});

test('bank app: login, accounts, cards, quote, and an order without an enrolled phone is refused', async () => {
  assert.equal((await app('POST', '/app/v1/session', { body: { login: 'anna', password: 'wrong' } })).status, 401);
  const login = await app('POST', '/app/v1/session', { body: { login: 'anna', password: read('customer-password') } });
  assert.equal(login.status, 200);
  const token = login.json.token;
  const accounts = await app('GET', '/app/v1/accounts', { token });
  assert.equal(accounts.status, 200);
  assert.ok(accounts.json.length >= 1);
  assert.equal((await app('GET', '/app/v1/cards', { token })).status, 200);
  const quote = await app('POST', '/app/v1/transactions/quote', { token, body: { sourceAccountId: accounts.json[0].id, beneficiaryName: 'Ион Попеску', beneficiaryIban: 'MD28AG000000022589630417', amountMinor: 10000 } });
  assert.equal(quote.status, 200);
  assert.equal(quote.json.totalMinor, 10000 + quote.json.feeMinor);
  const order = await app('POST', '/app/v1/transactions', { token, headers: { 'Idempotency-Key': randomUUID() }, body: { sourceAccountId: accounts.json[0].id, beneficiaryName: 'Ион Попеску', beneficiaryIban: 'MD28AG000000022589630417', amountMinor: 10000 } });
  if (!login.json.customer.deviceEnrolled) assert.equal(order.json.code, 'DEVICE_NOT_ENROLLED');
});

test('every available demonstration scenario passes against the real Auth Core', { timeout: 15 * 60_000 }, async () => {
  const list = await api('GET', '/api/scenarios');
  assert.equal(list.status, 200);
  const results = [];
  for (const scenario of list.json.filter((s) => s.available)) {
    const started = await api('POST', `/api/scenarios/${scenario.id}/run`);
    assert.equal(started.status, 202, `${scenario.id}: ${JSON.stringify(started.json)}`);
    let run;
    for (let i = 0; i < 180; i++) {
      run = (await api('GET', `/api/scenarios/runs/${started.json.runId}`)).json;
      if (run.state !== 'RUNNING') break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    results.push({ id: scenario.id, state: run.state, actual: run.actual, steps: run.steps.map((s) => s.text) });
  }
  const failed = results.filter((r) => r.state !== 'PASSED');
  for (const r of results) console.log(`${r.state.padEnd(8)} ${r.id}`);
  assert.deepEqual(failed, [], JSON.stringify(failed, null, 2));
});

test('the ledger balances after all scenarios', async () => {
  const r = await api('GET', '/api/ledger/check');
  assert.deepEqual(r.json, { total: 0, mismatchedAccounts: 0, ok: true });
});
