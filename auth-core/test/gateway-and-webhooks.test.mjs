import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadTs } from './support/load-ts.mjs';

const { isDeviceFacingRequest } = loadTs('middleware/mtlsGateway.ts');

test('gateway mTLS exemption covers exactly the device routes', () => {
  const exempt = [
    ['POST', '/v1/mobile/bootstrap'],
    ['GET', '/v1/mobile/authorizations/0b8f4e2c-0000-4000-8000-000000000001'],
    ['POST', '/v1/mobile/authorizations/0b8f4e2c-0000-4000-8000-000000000001/signature'],
    ['POST', '/v1/mobile/authorizations/x/verification-sessions'],
    ['POST', '/v1/recovery/sessions/abc/complete'],
    ['GET', '/v1/mobile/recovery/setup'],
    ['POST', '/v1/mobile/push-registration'],
    ['DELETE', '/v1/mobile/push-registration'],
    ['GET', '/v1/mobile/push-messages/0b8f4e2c-0000-4000-8000-0000000000a1'],
    ['POST', '/v1/push-receipts/0b8f4e2c-0000-4000-8000-0000000000a1'],
  ];
  const protectedRoutes = [
    ['POST', '/v1/mobile/sessions'],
    ['POST', '/v1/mobile/Sessions'], // Express matches routes case-insensitively
    ['POST', '/V1/MOBILE/SESSIONS/'],
    ['POST', '/v1/mobile/unknown'],
    ['GET', '/v1/mobile/'],
    ['POST', '/v1/authorizations'],
    ['POST', '/v1/recovery/sessions'],
    ['GET', '/v1/recovery/sessions/abc/complete'],
    ['POST', '/v1/authorizations/x/verification-sessions/y/complete'],
    ['GET', '/metrics'],
    ['POST', '/v1/push-messages'],
    ['GET', '/v1/push-messages/0b8f4e2c-0000-4000-8000-0000000000a1'],
    ['GET', '/v1/push-receipts/0b8f4e2c-0000-4000-8000-0000000000a1'],
  ];
  for (const [method, path] of exempt) assert.equal(isDeviceFacingRequest({ method, path }), true, `${method} ${path}`);
  for (const [method, path] of protectedRoutes) assert.equal(isDeviceFacingRequest({ method, path }), false, `${method} ${path}`);
});

// The allow-list in mtlsGateway.ts is maintained by hand. This test derives the
// expected set from openapi.yaml so that a new device route cannot ship without
// its exemption (a missing entry blocked offline deferred-signature uploads in
// 2.0.0-rc.2), and so that no bank route is ever exempted by mistake.
// Device-facing = tagged "Mobile SDK" or "Recovery" and authenticated by a
// device-held credential (deviceSignature, bootstrapToken, recoveryToken or the
// push receipt) instead of the default bankAuth.
function operationsFromOpenApi() {
  const operations = [];
  let path = null;
  let current = null;
  for (const line of readFileSync(new URL('../openapi.yaml', import.meta.url), 'utf8').split('\n')) {
    const pathMatch = /^ {2}(\/[^:]+):\s*$/.exec(line);
    if (pathMatch) { path = pathMatch[1]; current = null; continue; }
    if (/^[a-z]/.test(line)) { path = null; current = null; continue; }
    const method = /^ {4}(get|post|put|patch|delete):/.exec(line);
    if (method && path) { current = { method: method[1].toUpperCase(), path, tags: [], security: null }; operations.push(current); continue; }
    if (!current) continue;
    const tags = /^ {6}tags: \[(.*)\]/.exec(line);
    if (tags) current.tags = tags[1].split(',').map((t) => t.trim());
    const security = /^ {6}security: (.*)$/.exec(line);
    if (security) current.security = security[1].trim();
  }
  return operations;
}

test('every device-authenticated route in openapi.yaml is mTLS-exempt, and no bank route is', () => {
  const operations = operationsFromOpenApi();
  assert.ok(operations.length >= 40, 'openapi.yaml parsed');
  const concrete = (path) => path.replace(/\{[^}]+\}/g, '0b8f4e2c-0000-4000-8000-000000000001');
  for (const op of operations) {
    const deviceTag = op.tags.includes('Mobile SDK') || op.tags.includes('Recovery');
    const deviceAuth = op.security !== null && op.security !== '[{ bankAuth: [] }]';
    const expected = deviceTag && deviceAuth;
    assert.equal(isDeviceFacingRequest({ method: op.method, path: concrete(op.path) }), expected,
      `${op.method} ${op.path} (tags ${op.tags.join(',')}, security ${op.security ?? 'default bankAuth'})`);
  }
});

test('webhook destinations: private, reserved and malformed targets are refused', async () => {
  process.env.WEBHOOK_REQUIRE_HTTPS = 'true';
  const { assertWebhookUrlAllowed } = loadTs('services/webhookUrlPolicy.ts');
  const refused = [
    'http://93.184.216.34/hook', // plain HTTP
    'https://user:pass@93.184.216.34/hook', // credentials in URL
    'ftp://93.184.216.34/hook',
    'https://127.0.0.1/hook',
    'https://10.1.2.3/hook',
    'https://172.16.0.1/hook',
    'https://192.168.1.1/hook',
    'https://169.254.169.254/latest/meta-data', // cloud metadata
    'https://100.64.0.1/hook', // carrier-grade NAT
    'https://0.0.0.0/hook',
    'https://[::1]/hook',
    'https://[fd00::1]/hook',
    'https://[::ffff:127.0.0.1]/hook',
    'https://localhost/hook', // resolves to loopback
    'not a url',
  ];
  for (const url of refused) await assert.rejects(assertWebhookUrlAllowed(url), undefined, url);
  const allowed = await assertWebhookUrlAllowed('https://93.184.216.34/hook');
  assert.equal(allowed.address, '93.184.216.34');
  assert.equal(allowed.family, 4);
});

test('IPv6 classification handles every textual form', () => {
  const { isPrivateIpv6 } = loadTs('services/webhookUrlPolicy.ts');
  for (const ip of ['::1', '::', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a00:1', '0:0:0:0:0:ffff:c0a8:101', '64:ff9b::a9fe:a9fe',
    'fd12:3456::1', 'fe80::1%eth0', 'ff02::1', '2001:db8::5', 'fec0::1', 'garbage']) {
    assert.equal(isPrivateIpv6(ip), true, ip);
  }
  for (const ip of ['2606:4700::1111', '2a00:1450:4001:82a::200e', '::ffff:93.184.216.34']) {
    assert.equal(isPrivateIpv6(ip), false, ip);
  }
});

test('webhook delivery connects to the vetted address when Node asks for every address (Node 20+ autoSelectFamily)', async () => {
  const http = await import('node:http');
  const { pinnedLookup } = loadTs('services/webhookService.ts', { stubs: { '../db/pool': { pool: {} }, '../observability/metrics': { webhookDeliveryOutcomes: { inc() {} } } } });
  const server = http.createServer((_req, res) => res.end('ok'));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const status = await new Promise((resolve, reject) => {
      const request = http.request(`http://hooks.bank.example:${server.address().port}/events`, {
        method: 'POST',
        lookup: pinnedLookup({ address: '127.0.0.1', family: 4 }),
      }, (response) => { response.resume(); resolve(response.statusCode); });
      request.on('error', reject);
      request.end('{}');
    });
    assert.equal(status, 200);
  } finally {
    server.close();
  }
});
