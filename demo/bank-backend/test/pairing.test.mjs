// FI-016: the demo bank's app routes need the pairing code shown on the
// operator page. Auth Core is replaced by a minimal stand-in that answers the
// three calls the demo bank makes; the test is about the demo bank's own
// access control, not about Auth Core.
//
//   node --test demo/bank-backend/test/pairing.test.mjs
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEMO = join(dirname(fileURLToPath(import.meta.url)), '..', 'demo-bank.mjs');
const freePort = () => new Promise((resolve) => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });

let authCore; let demo; let output = ''; let devicePort; let operatorPort; const issued = [];

before(async () => {
  authCore = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      if (req.url === '/oauth/token') return res.end(JSON.stringify({ access_token: 'bank-token', expires_in: 3600 }));
      if (req.url === '/v1/nexus-identities') { res.statusCode = 201; return res.end(JSON.stringify({ nexusId: '123456789' })); }
      if (req.url === '/v1/mobile/sessions') { issued.push(JSON.parse(body)); res.statusCode = 201; return res.end(JSON.stringify({ accessToken: `ms_${issued.length}` })); }
      res.statusCode = 404; res.end('{}');
    });
  });
  await new Promise((r) => authCore.listen(0, '127.0.0.1', r));
  [devicePort, operatorPort] = [await freePort(), await freePort()];
  demo = spawn(process.execPath, [DEMO], {
    env: { PATH: process.env.PATH, AUTH_CORE_URL: `http://127.0.0.1:${authCore.address().port}`, CLIENT_ID: 'demo', CLIENT_SECRET: 'x',
      DEMO_BANK_PORT: String(operatorPort), DEMO_DEVICE_PORT: String(devicePort) },
  });
  demo.stdout.on('data', (d) => { output += d; });
  demo.stderr.on('data', (d) => { output += d; });
  for (let i = 0; i < 100 && !/pairing code for the demo app/.test(output); i += 1) await new Promise((r) => setTimeout(r, 50));
  assert.match(output, /pairing code for the demo app: \d{4} \d{4}/, output);
});
after(() => { demo?.kill(); authCore?.close(); });

// The newest code the demo bank printed (it prints a new one after a rotation).
const code = () => [...output.matchAll(/pairing code(?: for the demo app:)? (\d{4}) (\d{4})/g)].at(-1).slice(1).join('');
const ask = (headers = {}) => fetch(`http://127.0.0.1:${devicePort}/app/bootstrap-token`, { method: 'POST', headers });

test('without the pairing code no enrolment token is issued', async () => {
  const response = await ask();
  assert.equal(response.status, 401);
  assert.equal(issued.length, 0);
  for (const path of ['/app/pending', '/app/registered']) {
    const r = await fetch(`http://127.0.0.1:${devicePort}${path}`, { method: path === '/app/pending' ? 'GET' : 'POST', body: path === '/app/pending' ? undefined : '{}' });
    assert.equal(r.status, 401, path);
  }
});

test('a wrong pairing code is refused', async () => {
  const wrong = String((Number(code()) + 1) % 100_000_000).padStart(8, '0');
  assert.equal((await ask({ 'X-Demo-Pairing-Code': wrong })).status, 401);
  assert.equal(issued.length, 0);
});

test('the pairing code from the operator page gives a token', async () => {
  const response = await ask({ 'X-Demo-Pairing-Code': code() });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).token, 'ms_1');
});

test('the operator page shows the pairing code', async () => {
  const html = await (await fetch(`http://127.0.0.1:${operatorPort}/`)).text();
  assert.ok(html.includes(`${code().slice(0, 4)} ${code().slice(4)}`));
});

test('ten wrong codes replace the pairing code', async () => {
  const before = code();
  for (let i = 0; i < 10; i += 1) await ask({ 'X-Demo-Pairing-Code': '00000000' === before ? '11111111' : '00000000' });
  await new Promise((r) => setTimeout(r, 50));
  assert.notEqual(code(), before);
  assert.equal((await ask({ 'X-Demo-Pairing-Code': before })).status, 401, 'the old code no longer works');
});
