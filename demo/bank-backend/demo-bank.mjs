#!/usr/bin/env node
// Demo bank backend for the Android and iOS demo apps. It plays the part of a
// bank's own backend: it holds the bank's OAuth client credentials, creates
// the customer's NEXUS ID, issues BOOTSTRAP tokens to the app, and creates
// payment authorizations from a small operator page. Development only; it
// listens on 127.0.0.1 and keeps its state in memory.
//
//   node demo/bank-backend/demo-bank.mjs           # device port over HTTP (Android, adb reverse)
//   node demo/bank-backend/demo-bank.mjs --https   # device port over HTTPS (iPhone on the same Wi-Fi),
//        with the certificate from demo/bank-backend/make-cert.sh
//
// Two listeners, both on 127.0.0.1:
//   8090  operator page (send a payment, see its status, the evidence chain)
//   8091  device port, for the phone only: the demo app's /app/* calls and the
//         Auth Core endpoints a device calls (/v1/mobile/*, recovery completion,
//         push receipts), forwarded byte for byte. The bank API and the admin
//         console are not reachable here, so this port can be exposed to the
//         phone through adb reverse or an HTTPS tunnel.
//
// Settings (environment): AUTH_CORE_URL (default http://127.0.0.1:8080),
// DEMO_BANK_PORT (8090), DEMO_DEVICE_PORT (8091), DEMO_DEVICE_HOST (127.0.0.1),
// CLIENT_ID and CLIENT_SECRET
// (default: read from ~/nexus-local-credentials.txt, written by
// auth-core/scripts/run-local.sh).
import { createServer, request as httpRequest } from 'node:http';
import { paymentStatus } from './status.mjs';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const AUTH_CORE = (process.env.AUTH_CORE_URL ?? 'http://127.0.0.1:8080').replace(/\/$/, '');
const PORT = Number(process.env.DEMO_BANK_PORT ?? 8090);
const DEVICE_PORT = Number(process.env.DEMO_DEVICE_PORT ?? 8091);
const DEVICE_HOST = process.env.DEMO_DEVICE_HOST ?? '127.0.0.1';
const DEVICE_HTTPS = process.argv.includes('--https');
const TLS_DIR = join(dirname(fileURLToPath(import.meta.url)), 'tls');
const credentialsFile = process.env.CREDENTIALS_FILE ?? join(homedir(), 'nexus-local-credentials.txt');

function fromCredentialsFile(pattern) {
  try { return readFileSync(credentialsFile, 'utf8').match(pattern)?.[1]; } catch { return undefined; }
}
const CLIENT_ID = process.env.CLIENT_ID ?? fromCredentialsFile(/^Bank client:\s+(\S+)/m) ?? 'local-bank';
const CLIENT_SECRET = process.env.CLIENT_SECRET ?? fromCredentialsFile(/client_secret:\s+(\S+)/);
if (!CLIENT_SECRET) {
  console.error(`No client secret: set CLIENT_SECRET, or start Auth Core with auth-core/scripts/run-local.sh (it writes ${credentialsFile}).`);
  process.exit(2);
}

// Pairing code. The device port can be reachable from the whole
// Wi-Fi network, and /app/bootstrap-token hands out enrolment and replacement
// tokens. The app must send the code shown on the operator page; it changes on
// every start and after too many wrong attempts.
const PAIRING_HEADER = 'x-demo-pairing-code';
const MAX_PAIRING_FAILURES = 10;
let pairingCode = newPairingCode();
let pairingFailures = 0;
function newPairingCode() { return String(randomInt(0, 100_000_000)).padStart(8, '0'); }
function displayPairingCode() { return `${pairingCode.slice(0, 4)} ${pairingCode.slice(4)}`; }
function checkPairingCode(req) {
  const given = Buffer.from(String(req.headers[PAIRING_HEADER] ?? '').replace(/\D/g, ''), 'utf8');
  const expected = Buffer.from(pairingCode, 'utf8');
  if (given.length === expected.length && timingSafeEqual(given, expected)) return;
  pairingFailures += 1;
  if (pairingFailures >= MAX_PAIRING_FAILURES) {
    pairingCode = newPairingCode();
    pairingFailures = 0;
    log(`too many wrong pairing codes: new pairing code ${displayPairingCode()}`);
  }
  throw new HttpError(401, 'Pairing code missing or wrong: enter the code shown on the demo bank page');
}

// One demo customer, enrolled from the phone.
const customer = { nexusId: null, credentialId: null };
const payments = []; // { authorizationId, reference, amountMinor, currency, beneficiary, createdAt }
const log = (message) => console.log(`${new Date().toISOString().slice(11, 19)}  ${message}`);

let bankToken = null;
let bankTokenExpiresAt = 0;
async function token() {
  if (bankToken && Date.now() < bankTokenExpiresAt - 60_000) return bankToken;
  const response = await fetch(`${AUTH_CORE}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET }),
  });
  const json = await response.json().catch(() => ({}));
  if (response.status !== 200 || !json.access_token) throw new Error(`OAuth token refused (${response.status}): ${JSON.stringify(json)}`);
  bankToken = json.access_token;
  bankTokenExpiresAt = Date.now() + (json.expires_in ?? 3600) * 1000;
  return bankToken;
}

async function authCore(method, path, body, headers = {}) {
  const response = await fetch(`${AUTH_CORE}${path}`, {
    method,
    headers: { Authorization: `Bearer ${await token()}`, ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  return { status: response.status, json, text };
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// --- Called by the demo app -------------------------------------------------

/** A BOOTSTRAP token for the demo customer; creates the NEXUS ID on first use.
 * A phone that enrols again (reinstalled app) gets a replacement token, as a
 * bank would issue after re-identifying the customer. */
async function bootstrapToken() {
  if (!customer.nexusId) {
    const identity = await authCore('POST', '/v1/nexus-identities', { bankCustomerRef: `demo-customer-${randomBytes(3).toString('hex')}` });
    if (identity.status !== 201) throw new HttpError(502, `NEXUS ID not created: ${identity.text}`);
    customer.nexusId = identity.json.nexusId;
    customer.credentialId = null;
    log(`NEXUS ID ${customer.nexusId} created for the demo customer`);
  }
  let session = await authCore('POST', '/v1/mobile/sessions', { nexusId: customer.nexusId });
  if (session.status === 409 && session.json?.code === 'ACTIVE_CREDENTIAL_EXISTS') {
    session = await authCore('POST', '/v1/mobile/sessions', {
      nexusId: customer.nexusId,
      replacement: { method: 'OTHER', reference: `demo-reenrolment-${randomBytes(4).toString('hex')}` },
    });
    log('the phone enrols again: replacement BOOTSTRAP token issued');
  }
  if (session.status !== 201) throw new HttpError(502, `BOOTSTRAP token not issued: ${session.text}`);
  log(`BOOTSTRAP token issued for NEXUS ID ${customer.nexusId}`);
  return { token: session.json.accessToken, nexusId: customer.nexusId };
}

/** The newest payment still waiting for the customer. */
async function pending() {
  for (const payment of [...payments].reverse()) {
    const current = await authCore('GET', `/v1/authorizations/${payment.authorizationId}`);
    if (current.status === 200 && current.json.state === 'PENDING_USER' && new Date(current.json.expiresAt) > new Date()) {
      return { authorizationId: payment.authorizationId, call: payment.call ?? null };
    }
  }
  return {};
}

// --- Operator page ----------------------------------------------------------

// Verification calls (ADR 0017): the payment can require an AUDIO or VIDEO
// call with a bank operator (admin console, Verification calls) before the
// customer signs. Needs operator verification enabled for the bank:
//   node dist/cli/verificationSetup.js operator local-bank AUDIO,VIDEO
const CALL_POLICIES = {
  VIDEO: { requireVideo: true, audioAvailable: false },
  AUDIO: { requireAudio: true, videoAvailable: false },
};

async function createPayment({ amount, currency, name, iban, call }) {
  if (!customer.credentialId) throw new HttpError(409, 'Сначала зарегистрируйте телефон в демо-приложении.');
  const amountMinor = Math.round(Number(String(amount).replace(',', '.')) * 100);
  if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) throw new HttpError(400, 'Сумма должна быть положительным числом.');
  const reference = `DEMO-${Date.now().toString(36).toUpperCase()}`;
  const beneficiary = { name: String(name).trim(), iban: String(iban).replace(/\s+/g, '').toUpperCase() };
  const created = await authCore('POST', '/v1/authorizations', {
    nexusId: customer.nexusId, credentialId: customer.credentialId, transactionReference: reference,
    operationType: 'transfer', amountMinor: String(amountMinor), currency: String(currency).toUpperCase(), beneficiary,
    policyReference: 'TRANSFER-DEFAULT', policyVersion: '2026-09',
    ...(CALL_POLICIES[call] ? { verificationPolicy: CALL_POLICIES[call] } : {}),
  }, { 'Idempotency-Key': randomUUID() });
  if (created.status !== 201) throw new HttpError(created.status, `Authorization not created: ${created.text}`);
  payments.push({ authorizationId: created.json.authorizationId, reference, amountMinor, currency: String(currency).toUpperCase(), beneficiary, call: CALL_POLICIES[call] ? call : null, createdAt: new Date() });
  log(`payment ${reference} (${(amountMinor / 100).toFixed(2)} ${currency}) waiting for the customer`);
  return created.json;
}

async function paymentRows() {
  const rows = [];
  for (const payment of [...payments].reverse()) {
    const current = await authCore('GET', `/v1/authorizations/${payment.authorizationId}`);
    rows.push({ ...payment, status: paymentStatus(current.json, current.status), confirmationMethod: current.json?.confirmationMethod ?? null });
  }
  return rows;
}

const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function page(message = '') {
  const rows = await paymentRows();
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Демо-банк</title>
<meta http-equiv="refresh" content="5; url=/">
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#1d2b3f}
h1{font-size:22px}fieldset{border:1px solid #cdd8e6;border-radius:8px;padding:12px 16px;margin:16px 0}
label{display:inline-block;margin:6px 12px 6px 0}input{padding:6px 8px;border:1px solid #b9c7d8;border-radius:6px}
button{padding:8px 16px;border:0;border-radius:6px;background:#1f6feb;color:#fff;font-weight:600;cursor:pointer}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e3eaf3}
.ok{color:#127a3e;font-weight:600}.wait{color:#9a6700;font-weight:600}.bad{color:#b42318;font-weight:600}.msg{padding:8px 12px;border-radius:6px;background:#fff4d6}</style></head><body>
<h1>Демо-банк · оператор</h1>
<p>Код сопряжения для демо-приложения: <b style="font-size:20px;letter-spacing:2px">${displayPairingCode()}</b></p>
<p>Auth Core: <code>${escape(AUTH_CORE)}</code> · банк <code>${escape(CLIENT_ID)}</code><br>
Клиент: ${customer.nexusId ? `NEXUS ID <b>${escape(customer.nexusId)}</b>, ${customer.credentialId ? `телефон зарегистрирован (<code>${escape(customer.credentialId)}</code>)` : 'телефон ещё не зарегистрирован'}` : 'ещё не зарегистрирован: откройте демо-приложение и нажмите «Зарегистрировать телефон»'}</p>
${message ? `<p class="msg">${escape(message)}</p>` : ''}
<form method="post" action="/ops/payments"><fieldset><legend>Новый платёж клиенту на подтверждение</legend>
<label>Сумма <input name="amount" value="1250.00" size="10"></label>
<label>Валюта <input name="currency" value="PLN" size="4"></label>
<label>Получатель <input name="name" value="Jan Kowalski" size="22"></label>
<label>IBAN <input name="iban" value="PL61109010140000071219812874" size="32"></label>
<label>Проверка <select name="call"><option value="">только подпись</option><option value="VIDEO">видеозвонок с сотрудником</option><option value="AUDIO">аудиозвонок с сотрудником</option></select></label>
<button type="submit">Отправить на подтверждение</button></fieldset></form>
<table><tr><th>Создан</th><th>Референс</th><th>Сумма</th><th>Получатель</th><th>Статус</th></tr>
${rows.map((r) => `<tr><td>${r.createdAt.toLocaleTimeString('ru-RU')}</td><td><code>${escape(r.reference)}</code></td><td>${(r.amountMinor / 100).toFixed(2)} ${escape(r.currency)}</td><td>${escape(r.beneficiary.name)}<br><small>${escape(r.beneficiary.iban)}</small></td><td class="${r.status.css}">${escape(r.status.label)}${r.confirmationMethod ? `<br><small>${escape(r.confirmationMethod)}</small>` : ''}</td></tr>`).join('') || '<tr><td colspan="5">Платежей пока нет.</td></tr>'}
</table>
<p><small>Статус — это ответ Auth Core, а не основание для исполнения. Демо-банк ничего не исполняет; настоящий банк исполняет платёж только через свою границу исполнения (<code>bank-integration/</code>) с собственной проверкой доверия.</small></p>
${customer.nexusId ? `<p><a href="/ops/evidence">Цепочка доказательств клиента (JSON)</a></p>` : ''}
<p><small>Страница обновляется каждые 5 секунд.</small></p></body></html>`;
}

// --- HTTP -------------------------------------------------------------------

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 16_384) throw new HttpError(413, 'Body too large');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if ((req.headers['content-type'] ?? '').includes('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(raw));
  return raw ? JSON.parse(raw) : {};
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

/** The demo app's calls to its bank. Answers true when the request was one of them. */
async function appRoutes(req, res, pathname) {
  if (!pathname.startsWith('/app/')) return false;
  checkPairingCode(req);
  if (req.method === 'POST' && pathname === '/app/bootstrap-token') { send(res, 200, await bootstrapToken()); return true; }
  if (req.method === 'POST' && pathname === '/app/registered') {
    const { credentialId } = await readBody(req);
    if (typeof credentialId !== 'string' || !/^[0-9a-f-]{36}$/i.test(credentialId)) throw new HttpError(400, 'credentialId required');
    customer.credentialId = credentialId;
    log(`the phone is enrolled: credential ${credentialId}`);
    send(res, 200, { nexusId: customer.nexusId, credentialId });
    return true;
  }
  if (req.method === 'GET' && pathname === '/app/pending') { send(res, 200, await pending()); return true; }
  return false;
}

function handle(routes) {
  return async (req, res) => {
    const { pathname } = new URL(req.url, 'http://localhost');
    try {
      if (!(await routes(req, res, pathname))) send(res, 404, { error: 'not found' });
    } catch (error) {
      log(`error: ${error.message}`);
      if (!res.headersSent) send(res, error instanceof HttpError ? error.status : 500, { error: error.message });
      else res.end();
    }
  };
}

const operator = createServer(handle(async (req, res, pathname) => {
  if (await appRoutes(req, res, pathname)) return true;
  if (req.method === 'GET' && pathname === '/') { send(res, 200, await page(), 'text/html; charset=utf-8'); return true; }
  if (req.method === 'POST' && pathname === '/ops/payments') {
    let message;
    try { await createPayment(await readBody(req)); message = 'Платёж отправлен. Откройте демо-приложение на телефоне.'; } catch (e) { message = e.message; }
    send(res, 200, await page(message), 'text/html; charset=utf-8');
    return true;
  }
  if (req.method === 'GET' && pathname === '/ops/evidence' && customer.nexusId) {
    const evidence = await authCore('GET', `/v1/nexus-identities/${customer.nexusId}/evidence`);
    send(res, evidence.status, evidence.text);
    return true;
  }
  return false;
}));

// Auth Core endpoints a device calls. POST /v1/mobile/sessions is the bank's
// (it needs the bank token) and is not forwarded.
const DEVICE_PATHS = [
  /^\/v1\/mobile\/(?!sessions(\/|$))[A-Za-z0-9/_-]+$/,
  /^\/v1\/recovery\/sessions\/[0-9a-f-]{36}\/complete$/,
  /^\/v1\/push-receipts\/[A-Za-z0-9_-]+$/,
];
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'host']);
const upstream = new URL(AUTH_CORE);

/** Forwards a device request to Auth Core unchanged: same method, path, query,
 * signature headers and body bytes, so the device signature still verifies. */
function forwardToAuthCore(req, res) {
  const headers = Object.fromEntries(Object.entries(req.headers).filter(([name]) => !HOP_BY_HOP.has(name)));
  const requestUpstream = upstream.protocol === 'https:' ? httpsRequest : httpRequest;
  const outgoing = requestUpstream({
    protocol: upstream.protocol, hostname: upstream.hostname, port: upstream.port, method: req.method, path: req.url, headers,
  }, (incoming) => {
    const out = Object.fromEntries(Object.entries(incoming.headers).filter(([name]) => !HOP_BY_HOP.has(name)));
    res.writeHead(incoming.statusCode ?? 502, out);
    incoming.pipe(res);
  });
  outgoing.on('error', (error) => {
    log(`Auth Core not reachable: ${error.message}`);
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Auth Core not reachable' }));
  });
  req.pipe(outgoing);
}

function deviceServer(handler) {
  if (!DEVICE_HTTPS) return createServer(handler);
  const cert = join(TLS_DIR, 'server.crt');
  const key = join(TLS_DIR, 'server.key');
  if (!existsSync(cert) || !existsSync(key)) {
    console.error(`--https needs ${cert} and ${key}: run bash demo/bank-backend/make-cert.sh <the computer's Wi-Fi IP> first.`);
    process.exit(2);
  }
  return createHttpsServer({ cert: readFileSync(cert), key: readFileSync(key) }, handler);
}

const device = deviceServer(async (req, res) => {
  const { pathname } = new URL(req.url, 'http://localhost');
  if (DEVICE_PATHS.some((pattern) => pattern.test(pathname))) return forwardToAuthCore(req, res);
  return handle(appRoutes)(req, res);
});

operator.listen(PORT, '127.0.0.1', async () => {
  try {
    await token();
  } catch (error) {
    console.error(`Auth Core at ${AUTH_CORE} did not accept the bank client: ${error.message}`);
    process.exit(1);
  }
  device.listen(DEVICE_PORT, DEVICE_HOST, () => {
    log(`demo bank: operator page http://127.0.0.1:${PORT}, device port ${DEVICE_HTTPS ? 'https' : 'http'}://${DEVICE_HOST}:${DEVICE_PORT}; Auth Core ${AUTH_CORE}, bank client ${CLIENT_ID}`);
    log(`pairing code for the demo app: ${displayPairingCode()}`);
  });
});
