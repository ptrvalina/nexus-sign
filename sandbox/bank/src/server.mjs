#!/usr/bin/env node
// Sandbox bank: one process, two listeners.
//
//   console port (CONSOLE_HOST:CONSOLE_PORT)  bank operations console + /api for automation
//   device port  (DEVICE_HOST:DEVICE_PORT)    the bank app's API (/app/v1/*) and the Auth Core
//                                             endpoints a device calls (/v1/mobile/*, …), forwarded
//                                             byte for byte so device signatures still verify
//
// The bank API of Auth Core and its admin console are never reachable through
// the device port.
import { createServer, request as httpRequest } from 'node:http';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { readFileSync } from 'node:fs';
import { ConfigError, loadConfig } from './config.mjs';
import { openDatabase } from './db.mjs';
import { seedIfEmpty } from './seed.mjs';
import { createAuthCoreClient } from './authcore.mjs';
import { createFaults } from './faults.mjs';
import { createPayments } from './payments.mjs';
import { createCustomers } from './customers.mjs';
import { createAppApi } from './appApi.mjs';
import { createConsole } from './console/console.mjs';
import { createScenarioEngine } from './scenarios/engine.mjs';
import { createSoftwareDevice } from './scenarios/device.mjs';
import { errorBody, errorStatus, escapeHtml, log, sendHtml, sendJson } from './http.mjs';
import { recordEvent } from './events.mjs';

let config;
try {
  config = loadConfig();
} catch (error) {
  if (error instanceof ConfigError) {
    log('fatal', `configuration refused: ${error.message}`);
    process.exit(2);
  }
  throw error;
}

const db = openDatabase(config.dbPath);
if (seedIfEmpty(db, config.bank, config.customerPassword)) log('info', 'demo data written', { customers: config.bank.customers.length });
const authCore = createAuthCoreClient({ baseUrl: config.authCoreUrl, clientId: config.bankClientId, clientSecret: config.bankClientSecret });
const faults = createFaults(config.faultInjection);
const payments = createPayments({ db, bank: config.bank, authCore, faults });
const customers = createCustomers({ db, authCore });
const appApi = createAppApi({ db, bank: config.bank, customers, payments });
const device = createSoftwareDevice({ dataDir: config.dataDir, deviceBaseUrl: `${config.device.tlsCert ? 'https' : 'http'}://127.0.0.1:${config.device.port}` });
const scenarios = createScenarioEngine({ db, payments, customers, device, faults, authCore });
const consoleHandler = createConsole({ db, config, payments, scenarios, authCore, faults });

// Device endpoints of Auth Core. POST /v1/mobile/sessions is the bank's (it needs the bank token) and is not forwarded.
const DEVICE_PATHS = [
  /^\/v1\/mobile\/(?!sessions(\/|$))[A-Za-z0-9/_-]+$/,
  /^\/v1\/recovery\/sessions\/[0-9a-f-]{36}\/complete$/,
  /^\/v1\/push-receipts\/[A-Za-z0-9_-]+$/,
];
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'host']);
const upstream = new URL(config.authCoreUrl);

function forwardToAuthCore(req, res) {
  const headers = Object.fromEntries(Object.entries(req.headers).filter(([name]) => !HOP_BY_HOP.has(name)));
  const send = upstream.protocol === 'https:' ? httpsRequest : httpRequest;
  const outgoing = send({ protocol: upstream.protocol, hostname: upstream.hostname, port: upstream.port, method: req.method, path: req.url, headers }, (incoming) => {
    res.writeHead(incoming.statusCode ?? 502, Object.fromEntries(Object.entries(incoming.headers).filter(([name]) => !HOP_BY_HOP.has(name))));
    incoming.pipe(res);
  });
  outgoing.on('error', (error) => {
    log('warn', 'Auth Core not reachable from the device port', { error: error.message });
    if (!res.headersSent) sendJson(res, 502, { code: 'AUTH_CORE_UNREACHABLE', error: 'Auth Core not reachable' });
    else res.end();
  });
  req.pipe(outgoing);
}

const deviceHandler = async (req, res) => {
  const { pathname } = new URL(req.url, 'http://device');
  try {
    if (faults.deviceNetworkDown()) {
      req.resume();
      return sendJson(res, 503, { code: 'SANDBOX_NETWORK_DOWN', error: 'Network interruption (sandbox fault injection)' });
    }
    if (DEVICE_PATHS.some((p) => p.test(pathname))) return forwardToAuthCore(req, res);
    if (req.method === 'GET' && pathname === '/healthz') return sendJson(res, 200, { ok: true });
    if (!(await appApi(req, res, pathname))) sendJson(res, 404, { code: 'NOT_FOUND' });
  } catch (error) {
    if (errorStatus(error) >= 500) log('error', 'device port request failed', { path: pathname, error: error.message });
    if (!res.headersSent) sendJson(res, errorStatus(error), errorBody(error));
    else res.end();
  }
};

const consoleServer = createServer(async (req, res) => {
  try {
    await consoleHandler(req, res);
  } catch (error) {
    if (errorStatus(error) >= 500) log('error', 'console request failed', { path: req.url, error: error.message, stack: error.stack });
    if (!res.headersSent) sendHtml(res, errorStatus(error), `<!doctype html><meta charset="utf-8"><p>${escapeHtml(errorBody(error).error)}</p><p><a href="/">← консоль</a></p>`);
    else res.end();
  }
});

const deviceServer = config.device.tlsCert
  ? createHttpsServer({ cert: readFileSync(config.device.tlsCert), key: readFileSync(config.device.tlsKey) }, deviceHandler)
  : createServer(deviceHandler);

let reconciling = false;
const timer = setInterval(async () => {
  if (reconciling) return;
  reconciling = true;
  try { await payments.reconcileOpen(); } catch (error) { log('warn', 'reconciliation pass failed', { error: error.message }); } finally { reconciling = false; }
}, config.reconcileIntervalMs);

consoleServer.listen(config.console.port, config.console.host, () => {
  deviceServer.listen(config.device.port, config.device.host, () => {
    recordEvent(db, { type: 'SANDBOX_BANK_STARTED', source: 'SYSTEM', detail: { authCore: config.authCoreUrl, pinnedRevision: config.pinnedRevision, hsm: config.hsmDescription } });
    log('info', 'sandbox bank started', {
      console: `http://${config.console.host}:${config.console.port}`,
      device: `${config.device.tlsCert ? 'https' : 'http'}://${config.device.host}:${config.device.port}`,
      authCore: config.authCoreUrl, faultInjection: config.faultInjection,
    });
  });
});

function shutdown(signal) {
  log('info', 'stopping', { signal });
  clearInterval(timer);
  consoleServer.close();
  deviceServer.close();
  setTimeout(() => { db.close(); process.exit(0); }, 500).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
