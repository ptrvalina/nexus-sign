// The bank's side for the execution boundary tests: its own database with
// separate roles for the boundary and the payment gateway, a payment
// provider double that can misbehave, test certificates for mutual TLS, and
// a payment gateway in its own process.
//
// The provider double is not a payment provider and proves nothing about
// one: it lets the tests make it succeed, fail, stay pending, lose a
// response, answer nonsense, and execute a resubmission again when told it
// is not idempotent, so that the boundary's behaviour can be checked in each case.
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { ROOT, createDatabase } from './harness.mjs';

const ADMIN_DB_URL = process.env.INTEGRATION_DATABASE_URL;

/** The bank's database: owner pool, and pools for the boundary's and the gateway's roles. */
export async function bankDatabase(lib) {
  const db = await createDatabase({ schema: false });
  const suffix = randomBytes(4).toString('hex');
  const roles = { boundary: `bank_boundary_${suffix}`, gateway: `bank_gateway_${suffix}` };
  const passwords = { boundary: randomBytes(12).toString('hex'), gateway: randomBytes(12).toString('hex') };
  const admin = new pg.Client({ connectionString: ADMIN_DB_URL });
  await admin.connect();
  try {
    for (const k of ['boundary', 'gateway']) {
      await admin.query(`CREATE ROLE ${roles[k]} LOGIN PASSWORD '${passwords[k]}'`);
      await admin.query(`GRANT CONNECT ON DATABASE ${db.name} TO ${roles[k]}`);
    }
  } finally { await admin.end(); }
  await db.pool.query(`GRANT USAGE ON SCHEMA public TO ${roles.boundary}, ${roles.gateway}`);
  await lib.installSchema(db.pool, { boundaryRole: roles.boundary, gatewayRole: roles.gateway });
  const urlFor = (k) => { const u = new URL(db.url); u.username = roles[k]; u.password = passwords[k]; return u.toString(); };
  const pools = { boundary: new pg.Pool({ connectionString: urlFor('boundary'), max: 6 }), gateway: new pg.Pool({ connectionString: urlFor('gateway'), max: 6 }) };
  return {
    owner: db.pool, pools, urls: { boundary: urlFor('boundary'), gateway: urlFor('gateway') }, roles,
    async drop() {
      await pools.boundary.end(); await pools.gateway.end();
      await db.drop();
      const c = new pg.Client({ connectionString: ADMIN_DB_URL });
      await c.connect();
      try { for (const k of ['boundary', 'gateway']) await c.query(`DROP ROLE IF EXISTS ${roles[k]}`); } finally { await c.end(); }
    },
  };
}

/** A payment provider double. `idempotent` decides what a second submission of one operation id does. */
export function providerDouble({ idempotent = true } = {}) {
  const ops = new Map();
  const p = {
    calls: [], lookups: [], modes: [], beforeSubmit: null, beforeAnswer: null,
    /** Money actually moved for an operation id (a non-idempotent provider moves it again). */
    executions: (id) => ops.get(id)?.executions ?? 0,
    totalExecutions: () => [...ops.values()].reduce((n, op) => n + op.executions, 0),
    settle(id, status) { ops.get(id).status = status; },
    forget(id) { ops.delete(id); },
    async submit(order) {
      p.calls.push(order);
      if (p.beforeSubmit) await p.beforeSubmit(order);
      const mode = p.modes.shift() ?? 'succeed';
      if (mode === 'drop') throw new Error('connection reset before the provider received it');
      let op = ops.get(order.operationId);
      if (!op || !idempotent) {
        const status = mode === 'fail' ? 'failed' : mode === 'pending' ? 'pending' : 'succeeded';
        op = { status, providerReference: `PAY-${randomUUID().slice(0, 8)}`, executions: (op?.executions ?? 0) + (status === 'failed' ? 0 : 1) };
        ops.set(order.operationId, op);
      }
      if (p.beforeAnswer) await p.beforeAnswer(order);
      if (mode === 'lose') throw new Error('response lost after the provider executed it');
      if (mode === 'garbage') return { status: 'maybe' };
      return { status: op.status, providerReference: op.providerReference };
    },
    async lookup(id) {
      p.lookups.push(id);
      if (p.lookupMode === 'error') throw new Error('provider lookup unavailable');
      const op = ops.get(id);
      return op ? { status: op.status, providerReference: op.providerReference } : { status: 'not_found' };
    },
  };
  return p;
}

/** The provider double behind HTTP, for a gateway in another process. */
export async function providerServer(provider) {
  const server = createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    try {
      if (req.method === 'POST' && req.url === '/payments') {
        let raw = ''; for await (const c of req) raw += c;
        return send(200, await provider.submit(JSON.parse(raw)));
      }
      const m = /^\/payments\/(.+)$/.exec(req.url);
      if (req.method === 'GET' && m) {
        const r = await provider.lookup(decodeURIComponent(m[1]));
        return r.status === 'not_found' ? send(404, r) : send(200, r);
      }
      return send(404, {});
    } catch (error) {
      res.destroy(error); // the connection drops: the gateway sees no answer
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

/** Test certificates (openssl): a CA, the gateway's server certificate, client certificates. */
export function certificates() {
  const dir = mkdtempSync(join(tmpdir(), 'bank-mtls-'));
  const run = (args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  const ca = (name) => {
    run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`]);
    run(['req', '-x509', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-days', '2', '-out', `${name}.crt`]);
  };
  const leaf = (name, caName, cn, server) => {
    run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`]);
    run(['req', '-new', '-key', `${name}.key`, '-subj', `/CN=${cn}`, '-out', `${name}.csr`]);
    writeFileSync(join(dir, `${name}.ext`), server ? 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' : 'extendedKeyUsage=clientAuth\n');
    run(['x509', '-req', '-in', `${name}.csr`, '-CA', `${caName}.crt`, '-CAkey', `${caName}.key`, '-CAcreateserial', '-days', '2', '-extfile', `${name}.ext`, '-out', `${name}.crt`]);
  };
  ca('bank-ca'); ca('other-ca');
  leaf('gateway', 'bank-ca', 'payment-gateway', true);
  leaf('boundary', 'bank-ca', 'bank-execution-boundary', false);
  leaf('other-service', 'bank-ca', 'statement-service', false);
  leaf('rogue', 'other-ca', 'bank-execution-boundary', false);
  const read = (f) => readFileSync(join(dir, f));
  const pair = (n) => ({ key: read(`${n}.key`), cert: read(`${n}.crt`) });
  return { dir, ca: read('bank-ca.crt'), otherCa: read('other-ca.crt'), gateway: pair('gateway'), boundary: pair('boundary'), otherService: pair('other-service'), rogue: pair('rogue') };
}

/** Starts the payment gateway in its own process (support/gatewayProcess.mjs). */
export async function startGatewayProcess({ databaseUrl, providerUrl, certs, allowedClients = ['bank-execution-boundary'] }) {
  const env = {
    ...process.env, GATEWAY_DATABASE_URL: databaseUrl, GATEWAY_PROVIDER_URL: providerUrl, GATEWAY_ALLOWED_CLIENTS: allowedClients.join(','),
    GATEWAY_TLS_DIR: certs.dir,
  };
  const child = spawn(process.execPath, [join(ROOT, 'test/integration/support/gatewayProcess.mjs')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  child.stderr.on('data', (d) => { log += d; });
  const port = await new Promise((resolve, reject) => {
    child.stdout.on('data', (d) => { const m = /listening (\d+)/.exec(String(d)); if (m) resolve(Number(m[1])); });
    child.on('exit', (code) => reject(new Error(`gateway exited ${code}: ${log}`)));
    setTimeout(() => reject(new Error(`gateway did not start: ${log}`)), 10_000);
  });
  const exited = new Promise((r) => child.on('exit', r));
  return {
    url: `https://127.0.0.1:${port}`, pid: child.pid, logs: () => log,
    kill: async () => { child.kill('SIGKILL'); await exited; },
    stop: async () => { child.kill('SIGTERM'); await exited; },
  };
}
