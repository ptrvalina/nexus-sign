// Starts real Auth Core processes (dist/server.js) against a fresh PostgreSQL
// database and an empty Redis database for each environment, so security
// properties are tested against the actual datastore semantics: row locks,
// constraints, triggers and Redis atomic operations.
//
// Needs a built project (npm run build) and:
//   INTEGRATION_DATABASE_URL  a role allowed to CREATE DATABASE, e.g.
//                             postgres://postgres:postgres@127.0.0.1:5432/postgres
//   INTEGRATION_REDIS_URL     e.g. redis://127.0.0.1:6379
// Without them the integration suites are skipped.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { createServer } from 'node:net';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

const ADMIN_DB_URL = process.env.INTEGRATION_DATABASE_URL;
const REDIS_URL = process.env.INTEGRATION_REDIS_URL;

/**
 * With REQUIRE_ALL_INTEGRATION_SUITES=1 (set in CI) a missing service is a
 * failure, not a skip: a required suite must never pass by not running.
 */
export function requiredOrSkip(reason) {
  if (reason && process.env.REQUIRE_ALL_INTEGRATION_SUITES === '1') {
    throw new Error(`Required integration suite cannot run: ${reason} (REQUIRE_ALL_INTEGRATION_SUITES=1)`);
  }
  return reason;
}

/** node:test `skip` option for suites that need PostgreSQL and Redis. */
export const skipWithoutServices = requiredOrSkip(ADMIN_DB_URL && REDIS_URL
  ? false
  : 'INTEGRATION_DATABASE_URL and INTEGRATION_REDIS_URL are not set');

let redisDbCounter = 1;

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolvePort(port));
    });
  });
}

function databaseUrl(name) {
  const url = new URL(ADMIN_DB_URL);
  url.pathname = `/${name}`;
  return url.toString();
}

/** Creates an empty database with the schema and every migration applied
 * (`{ schema: false }`: an empty database, e.g. a bank's own store). */
export async function createDatabase({ schema = true } = {}) {
  const { Client, Pool } = require('pg');
  const name = `nexus_it_${randomBytes(6).toString('hex')}`;
  const admin = new Client({ connectionString: ADMIN_DB_URL });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }
  const url = databaseUrl(name);
  const setup = new Client({ connectionString: url });
  await setup.connect();
  try {
    await setup.query('SET client_min_messages = warning');
    if (schema) {
      await setup.query(readFileSync(join(ROOT, 'src/db/schema.sql'), 'utf8'));
      for (const file of readdirSync(join(ROOT, 'migrations')).filter((f) => f.endsWith('.sql')).sort()) {
        await setup.query(readFileSync(join(ROOT, 'migrations', file), 'utf8'));
      }
    }
  } finally {
    await setup.end();
  }
  const pool = new Pool({ connectionString: url, max: 4 });
  return {
    name,
    url,
    pool,
    async drop() {
      await pool.end();
      const cleanup = new Client({ connectionString: ADMIN_DB_URL });
      await cleanup.connect();
      try {
        await cleanup.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      } finally {
        await cleanup.end();
      }
    },
  };
}

async function emptyRedisDatabase() {
  const Redis = require('ioredis');
  const index = redisDbCounter;
  redisDbCounter = (redisDbCounter % 15) + 1;
  const url = new URL(REDIS_URL);
  url.pathname = `/${index}`;
  const client = new Redis(url.toString(), { maxRetriesPerRequest: 1 });
  await client.flushdb();
  return { url: url.toString(), client };
}

/** What a child process needs from the parent environment on every OS:
 * PATH, and on Windows the system directory and temp paths, without which
 * Node cannot initialise networking or crypto. Nothing else is inherited. */
export function processEnvironment() {
  const keep = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'windir', 'TEMP', 'TMP'];
  return Object.fromEntries(keep.filter((k) => process.env[k] !== undefined).map((k) => [k, process.env[k]]));
}

/** Environment every test server shares; tests override what they examine. */
export function baseEnvironment() {
  return {
    NODE_ENV: 'development',
    ALLOW_INSECURE_DEVELOPMENT: 'true',
    HSM_ADAPTER: 'software',
    REQUIRE_VALID_ATTESTATION: 'false',
    OFFLINE_CONFIRMATION_ENABLED: 'true',
    DEVICE_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    WEBHOOK_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    ADMIN_COOKIE_SECURE: 'false',
    ADMIN_MFA_REQUIRED: 'false',
    ADMIN_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  };
}

function runCli(script, args, env) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(process.execPath, [join(ROOT, 'dist/cli', script), ...args], { env, cwd: ROOT });
    let output = '';
    child.stdout.on('data', (d) => { output += d; });
    child.stderr.on('data', (d) => { output += d; });
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolveRun(output) : reject(new Error(`${script} exited ${code}:\n${output}`))));
  });
}

/**
 * Starts Auth Core on a fresh database. Returns helpers to provision bank
 * clients and admins through the operator CLIs, direct database access for
 * tamper scenarios, and stop().
 */
export async function startAuthCore({ env: overrides = {}, database } = {}) {
  const db = database ?? await createDatabase();
  const redis = await emptyRedisDatabase();
  const port = await freePort();
  const env = {
    ...processEnvironment(),
    ...baseEnvironment(),
    DATABASE_URL: db.url,
    REDIS_URL: redis.url,
    PORT: String(port),
    ...overrides,
  };
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];

  let log = '';
  const child = spawn(process.execPath, [join(ROOT, 'dist/server.js')], { env, cwd: ROOT });
  child.stdout.on('data', (d) => { log += d; });
  child.stderr.on('data', (d) => { log += d; });
  const exited = new Promise((resolveExit) => child.on('exit', (code) => resolveExit(code)));

  const baseUrl = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20_000;
  for (;;) {
    const code = await Promise.race([exited, new Promise((r) => setTimeout(() => r(undefined), 150))]);
    if (code !== undefined) {
      // Release the Redis connection, or the test process cannot exit.
      redis.client.disconnect();
      if (!database) await db.drop();
      throw new Error(`Auth Core exited with ${code} during startup:\n${log}`);
    }
    try {
      const ready = await fetch(`${baseUrl}/readyz`);
      if (ready.status === 200) break;
    } catch { /* not listening yet */ }
    if (Date.now() > deadline) {
      child.kill('SIGKILL');
      redis.client.disconnect();
      throw new Error(`Auth Core did not become ready:\n${log}`);
    }
  }

  return {
    baseUrl,
    db: db.pool,
    env,
    logs: () => log,
    /** Registers a bank client with the operator CLI; returns its secret. */
    async registerBank(clientId, { webhookUrl, pushMode = 'BANK', certificateSha256 } = {}) {
      const args = [clientId];
      if (webhookUrl) args.push(webhookUrl);
      args.push(`--push-mode=${pushMode}`);
      if (certificateSha256) args.push(`--mtls-cert-sha256=${certificateSha256}`);
      const output = await runCli('registerClient.js', args, env);
      const secret = /client_secret:\s*(\S+)/.exec(output)?.[1];
      const webhookSecret = /webhook_secret:\s*(\S+)/.exec(output)?.[1];
      if (!secret) throw new Error(`registerClient printed no secret:\n${output}`);
      return { clientId, secret, webhookSecret };
    },
    /** Runs cli/verificationSetup.js (provider-add, provider-retire, operator, show). */
    async verificationSetup(...args) {
      return runCli('verificationSetup.js', args, env);
    },
    /** Creates an admin with the operator CLI; returns password and TOTP secret. */
    async createAdmin(username, role, { clientId, password } = {}) {
      const args = [username, role];
      if (clientId) args.push(`--client=${clientId}`);
      const output = await runCli('createAdminUser.js', args, password ? { ...env, NEXUS_ADMIN_PASSWORD: password } : env);
      return {
        username,
        password: /password:\s*(\S+)/.exec(output)?.[1],
        totpSecret: /totp_secret:\s*(\S+)/.exec(output)?.[1],
        output,
      };
    },
    /** Kills the process at once (SIGKILL: no drain, no cleanup), as a crash
     * would; the database is kept. Then stop() only releases the resources. */
    async crash() {
      if (child.exitCode === null) {
        child.kill('SIGKILL');
        await exited;
      }
    },
    async stop() {
      if (child.exitCode === null) {
        child.kill('SIGTERM');
        await Promise.race([exited, new Promise((r) => setTimeout(r, 5000))]);
        if (child.exitCode === null) child.kill('SIGKILL');
      }
      redis.client.disconnect();
      if (!database) await db.drop();
    },
  };
}

/** Starts a process expected to refuse to start; returns its exit code and output. */
export async function startExpectingFailure(overrides, { database } = {}) {
  const db = database ?? await createDatabase();
  const redis = await emptyRedisDatabase();
  const env = { ...processEnvironment(), ...baseEnvironment(), DATABASE_URL: db.url, REDIS_URL: redis.url, PORT: String(await freePort()), ...overrides };
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  const child = spawn(process.execPath, [join(ROOT, 'dist/server.js')], { env, cwd: ROOT });
  let log = '';
  child.stdout.on('data', (d) => { log += d; });
  child.stderr.on('data', (d) => { log += d; });
  const code = await Promise.race([
    new Promise((r) => child.on('exit', r)),
    new Promise((r) => setTimeout(() => r('still-running'), 10_000)),
  ]);
  if (code === 'still-running') child.kill('SIGKILL');
  redis.client.disconnect();
  if (!database) await db.drop();
  return { code, log };
}
