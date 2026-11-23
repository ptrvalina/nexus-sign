// Sandbox configuration. Every value comes from explicit SANDBOX settings; a
// missing or non-sandbox value stops the process (fail closed). Nothing falls
// back to a production endpoint, and there is no default Auth Core address.
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SANDBOX_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

export class ConfigError extends Error {}

function secret(env, name) {
  if (env[`${name}_FILE`]) return readFileSync(env[`${name}_FILE`], 'utf8').trim();
  return env[name];
}

function required(env, name) {
  const value = secret(env, name);
  if (value === undefined || value === '') throw new ConfigError(`${name} is required`);
  return value;
}

function publicUrl(value) {
  if (!value) return null;
  const url = new URL(value);
  if (url.protocol !== 'https:') throw new ConfigError(`${value}: public addresses must be https`);
  return url.toString().replace(/\/$/, '');
}

function port(env, name, fallback) {
  const value = Number(env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new ConfigError(`${name} must be a TCP port`);
  return value;
}

/** Loads and checks the configuration; throws ConfigError on anything unsafe. */
export function loadConfig(env = process.env) {
  if (env.SANDBOX_ENVIRONMENT !== 'sandbox') {
    throw new ConfigError('SANDBOX_ENVIRONMENT=sandbox is required: this service runs only in the isolated sandbox');
  }
  const authCoreUrl = new URL(required(env, 'AUTH_CORE_URL'));
  const allowedHosts = (env.SANDBOX_ALLOWED_AUTH_CORE_HOSTS ?? 'auth-core,127.0.0.1,localhost')
    .split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
  if (!allowedHosts.includes(authCoreUrl.hostname.toLowerCase())) {
    throw new ConfigError(`AUTH_CORE_URL host ${authCoreUrl.hostname} is not a sandbox host (${allowedHosts.join(', ')})`);
  }

  const dataDir = resolve(required(env, 'SANDBOX_DATA_DIR'));
  const dbPath = resolve(env.BANK_DB_PATH ?? join(dataDir, 'bank.sqlite'));
  const rel = relative(dataDir, dbPath);
  if (rel.startsWith('..') || isAbsolute(rel)) throw new ConfigError('BANK_DB_PATH must be inside SANDBOX_DATA_DIR');

  const bankConfigPath = env.SANDBOX_BANK_CONFIG ?? join(SANDBOX_ROOT, 'config', 'bank.json');
  const bank = JSON.parse(readFileSync(bankConfigPath, 'utf8'));

  return {
    authCoreUrl: authCoreUrl.toString().replace(/\/$/, ''),
    bankClientId: required(env, 'BANK_CLIENT_ID'),
    bankClientSecret: required(env, 'BANK_CLIENT_SECRET'),
    dataDir,
    dbPath,
    bank,
    console: {
      host: env.CONSOLE_HOST ?? '127.0.0.1',
      port: port(env, 'CONSOLE_PORT', 8190),
      username: env.CONSOLE_USERNAME ?? 'operator',
      password: required(env, 'CONSOLE_PASSWORD'),
      secureCookies: env.CONSOLE_SECURE_COOKIES === 'true',
    },
    device: {
      host: env.DEVICE_HOST ?? '127.0.0.1',
      port: port(env, 'DEVICE_PORT', 8191),
      tlsCert: env.DEVICE_TLS_CERT || null,
      tlsKey: env.DEVICE_TLS_KEY || null,
    },
    customerPassword: required(env, 'DEMO_CUSTOMER_PASSWORD'),
    // Fault injection exists only here, in the sandbox bank; Auth Core has none.
    faultInjection: env.SANDBOX_FAULT_INJECTION === 'enabled',
    reconcileIntervalMs: Number(env.RECONCILE_INTERVAL_MS ?? 1000),
    hsmDescription: env.SANDBOX_HSM_DESCRIPTION ?? 'not reported',
    // Public mode (sandbox/bin/sandbox up --public DOMAIN): the address phones use, the
    // TestFlight invitation and the directory with the Android APK offered on the landing page.
    publicUrl: publicUrl(env.SANDBOX_PUBLIC_URL),
    testflightUrl: publicUrl(env.SANDBOX_TESTFLIGHT_URL),
    downloadsDir: env.SANDBOX_DOWNLOADS_DIR || null,
    pinnedRevision: env.SANDBOX_PINNED_AUTH_CORE ?? 'not reported',
  };
}
