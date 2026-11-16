// Runs Auth Core's startup checks (configurationErrors, productionBlockers)
// over the ConfigMap and placeholder values for the Secret keys, read as
// JSON on stdin from check-manifests.py. Placeholders are random, generated
// here, and never written anywhere.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { loadTs } from '../../auth-core/test/support/load-ts.mjs';

const { config, secretKeys } = JSON.parse(readFileSync(0, 'utf8'));
const placeholder = {
  DATABASE_URL: 'postgres://nexus_app:x@db.bank.example:5432/nexus',
  REDIS_URL: 'rediss://redis.bank.example:6380',
  METRICS_BEARER_TOKEN: randomBytes(32).toString('hex'),
  APPLE_APP_ATTEST_ROOT_CA_PEM: '-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----',
  GOOGLE_SERVICE_ACCOUNT_JSON: '{"type":"service_account"}',
};
for (const key of Object.keys(process.env)) if (/^[A-Z][A-Z0-9_]+$/.test(key) && key !== 'PATH' && key !== 'HOME') delete process.env[key];
Object.assign(process.env, config);
for (const key of secretKeys) process.env[key] = placeholder[key] ?? randomBytes(48).toString('base64');
const { env } = loadTs('config/env.ts');
const { configurationErrors, productionBlockers } = loadTs('config/productionPosture.ts');
const failures = [...configurationErrors(env), ...productionBlockers(env)];
if (failures.length) { console.log(failures.join('\n')); process.exit(1); }
console.log(`ok: production posture checks pass for the manifests (NODE_ENV=${env.NODE_ENV}, ${Object.keys(config).length} settings, ${secretKeys.length} secret keys)`);
