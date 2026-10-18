import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { loadTs } from './support/load-ts.mjs';
import { processEnvironment } from './integration/support/harness.mjs';

const { productionBlockers, configurationErrors } = loadTs('config/productionPosture.ts');

const KEY = Buffer.alloc(32, 7).toString('base64');
// Shape of a wrapped key (masterKeyVault.ts); posture checks do not unwrap.
const WRAPPED = `w1$nexus-master-kek$${Buffer.alloc(12).toString('base64')}$${Buffer.alloc(48).toString('base64')}`;

const production = {
  NODE_ENV: 'production',
  HSM_ADAPTER: 'pkcs11',
  REQUIRE_VALID_ATTESTATION: true,
  APPLE_APP_ID: 'TEAMID.com.bank.app',
  APPLE_APP_ATTEST_ROOT_CA_PEM: '-----BEGIN CERTIFICATE-----',
  GOOGLE_SERVICE_ACCOUNT_JSON: undefined,
  ANDROID_PACKAGE_NAME: undefined,
  MASTER_KEY_SOURCE: 'hsm',
  PKCS11_KEK_LABEL: 'nexus-master-kek',
  WEBHOOK_SECRET_ENCRYPTION_KEY_WRAPPED: WRAPPED,
  ADMIN_COOKIE_SECURE: true,
  ADMIN_MFA_REQUIRED: true,
  ADMIN_SECRET_ENCRYPTION_KEY_WRAPPED: WRAPPED,
  PKCS11_MODULE_PATH: '/usr/lib/hsm.so',
  PKCS11_PIN: '1234',
  PKCS11_EVIDENCE_KEY_LABEL: 'evidence',
  PKCS11_TOKEN_LABEL: 'nexus',
  DATABASE_SSL: true,
  REDIS_TLS_REQUIRED: true,
  REQUIRE_MTLS_HEADER: true,
  TRUSTED_PROXY_IPS: ['10.0.0.5'],
  WEBHOOK_ALLOWED_HOSTS: ['hooks.bank.example'],
  WEBHOOK_REQUIRE_HTTPS: true,
  REDIS_URL: 'rediss://redis.internal:6380',
  OFFLINE_CONFIRMATION_ENABLED: false,
  ANDROID_KEY_SECURITY_POLICY: 'REQUIRE_HARDWARE_BACKED',
  ANDROID_REQUIRE_LOCKED_BOOTLOADER: true,
  ANDROID_APP_CERT_SHA256: [],
  ANDROID_REQUIRED_DEVICE_VERDICT: 'MEETS_DEVICE_INTEGRITY',
  METRICS_BEARER_TOKEN: 'm'.repeat(40),
};

// The same configuration with plaintext master keys (MASTER_KEY_SOURCE=env),
// for the checks of plaintext key values.
const plain = {
  ...production, MASTER_KEY_SOURCE: 'env', WEBHOOK_SECRET_ENCRYPTION_KEY: KEY, ADMIN_SECRET_ENCRYPTION_KEY: KEY,
  WEBHOOK_SECRET_ENCRYPTION_KEY_WRAPPED: undefined, ADMIN_SECRET_ENCRYPTION_KEY_WRAPPED: undefined,
};

test('a complete production configuration has no blockers', () => {
  assert.deepEqual(productionBlockers(production), []);
});

test('each missing production control is reported', () => {
  const cases = [
    [{ HSM_ADAPTER: 'software' }, 'HSM_ADAPTER must be pkcs11 in production'],
    [{ REQUIRE_VALID_ATTESTATION: false }, 'REQUIRE_VALID_ATTESTATION must be true in production'],
    [{ APPLE_APP_ATTEST_ROOT_CA_PEM: undefined }, 'APPLE_APP_ATTEST_ROOT_CA_PEM must be pinned in production'],
    [{ ADMIN_COOKIE_SECURE: false }, 'ADMIN_COOKIE_SECURE must be true in production'],
    [{ ADMIN_MFA_REQUIRED: false }, 'ADMIN_MFA_REQUIRED must be true in production'],
    [{ ADMIN_SECRET_ENCRYPTION_KEY_WRAPPED: undefined }, 'ADMIN_SECRET_ENCRYPTION_KEY is required in production (admin TOTP secrets)'],
    [{ REDIS_URL: 'redis://redis.internal:6379' }, 'REDIS_URL must use rediss:// in production'],
    [{ WEBHOOK_ALLOWED_HOSTS: [] }, 'WEBHOOK_ALLOWED_HOSTS must be configured in production'],
    [{ REQUIRE_MTLS_HEADER: false }, 'REQUIRE_MTLS_HEADER must be true in production'],
    [{ TRUSTED_PROXY_IPS: [] }, 'TRUSTED_PROXY_IPS must list the mTLS gateway addresses in production'],
  ];
  for (const [override, message] of cases) {
    assert.ok(productionBlockers({ ...production, ...override }).includes(message), message);
  }
});

test('development is not held to the production posture', () => {
  assert.deepEqual(productionBlockers({ ...production, NODE_ENV: 'development', HSM_ADAPTER: 'software' }), []);
});

test('offline confirmation needs the device secret key in every environment', () => {
  assert.equal(configurationErrors({ ...plain, NODE_ENV: 'development', OFFLINE_CONFIRMATION_ENABLED: true }).length, 1);
  assert.deepEqual(configurationErrors({ ...plain, OFFLINE_CONFIRMATION_ENABLED: true, DEVICE_SECRET_ENCRYPTION_KEY: KEY }), []);
  assert.deepEqual(configurationErrors({ ...production, OFFLINE_CONFIRMATION_ENABLED: true, DEVICE_SECRET_ENCRYPTION_KEY_WRAPPED: WRAPPED }), [], 'wrapped key counts');
});

test('secure push needs the device secret key and one complete provider', () => {
  const apns = { APNS_TEAM_ID: 'ABCDE12345', APNS_KEY_ID: 'KEY1234567', APNS_PRIVATE_KEY_PEM: '-----BEGIN PRIVATE KEY-----', APNS_TOPIC: 'com.bank.app' };
  const fcm = { FCM_PROJECT_ID: 'bank-app-prod', FCM_SERVICE_ACCOUNT_JSON: '{}' };
  assert.deepEqual(configurationErrors({ ...plain, PUSH_DELIVERY_ENABLED: true, DEVICE_SECRET_ENCRYPTION_KEY: KEY, ...apns }), []);
  assert.deepEqual(configurationErrors({ ...plain, PUSH_DELIVERY_ENABLED: true, DEVICE_SECRET_ENCRYPTION_KEY: KEY, ...fcm }), []);
  assert.deepEqual(configurationErrors({ ...plain, PUSH_DELIVERY_ENABLED: true, ...fcm }),
    ['DEVICE_SECRET_ENCRYPTION_KEY is required when PUSH_DELIVERY_ENABLED is true']);
  assert.deepEqual(configurationErrors({ ...plain, PUSH_DELIVERY_ENABLED: true, DEVICE_SECRET_ENCRYPTION_KEY: KEY }),
    ['PUSH_DELIVERY_ENABLED needs APNs (APNS_*) and/or FCM (FCM_*) to be configured']);
});

test('a partly configured push provider is an error even when push is off', () => {
  assert.deepEqual(configurationErrors({ ...production, APNS_TEAM_ID: 'ABCDE12345' }),
    ['APNS_TEAM_ID, APNS_KEY_ID, APNS_PRIVATE_KEY_PEM and APNS_TOPIC must be set together']);
  assert.deepEqual(configurationErrors({ ...production, FCM_PROJECT_ID: 'bank-app-prod' }),
    ['FCM_PROJECT_ID and FCM_SERVICE_ACCOUNT_JSON must be set together']);
});

test('outside production, insecure settings need an explicit ALLOW_INSECURE_DEVELOPMENT', () => {
  const development = { ...production, NODE_ENV: 'development', ALLOW_INSECURE_DEVELOPMENT: false };
  const cases = [
    [{ HSM_ADAPTER: 'software' }, 'HSM_ADAPTER=software'],
    [{ REQUIRE_VALID_ATTESTATION: false }, 'REQUIRE_VALID_ATTESTATION=false'],
    [{ REQUIRE_MTLS_HEADER: false }, 'REQUIRE_MTLS_HEADER=false'],
  ];
  for (const [override, setting] of cases) {
    const errors = configurationErrors({ ...development, ...override });
    assert.ok(errors.some((e) => e.includes(setting) && e.includes('ALLOW_INSECURE_DEVELOPMENT=true')), `${setting}: ${errors}`);
    assert.deepEqual(configurationErrors({ ...development, ...override, ALLOW_INSECURE_DEVELOPMENT: true }), []);
  }
});

test('production refuses ALLOW_INSECURE_DEVELOPMENT', () => {
  assert.ok(productionBlockers({ ...production, ALLOW_INSECURE_DEVELOPMENT: true }).includes('ALLOW_INSECURE_DEVELOPMENT must not be set in production'));
});

test('the service does not start without an explicit NODE_ENV', { skip: existsSync(new URL('../dist/config/env.js', import.meta.url)) ? false : 'run `npm run build` first: this test loads the compiled configuration' }, async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const root = fileURLToPath(new URL('..', import.meta.url));
  const env = { ...processEnvironment(), DATABASE_URL: 'postgres://u:p@127.0.0.1:1/db', REDIS_URL: 'redis://127.0.0.1:1' };
  const run = spawnSync(process.execPath, ['-e', "require('./dist/config/env')"], { cwd: root, env, encoding: 'utf8' });
  assert.notEqual(run.status, 0, 'loading the configuration without NODE_ENV must fail');
  assert.match(run.stderr, /NODE_ENV/);
});

test('production with Android attestation requires the key policy, status list, app certificate and locked bootloader', () => {
  const android = { ...production, GOOGLE_SERVICE_ACCOUNT_JSON: '{}', ANDROID_PACKAGE_NAME: 'com.bank.app', ANDROID_ATTESTATION_STATUS_FILE: '/etc/nexus/status.json', ANDROID_APP_CERT_SHA256: ['ab'.repeat(32)] };
  assert.deepEqual(productionBlockers(android), []);
  const cases = [
    [{ ANDROID_KEY_SECURITY_POLICY: 'ALLOW_SOFTWARE' }, /ALLOW_SOFTWARE/],
    [{ ANDROID_ATTESTATION_STATUS_FILE: undefined }, /status list/],
    [{ ANDROID_APP_CERT_SHA256: [] }, /signing certificate/],
    [{ ANDROID_REQUIRE_LOCKED_BOOTLOADER: false }, /LOCKED_BOOTLOADER/],
    [{ ANDROID_REQUIRED_DEVICE_VERDICT: 'MEETS_BASIC_INTEGRITY' }, /DEVICE_VERDICT/],
  ];
  for (const [override, pattern] of cases) {
    assert.ok(productionBlockers({ ...android, ...override }).some((b) => pattern.test(b)), String(pattern));
  }
});

test('every production setting is required: weakening any one of them is a blocker (NXS-038)', () => {
  const weakened = {
    HSM_ADAPTER: 'software', REQUIRE_VALID_ATTESTATION: false, APPLE_APP_ATTEST_ROOT_CA_PEM: undefined,
    WEBHOOK_SECRET_ENCRYPTION_KEY_WRAPPED: undefined, ADMIN_COOKIE_SECURE: false, ADMIN_MFA_REQUIRED: false, ADMIN_SECRET_ENCRYPTION_KEY_WRAPPED: undefined,
    MASTER_KEY_SOURCE: 'env', METRICS_BEARER_TOKEN: undefined, DEVICE_NONCE_STORE: 'redis',
    PKCS11_MODULE_PATH: undefined, PKCS11_PIN: undefined, PKCS11_EVIDENCE_KEY_LABEL: undefined, PKCS11_TOKEN_LABEL: undefined,
    DATABASE_SSL: false, REDIS_TLS_REQUIRED: false, REQUIRE_MTLS_HEADER: false, TRUSTED_PROXY_IPS: [], WEBHOOK_ALLOWED_HOSTS: [],
    WEBHOOK_REQUIRE_HTTPS: false, REDIS_URL: 'redis://redis.internal:6379', ALLOW_INSECURE_DEVELOPMENT: true,
  };
  for (const [key, value] of Object.entries(weakened)) {
    assert.ok(productionBlockers({ ...production, [key]: value }).length > 0, `${key}=${JSON.stringify(value)} must block production`);
  }
  assert.ok(productionBlockers({ ...production, APPLE_APP_ID: undefined }).length > 0, 'no attestation platform configured');
});

test('master keys are validated at startup', () => {
  assert.deepEqual(configurationErrors({ ...plain, WEBHOOK_SECRET_ENCRYPTION_KEY: 'short' }), ['WEBHOOK_SECRET_ENCRYPTION_KEY must be 32 random bytes, base64-encoded']);
  assert.deepEqual(configurationErrors({ ...plain, ADMIN_SECRET_ENCRYPTION_KEY: Buffer.alloc(16).toString('base64') }), ['ADMIN_SECRET_ENCRYPTION_KEY must be 32 random bytes, base64-encoded']);
  assert.deepEqual(configurationErrors(plain), []);
});

test('FI-004: offline confirmation in production needs per-currency caps; caps are validated', () => {
  const { parseOfflineLimits } = loadTs('config/productionPosture.ts');
  const offline = { ...production, OFFLINE_CONFIRMATION_ENABLED: true, DEVICE_SECRET_ENCRYPTION_KEY_WRAPPED: WRAPPED };
  assert.ok(productionBlockers(offline).some((b) => b.startsWith('OFFLINE_CONFIRMATION_MAX_AMOUNT is required in production')));
  assert.ok(!productionBlockers({ ...offline, OFFLINE_CONFIRMATION_MAX_AMOUNT: 'PLN:100000' }).some((b) => b.startsWith('OFFLINE_CONFIRMATION_MAX_AMOUNT')));
  assert.ok(productionBlockers(offline).some((b) => b.startsWith('OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY is required in production')));
  assert.ok(!productionBlockers({ ...offline, OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY: 10 }).some((b) => b.startsWith('OFFLINE_CONFIRMATION_MAX_PER')));
  assert.deepEqual([...parseOfflineLimits('PLN:100000, EUR:0')], [['PLN', 100000n], ['EUR', 0n]]);
  for (const bad of ['PLN', 'pln:1', 'PLN:-1', 'PLN:01', 'PLN:1,PLN:2', 'PLN:1.5']) {
    assert.throws(() => parseOfflineLimits(bad), /OFFLINE_CONFIRMATION_MAX_AMOUNT/, bad);
    assert.ok(configurationErrors({ ...production, NODE_ENV: 'development', ALLOW_INSECURE_DEVELOPMENT: true, OFFLINE_CONFIRMATION_MAX_AMOUNT: bad }).some((e) => e.includes('OFFLINE_CONFIRMATION_MAX_AMOUNT')), bad);
  }
});

test('FI-008: production requires the PostgreSQL nonce store', () => {
  assert.ok(productionBlockers({ ...production, DEVICE_NONCE_STORE: 'redis' }).some((b) => b.startsWith('DEVICE_NONCE_STORE must be postgres in production')));
  assert.ok(!productionBlockers({ ...production, DEVICE_NONCE_STORE: 'postgres' }).some((b) => b.startsWith('DEVICE_NONCE_STORE')));
});

test('FI-030: production requires a metrics token of at least 32 characters', () => {
  const message = 'METRICS_BEARER_TOKEN of at least 32 characters is required in production (FI-030)';
  assert.ok(productionBlockers({ ...production, METRICS_BEARER_TOKEN: undefined }).includes(message));
  assert.ok(productionBlockers({ ...production, METRICS_BEARER_TOKEN: 'short' }).includes(message));
});

test('FI-005: production requires HSM-wrapped master keys; plaintext and wrapped keys do not mix', () => {
  assert.ok(productionBlockers({ ...production, MASTER_KEY_SOURCE: 'env', WEBHOOK_SECRET_ENCRYPTION_KEY: KEY, ADMIN_SECRET_ENCRYPTION_KEY: KEY })
    .some((b) => b.startsWith('MASTER_KEY_SOURCE must be hsm in production')));
  const dev = { ...production, NODE_ENV: 'development', ALLOW_INSECURE_DEVELOPMENT: true };
  assert.ok(configurationErrors({ ...dev, DEVICE_SECRET_ENCRYPTION_KEY: KEY }).some((e) => e.includes('must not be set in plaintext with MASTER_KEY_SOURCE=hsm')));
  assert.ok(configurationErrors({ ...dev, PKCS11_KEK_LABEL: undefined }).some((e) => e.includes('needs PKCS11_MODULE_PATH, PKCS11_PIN and PKCS11_KEK_LABEL')));
  assert.ok(configurationErrors({ ...dev, DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS_WRAPPED: WRAPPED }).some((e) => e.includes('_PREVIOUS_WRAPPED is set but')));
  assert.ok(configurationErrors({ ...dev, MASTER_KEY_SOURCE: 'env' }).some((e) => e.includes('_WRAPPED is only read with MASTER_KEY_SOURCE=hsm')));
});

test('FI-004: offline confirmation v1 is refused in production and needs the insecure flag elsewhere', () => {
  const offline = { ...production, OFFLINE_CONFIRMATION_ENABLED: true, OFFLINE_CONFIRMATION_MAX_AMOUNT: 'PLN:100000', OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY: 3 };
  assert.ok(!productionBlockers({ ...offline, OFFLINE_CONFIRMATION_MODE: 'deferred_signature' }).some((b) => /OFFLINE_CONFIRMATION_MODE/.test(b)));
  assert.ok(productionBlockers({ ...offline, OFFLINE_CONFIRMATION_MODE: 'immediate' }).some((b) => /OFFLINE_CONFIRMATION_MODE must be deferred_signature/.test(b)));
  const dev = { ...offline, NODE_ENV: 'development', ALLOW_INSECURE_DEVELOPMENT: false, HSM_ADAPTER: 'pkcs11', REQUIRE_MTLS_HEADER: true, ADMIN_MFA_REQUIRED: true };
  assert.ok(configurationErrors({ ...dev, OFFLINE_CONFIRMATION_MODE: 'immediate' }).some((e) => /OFFLINE_CONFIRMATION_MODE=immediate is a development setting/.test(e)));
  assert.ok(!configurationErrors({ ...dev, OFFLINE_CONFIRMATION_MODE: 'deferred_signature' }).some((e) => /OFFLINE_CONFIRMATION_MODE/.test(e)));
});
