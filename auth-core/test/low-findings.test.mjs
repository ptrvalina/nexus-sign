// Regression tests for LOW findings fixed in 2.0.0-rc.1 that need no
// database: NXS-033 (canonicalizer, see property-fuzz.test.mjs), NXS-034,
// NXS-035, NXS-037.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { loadTs } from './support/load-ts.mjs';

const key = randomBytes(32).toString('base64');
const envStub = (overrides = {}) => ({ '../config/env': { env: { WEBHOOK_SECRET_ENCRYPTION_KEY: key, DEVICE_SECRET_ENCRYPTION_KEY: key, NODE_ENV: 'test', ...overrides } } });

test('NXS-034: a device nonce outlives the whole timestamp window', () => {
  const { deviceNonceTtlSeconds } = loadTs('middleware/mobileAuth.ts', {
    stubs: { '../db/redis': { redis: {} }, '../db/pool': { pool: {} }, '../config/env': { env: {} } },
  });
  for (const skew of [30, 300, 900]) {
    // First seen at T - skew, still acceptable at T + skew (+1 s rounding).
    assert.ok(deviceNonceTtlSeconds(skew) > 2 * skew + 1, String(skew));
  }
});

test('NXS-035: a webhook secret is bound to its bank client; 1.4 ciphertexts still decrypt', () => {
  const { encryptSecret, decryptSecret } = loadTs('crypto/secretBox.ts', { stubs: envStub() });
  const stored = encryptSecret('whsec-bank-a', 'webhook', 'bank-a');
  assert.match(stored, /^v2\$/);
  assert.equal(decryptSecret(stored, 'webhook', 'bank-a'), 'whsec-bank-a');
  assert.throws(() => decryptSecret(stored, 'webhook', 'bank-b'), 'copied to another bank\'s row');
  assert.throws(() => encryptSecret('x', 'webhook'), /bound to their bank client/);

  // 1.4 format: iv$tag$ciphertext without associated data.
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key, 'base64'), iv);
  const ct = Buffer.concat([cipher.update('legacy-secret'), cipher.final()]);
  const legacy = [iv.toString('base64'), cipher.getAuthTag().toString('base64'), ct.toString('base64')].join('$');
  assert.equal(decryptSecret(legacy, 'webhook', 'bank-a'), 'legacy-secret');
});

test('NXS-037: production refuses an APNs DEVELOPMENT registration', async () => {
  const load = (NODE_ENV) => loadTs('services/pushRegistrationService.ts', {
    stubs: {
      ...envStub({ NODE_ENV }),
      '../db/pool': { pool: { query: async () => { throw new Error('reached the database'); } }, withTransaction: async () => { throw new Error('reached the database'); } },
      './clientService': { getClientPushMode: async () => 'NEXUS' },
    },
  });
  const device = { credentialId: '00000000-0000-4000-8000-000000000002', clientId: 'bank', nexusId: '123456789', platform: 'IOS' };
  const input = { provider: 'APNS', apnsEnvironment: 'DEVELOPMENT', deviceToken: 'a'.repeat(64), keyId: 'AAAAAAAAAAAAAAAAAAAAAA' };
  await assert.rejects(load('production').registerPushDevice(device, input), /DEVELOPMENT is not accepted in production/);
  // Outside production the request gets past validation (and stops at the stubbed database).
  await assert.rejects(load('development').registerPushDevice(device, input), (error) => !/DEVELOPMENT/.test(error.message));
});
