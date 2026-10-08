// NXS-007 / NXS-038: the built server refuses to start in a configuration
// that would switch off a production control, and says why.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { skipWithoutServices, startExpectingFailure } from './support/harness.mjs';

describe('production startup posture', { skip: skipWithoutServices }, () => {
  test('NODE_ENV must be set explicitly', async () => {
    const { code, log } = await startExpectingFailure({ NODE_ENV: undefined });
    assert.notEqual(code, 0);
    assert.notEqual(code, 'still-running');
    assert.match(log, /NODE_ENV/);
  });

  test('outside production, insecure settings need ALLOW_INSECURE_DEVELOPMENT', async () => {
    const { code, log } = await startExpectingFailure({ ALLOW_INSECURE_DEVELOPMENT: undefined });
    assert.notEqual(code, 'still-running');
    for (const setting of ['HSM_ADAPTER=software', 'REQUIRE_VALID_ATTESTATION=false', 'ADMIN_MFA_REQUIRED=false']) assert.match(log, new RegExp(setting));
  });

  test('production with development settings lists every blocker and exits', async () => {
    const { code, log } = await startExpectingFailure({ NODE_ENV: 'production', ALLOW_INSECURE_DEVELOPMENT: undefined });
    assert.notEqual(code, 'still-running');
    assert.notEqual(code, 0);
    for (const blocker of ['HSM_ADAPTER must be pkcs11', 'REQUIRE_VALID_ATTESTATION must be true', 'ADMIN_COOKIE_SECURE must be true',
      'ADMIN_MFA_REQUIRED must be true', 'REQUIRE_MTLS_HEADER must be true', 'DATABASE_SSL must be true', 'REDIS_URL must use rediss://']) {
      assert.ok(log.includes(blocker), `${blocker} reported:\n${log.slice(0, 2000)}`);
    }
  });
});
