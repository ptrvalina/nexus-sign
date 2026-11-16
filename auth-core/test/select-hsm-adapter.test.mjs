// The in-memory development HSM must never seal evidence outside development
// (audit finding B-03): its key is lost at exit and the seals it made can
// never be verified again.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './support/load-ts.mjs';

const stubs = { '../config/env': { env: {} } };
const { selectHsmAdapter } = loadTs('crypto/selectHsmAdapter.ts', { stubs });

test('the software HSM adapter is refused in production and without ALLOW_INSECURE_DEVELOPMENT', async () => {
  await assert.rejects(selectHsmAdapter({ HSM_ADAPTER: 'software', NODE_ENV: 'production', ALLOW_INSECURE_DEVELOPMENT: true }), /refused/);
  await assert.rejects(selectHsmAdapter({ HSM_ADAPTER: 'software', NODE_ENV: 'production', ALLOW_INSECURE_DEVELOPMENT: false }), /refused/);
  await assert.rejects(selectHsmAdapter({ HSM_ADAPTER: 'software', NODE_ENV: 'test', ALLOW_INSECURE_DEVELOPMENT: false }), /refused/);
  await assert.rejects(selectHsmAdapter({ HSM_ADAPTER: 'software', NODE_ENV: 'development', ALLOW_INSECURE_DEVELOPMENT: false }), /refused/);
});

test('the software HSM adapter is available for development with ALLOW_INSECURE_DEVELOPMENT', async () => {
  const hsm = await selectHsmAdapter({ HSM_ADAPTER: 'software', NODE_ENV: 'development', ALLOW_INSECURE_DEVELOPMENT: true });
  assert.match(await hsm.evidencePublicKeyPem(), /BEGIN PUBLIC KEY/);
});
