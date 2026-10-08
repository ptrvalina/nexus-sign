import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './support/load-ts.mjs';

const CREDENTIAL = '00000000-0000-4000-8000-000000000002';

function middleware({ session, clientStatus = 'ACTIVE' }) {
  class CredentialIntegrityError extends Error {}
  const stubs = {
    '../config/env': { env: { DEVICE_REQUEST_MAX_SKEW_SECONDS: 300, DEVICE_REQUEST_PATH_PREFIX: '' } },
    '../db/redis': { redis: {} },
    '../services/mobileSessionService': { resolveMobileSession: async () => session },
    '../services/nexusIdentityService': { getNexusIdentityStatus: async () => 'ACTIVE' },
    '../services/clientService': { getClientRecord: async () => ({ status: clientStatus }) },
    '../services/credentialService': { getActiveDeviceCredential: async () => null },
    '../services/credentialIntegrity': { CredentialIntegrityError, assertCredentialIntegrity: async () => 'hash' },
  };
  return loadTs('middleware/mobileAuth.ts', { stubs }).authenticateMobileSession;
}

async function run(authenticate) {
  const out = { status: 200, body: null, next: false };
  const req = { header: (name) => (name.toLowerCase() === 'authorization' ? 'Bearer ms_token' : undefined) };
  const res = { status(code) { out.status = code; return this; }, json(body) { out.body = body; } };
  await authenticate(req, res, (error) => { if (error) throw error; out.next = true; });
  return { ...out, req };
}

const bootstrap = { clientId: 'bank-a', nexusId: '123456789', purpose: 'BOOTSTRAP', attestationChallenge: 'challenge' };

test('a BOOTSTRAP token authorizes enrolment only, without a credential', async () => {
  const result = await run(middleware({ session: bootstrap }));
  assert.equal(result.next, true);
  assert.equal(result.req.mobileSessionPurpose, 'BOOTSTRAP');
  assert.equal(result.req.mobileCredentialId, undefined);
});

test('SESSION tokens left in Redis by 1.x or 2.0.0-rc.1 are refused (no bearer token for enrolled devices)', async () => {
  const legacy = { clientId: 'bank-a', nexusId: '123456789', purpose: 'SESSION', credentialId: CREDENTIAL };
  const result = await run(middleware({ session: legacy }));
  assert.equal(result.status, 401);
  assert.equal(result.next, false);
});

test('mobile tokens of a disabled bank client are refused', async () => {
  assert.equal((await run(middleware({ session: bootstrap, clientStatus: 'DISABLED' }))).status, 401);
});

test('the token store returns only BOOTSTRAP tokens', async () => {
  const stored = new Map();
  const redis = { get: async (k) => stored.get(k) ?? null, getdel: async (k) => { const v = stored.get(k) ?? null; stored.delete(k); return v; } };
  const { resolveMobileSession, consumeMobileSession } = loadTs('services/mobileSessionService.ts', {
    stubs: { '../db/redis': { redis }, '../crypto/tokenDigest': { tokenKey: (prefix, token) => prefix + token } },
  });
  stored.set('mobile_session:ms_legacy', JSON.stringify({ clientId: 'bank-a', nexusId: '123456789', purpose: 'SESSION', credentialId: CREDENTIAL }));
  stored.set('mobile_session:ms_boot', JSON.stringify(bootstrap));
  assert.equal(await resolveMobileSession('ms_legacy'), null);
  assert.equal(await consumeMobileSession('ms_legacy'), null);
  assert.equal((await resolveMobileSession('ms_boot')).purpose, 'BOOTSTRAP');
});
