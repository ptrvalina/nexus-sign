// FI-004: an offline code is an HMAC under a key Auth Core also holds, so the
// deployment caps the amount it may confirm, per currency. Above the cap (or
// in a currency not listed) no QR challenge is issued and a code is refused,
// without using up an attempt; device-signature confirmation is unaffected.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, offlineCode, submitSignature } from './support/actors.mjs';

describe('offline confirmation limits', { skip: skipWithoutServices }, () => {
  let server; let bank; let device;
  before(async () => {
    // v1 (code only), so that an accepted code reads VERIFIED; the caps apply
    // to v2 in the same code path (offline-deferred-signature.test.mjs).
    server = await startAuthCore({ env: { OFFLINE_CONFIRMATION_MODE: 'immediate', OFFLINE_CONFIRMATION_MAX_AMOUNT: 'PLN:100000' } });
    bank = await bankSession(server, await server.registerBank('bank-offline-limits'));
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
  });
  after(async () => { await server?.stop(); });

  const offline = async (auth) => {
    const { canonical } = await deviceSignature(server, device, auth.authorizationId);
    return bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(device, canonical) } });
  };

  test('at or below the cap: challenge and code work', async () => {
    const auth = await bank.createAuthorization(device, { amountMinor: '100000' });
    assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/offline-challenge`)).status, 200);
    assert.equal((await offline(auth)).json.status, 'VERIFIED');
  });

  test('above the cap: no challenge, a correct code is refused, no attempt used, signing still works', async () => {
    const auth = await bank.createAuthorization(device, { amountMinor: '100001' });
    const challenge = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/offline-challenge`);
    assert.equal(challenge.status, 409);
    assert.equal(challenge.json.code, 'OFFLINE_LIMIT_EXCEEDED');
    const refused = await offline(auth);
    assert.equal(refused.json.status, 'FAILED');
    assert.match(refused.json.reason, /exceeds the offline confirmation limit for PLN/);
    const attempts = await server.db.query(`SELECT count(*)::int AS n FROM authorization_attempts WHERE authorization_id = $1`, [auth.authorizationId]);
    assert.equal(attempts.rows[0].n, 0);
    const { signature } = await deviceSignature(server, device, auth.authorizationId);
    assert.equal((await submitSignature(server, device, auth.authorizationId, signature)).json.status, 'VERIFIED');
  });

  test('a currency without a cap is not offered offline', async () => {
    const auth = await bank.createAuthorization(device, { amountMinor: '100', currency: 'EUR' });
    const challenge = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/offline-challenge`);
    assert.equal(challenge.status, 409);
    assert.match(challenge.json.error, /not offered for EUR/);
    assert.equal((await offline(auth)).json.status, 'FAILED');
  });
});
