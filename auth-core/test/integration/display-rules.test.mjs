// Beneficiary values that could hide the account in the confirmation
// prompt are refused when the bank creates the authorization, before any
// device sees them. The device-side rules are checked against the shared
// vectors (test-vectors/signed-payload-v1.json) by both SDKs.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, call } from './support/actors.mjs';

const IBAN = 'PL61109010140000071219812874';

describe('beneficiary display rules', { skip: skipWithoutServices }, () => {
  let server; let bank; let device;

  before(async () => {
    server = await startAuthCore();
    bank = await bankSession(server, await server.registerBank('bank-display'));
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
  });
  after(async () => { await server?.stop(); });

  const create = (beneficiary) => bank.call('POST', '/v1/authorizations', {
    headers: { 'Idempotency-Key': randomUUID() },
    body: {
      nexusId: device.nexusId, credentialId: device.credentialId, transactionReference: `tx-${randomUUID()}`,
      operationType: 'TRANSFER', amountMinor: '125000', currency: 'PLN', beneficiary, policyReference: 'default', policyVersion: '1',
    },
  });

  test('a 140-character name is accepted and signed verbatim', async () => {
    const name = 'N'.repeat(140);
    const r = await create({ name, iban: IBAN });
    assert.equal(r.status, 201, r.text);
    const fetched = await call(server.baseUrl, 'GET', `/v1/mobile/authorizations/${r.json.authorizationId}`, { device });
    assert.equal(fetched.status, 200, fetched.text);
    const payload = JSON.parse(Buffer.from(fetched.json.canonicalPayloadBase64, 'base64').toString('utf8'));
    assert.equal(payload.beneficiary.name, name);
  });

  for (const [what, beneficiary] of [
    ['141 characters', { name: 'N'.repeat(141), iban: IBAN }],
    ['an empty value', { name: '', iban: IBAN }],
    ['only spaces', { name: '   ', iban: IBAN }],
    ['a leading space', { name: ' Jan Kowalski', iban: IBAN }],
    ['a trailing no-break space', { name: 'Jan Kowalski ', iban: IBAN }],
    ['a padded IBAN', { name: 'Jan Kowalski', iban: `${IBAN} ` }],
  ]) {
    test(`a beneficiary value with ${what} is refused with 400`, async () => {
      const r = await create(beneficiary);
      assert.equal(r.status, 400, r.text);
    });
  }
});
