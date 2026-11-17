// Once attestation is required, credentials enrolled without
// verified attestation cannot approve new transactions.
import { after, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createDatabase, skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession } from './support/actors.mjs';

describe('attestation requirement for existing credentials', { skip: skipWithoutServices }, () => {
  let db; let server;
  after(async () => { await server?.stop(); await db?.drop(); });

  test('an UNKNOWN credential is refused after REQUIRE_VALID_ATTESTATION is switched on', async () => {
    db = await createDatabase();
    const first = await startAuthCore({ database: db });
    const creds = await first.registerBank('bank-attest');
    const enrolling = await bankSession(first, creds);
    const device = await enrolling.enrolDevice((await enrolling.createIdentity()).nexusId);
    await first.stop();

    server = await startAuthCore({ database: db, env: { REQUIRE_VALID_ATTESTATION: 'true' } });
    const bank = await bankSession(server, creds);
    const refused = await bank.call('POST', '/v1/authorizations', {
      body: { nexusId: device.nexusId, credentialId: device.credentialId, transactionReference: 'T-1', operationType: 'TRANSFER', amountMinor: '100', currency: 'PLN',
        beneficiary: { name: 'Jan', iban: 'PL61109010140000071219812874' }, policyReference: 'p', policyVersion: '1' },
      headers: { 'Idempotency-Key': 'k-1' },
    });
    assert.equal(refused.status, 409, refused.text);
    assert.equal(refused.json.code, 'CREDENTIAL_NOT_ATTESTED');
  });
});
