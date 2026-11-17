// Lock order between confirming a payment and revoking its device (audit
// finding A1-07). Confirmation locks the authorization row and then reads the
// credential FOR SHARE; revocation used to update the credential first and
// then cancel the authorization, so the two could deadlock (40P01, a 500 to
// one side). Revocation now takes the open authorizations first.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
  '../db/redis': { redis: {} },
};

describe('revoking a device while its payment is being confirmed (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s; let hsm; const clientId = `bank-${randomBytes(4).toString('hex')}`;
  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    s = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ($1, 'x')`, [clientId]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  test('the confirmation holds its authorization, reads the credential, and both sides finish', async () => {
    const identity = await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`);
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const credential = await s.credentials.createCredential({
      nexusId: identity.nexusId, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), platform: 'IOS', securityLevel: 'SECURE_ENCLAVE',
      attestationStatus: 'VERIFIED', clientId, hsm, enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    const authorizationId = randomUUID();
    await admin.query(`INSERT INTO authorization_requests (authorization_id, client_id, nexus_id, credential_id, transaction_reference, operation_type, amount_minor, currency,
        beneficiary, policy_reference, policy_version, canonical_payload_hash, nonce, issued_at, expires_at)
      VALUES ($1::uuid, $2, $3, $4, $1::text, 'TRANSFER', 100, 'EUR', '{}', 'p', '1', repeat('0', 64), $1::text, now(), now() + interval '5 minutes')`,
    [authorizationId, clientId, identity.nexusId, credential.credentialId]);

    // The confirmation (authorizationConfirmation.ts): authorization FOR UPDATE ...
    const confirmation = new pg.Client({ connectionString: db.url });
    await confirmation.connect();
    try {
      await confirmation.query('BEGIN');
      await confirmation.query(`SET LOCAL lock_timeout = '3s'`);
      await confirmation.query(`SELECT 1 FROM authorization_requests WHERE authorization_id = $1 FOR UPDATE`, [authorizationId]);
      // ... meanwhile the bank revokes the device ...
      const revocation = s.credentials.revokeCredentialForClient(credential.credentialId, clientId, 'LOST').then(() => 'done', (e) => e);
      await new Promise((r) => setTimeout(r, 400));
      // ... then the confirmation reads the credential FOR SHARE. With the old
      // order the revocation held the credential and waited for the
      // authorization: a deadlock (40P01) or this read timing out.
      const read = await confirmation.query(`SELECT state FROM credentials WHERE credential_id = $1 FOR SHARE`, [credential.credentialId]);
      assert.equal(read.rows[0].state, 'ACTIVE', 'the revocation has not touched the credential yet');
      await confirmation.query('COMMIT');
      assert.equal(await revocation, 'done', 'the revocation completes after the confirmation');
    } finally {
      await confirmation.end();
    }
    const after = await admin.query(`SELECT (SELECT state FROM credentials WHERE credential_id = $1) AS credential, (SELECT state FROM authorization_requests WHERE authorization_id = $2) AS authorization`,
      [credential.credentialId, authorizationId]);
    assert.deepEqual(after.rows[0], { credential: 'REVOKED', authorization: 'CANCELLED' });
  });
});
