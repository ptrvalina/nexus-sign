// Device replacement with a hold (audit finding A2-01), on PostgreSQL with the
// full schema and migrations. Until 2.0.0-rc.2 one bank call enrolled a new
// device and revoked the customer's device at once, so whoever held the bank
// backend's credentials could take over any NEXUS ID. Now the replacement is
// a request: the enrolled device approves or cancels it, or it matures after
// DEVICE_REPLACEMENT_HOLD_SECONDS, and enrolment uses it exactly once in the
// transaction that revokes the old device.
//
// Service level: the services run in this process against a real database
// (Redis and metrics are not used by these paths and are stubbed). The HTTP
// routes are covered by the OpenAPI route check and the mTLS exemption test.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
};
const pem = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' }).toString();

describe('device replacement hold (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let services; let hsm; const clientId = `bank-${randomBytes(4).toString('hex')}`;

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.DEVICE_REPLACEMENT_HOLD_SECONDS = '2';
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map(); // one module graph: one pool, ended in after()
    services = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      replacements: loadTs('services/deviceReplacementService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ($1, 'x')`, [clientId]);
  });
  after(async () => { await services?.db.pool.end(); await admin?.end(); await db?.drop(); });

  const enrol = (nexusId, replacement) => services.credentials.createCredential({
    nexusId, publicKeyPem: pem(), platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', attestationStatus: 'VERIFIED', clientId, replacement, hsm,
    enrolment: { reason: replacement ? 'REPLACEMENT' : 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
  });
  const activeCredentials = async (nexusId) => (await admin.query(`SELECT credential_id FROM credentials WHERE nexus_id = $1 AND state = 'ACTIVE'`, [nexusId])).rows.map((r) => r.credential_id);
  async function customerWithDevice() {
    const identity = await services.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`);
    const device = await enrol(identity.nexusId);
    return { nexusId: identity.nexusId, device };
  }

  test('a bank request alone does not replace the device before the hold; the old device stays active', async () => {
    const { nexusId, device } = await customerWithDevice();
    const { replacement, created } = await services.replacements.requestDeviceReplacement(clientId, nexusId, 'OTHER', 'case-1');
    assert.equal(created, true); assert.equal(replacement.state, 'PENDING'); assert.equal(replacement.usable, false);
    // A second request returns the same open one (no new hold, no second request).
    const again = await services.replacements.requestDeviceReplacement(clientId, nexusId, 'BRANCH_VISIT', 'case-2');
    assert.equal(again.created, false); assert.equal(again.replacement.replacementId, replacement.replacementId);
    // Enrolment with the request still on hold, and without any request: refused, nothing revoked.
    await assert.rejects(enrol(nexusId, { method: 'OTHER', reference: 'case-1', replacementId: replacement.replacementId }), /still on hold/);
    await assert.rejects(enrol(nexusId, { method: 'OTHER', reference: 'case-1' }), /needs an approved or matured replacement request/);
    assert.deepEqual(await activeCredentials(nexusId), [device.credentialId]);
    // The bank was told.
    const audit = await admin.query(`SELECT event_type FROM audit_logs WHERE nexus_id = $1 AND event_type = 'credential_replacement_requested'`, [nexusId]);
    assert.equal(audit.rowCount, 1);
  });

  test('the enrolled device cancels: the request can never be used', async () => {
    const { nexusId, device } = await customerWithDevice();
    const { replacement } = await services.replacements.requestDeviceReplacement(clientId, nexusId, 'OTHER', 'case-3');
    const cancelled = await services.replacements.decideDeviceReplacement(device.credentialId, nexusId, replacement.replacementId, 'CANCEL');
    assert.equal(cancelled.state, 'CANCELLED');
    await new Promise((r) => setTimeout(r, 2200)); // past the hold
    await assert.rejects(enrol(nexusId, { method: 'OTHER', reference: 'case-3', replacementId: replacement.replacementId }), /cancelled/);
    await assert.rejects(services.replacements.decideDeviceReplacement(device.credentialId, nexusId, replacement.replacementId, 'APPROVE'), /No pending replacement/);
    assert.deepEqual(await activeCredentials(nexusId), [device.credentialId]);
  });

  test('the enrolled device approves: the hold ends at once, enrolment replaces the device and uses the request once', async () => {
    const { nexusId, device } = await customerWithDevice();
    const { replacement } = await services.replacements.requestDeviceReplacement(clientId, nexusId, 'IN_APP_STRONG_AUTHENTICATION', 'case-4');
    const approved = await services.replacements.decideDeviceReplacement(device.credentialId, nexusId, replacement.replacementId, 'APPROVE');
    assert.equal(approved.state, 'APPROVED'); assert.equal(approved.usable, true);
    const next = await enrol(nexusId, { method: 'IN_APP_STRONG_AUTHENTICATION', reference: 'case-4', replacementId: replacement.replacementId });
    assert.deepEqual(await activeCredentials(nexusId), [next.credentialId]);
    const row = (await admin.query(`SELECT state, used_by_credential_id FROM device_replacements WHERE replacement_id = $1`, [replacement.replacementId])).rows[0];
    assert.equal(row.state, 'USED'); assert.equal(row.used_by_credential_id, next.credentialId);
    // Used once: a second enrolment with the same request is refused and the new device stays.
    await assert.rejects(enrol(nexusId, { method: 'IN_APP_STRONG_AUTHENTICATION', reference: 'case-4', replacementId: replacement.replacementId }), /already used/);
    assert.deepEqual(await activeCredentials(nexusId), [next.credentialId]);
  });

  test('without a decision the request matures after the hold (lost phone)', async () => {
    const { nexusId } = await customerWithDevice();
    const { replacement } = await services.replacements.requestDeviceReplacement(clientId, nexusId, 'BRANCH_VISIT', 'case-5');
    await new Promise((r) => setTimeout(r, 2200));
    const matured = (await services.replacements.requestDeviceReplacement(clientId, nexusId, 'BRANCH_VISIT', 'case-5')).replacement;
    assert.equal(matured.usable, true);
    const next = await enrol(nexusId, { method: 'BRANCH_VISIT', reference: 'case-5', replacementId: replacement.replacementId });
    assert.deepEqual(await activeCredentials(nexusId), [next.credentialId]);
  });

  test('revoking the device first does not skip the hold: a new device needs a matured request', async () => {
    const { nexusId, device } = await customerWithDevice();
    await services.credentials.revokeCredentialForClient(device.credentialId, clientId, 'lost phone');
    // Plain enrolment after the revocation is refused; nothing is enrolled.
    await assert.rejects(enrol(nexusId), /needs an approved or matured replacement request/);
    assert.deepEqual(await activeCredentials(nexusId), []);
    const { replacement } = await services.replacements.requestDeviceReplacement(clientId, nexusId, 'BRANCH_VISIT', 'case-7');
    assert.equal(replacement.usable, false);
    await assert.rejects(enrol(nexusId, { method: 'BRANCH_VISIT', reference: 'case-7', replacementId: replacement.replacementId }), /still on hold/);
    // No enrolled device can approve; the revoked one cannot either.
    await assert.rejects(services.replacements.decideDeviceReplacement(device.credentialId, nexusId, replacement.replacementId, 'APPROVE'), /Only the enrolled device/);
    await new Promise((r) => setTimeout(r, 2200));
    const next = await enrol(nexusId, { method: 'BRANCH_VISIT', reference: 'case-7', replacementId: replacement.replacementId });
    assert.deepEqual(await activeCredentials(nexusId), [next.credentialId]);
    const evidence = (await admin.query(`SELECT sealed_payload AS payload FROM evidence_records WHERE evidence_id = $1`, [next.enrolmentEvidenceId])).rows[0];
    if (evidence) assert.equal(evidence.payload.replacementAuthorization?.reference, 'case-7');
  });

  test('only an active device of the same customer decides, and the database keeps the request history', async () => {
    const a = await customerWithDevice();
    const b = await customerWithDevice();
    const { replacement } = await services.replacements.requestDeviceReplacement(clientId, a.nexusId, 'OTHER', 'case-6');
    await assert.rejects(services.replacements.decideDeviceReplacement(b.device.credentialId, a.nexusId, replacement.replacementId, 'APPROVE'), /Only the enrolled device/);
    await assert.rejects(services.replacements.decideDeviceReplacement(b.device.credentialId, b.nexusId, replacement.replacementId, 'APPROVE'), /No pending replacement/);
    await assert.rejects(admin.query(`DELETE FROM device_replacements WHERE replacement_id = $1`, [replacement.replacementId]), /are kept/);
    await assert.rejects(admin.query(`UPDATE device_replacements SET not_before = now() - interval '1 day' WHERE replacement_id = $1`, [replacement.replacementId]), /only its state changes/);
    await admin.query(`UPDATE device_replacements SET state = 'CANCELLED' WHERE replacement_id = $1`, [replacement.replacementId]);
    await assert.rejects(admin.query(`UPDATE device_replacements SET state = 'APPROVED' WHERE replacement_id = $1`, [replacement.replacementId]), /not permitted/);
  });
});
