// Several active devices per NEXUS ID (migration 027), on PostgreSQL with the
// full schema. A further device joins only through an addition request that
// an enrolled device approves (or whose hold passes), up to the bank's limit,
// which the database enforces too; the customer removes a device from another
// one; a replacement still revokes every active device.
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
};
const pem = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' }).toString();

describe('multiple devices (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s; let hsm; const clientId = `bank-${randomBytes(4).toString('hex')}`;

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.DEVICE_REPLACEMENT_HOLD_SECONDS = '2';
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    s = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      requests: loadTs('services/deviceReplacementService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ($1, 'x')`, [clientId]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  const setLimit = (n) => admin.query(`UPDATE bank_clients SET max_devices_per_identity = $2 WHERE client_id = $1`, [clientId, n]);
  const enrol = (nexusId, replacement) => s.credentials.createCredential({
    nexusId, publicKeyPem: pem(), platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', attestationStatus: 'VERIFIED', clientId, replacement, hsm,
    enrolment: { reason: replacement ? (replacement.kind === 'ADDITION' ? 'ADDITION' : 'REPLACEMENT') : 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
  });
  const active = async (nexusId) => (await admin.query(`SELECT credential_id FROM credentials WHERE nexus_id = $1 AND state = 'ACTIVE' ORDER BY created_at`, [nexusId])).rows.map((r) => r.credential_id);
  async function customer() {
    const identity = await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`);
    return { nexusId: identity.nexusId, phone: await enrol(identity.nexusId) };
  }
  async function addDevice(nexusId, approver) {
    const { replacement } = await s.requests.requestDeviceReplacement(clientId, nexusId, 'IN_APP_STRONG_AUTHENTICATION', 'add', 'ADDITION');
    await s.requests.decideDeviceReplacement(approver.credentialId, nexusId, replacement.replacementId, 'APPROVE');
    return enrol(nexusId, { method: 'IN_APP_STRONG_AUTHENTICATION', reference: 'add', replacementId: replacement.replacementId, kind: 'ADDITION' });
  }

  test('with the default limit of one device an addition is refused', async () => {
    await setLimit(1);
    const { nexusId, phone } = await customer();
    await assert.rejects(s.requests.requestDeviceReplacement(clientId, nexusId, 'OTHER', 'tablet', 'ADDITION'), /bank's limit/);
    assert.deepEqual(await active(nexusId), [phone.credentialId]);
  });

  test('an approved addition adds a device and revokes none; the limit holds', async () => {
    await setLimit(2);
    const { nexusId, phone } = await customer();
    const { replacement } = await s.requests.requestDeviceReplacement(clientId, nexusId, 'OTHER', 'tablet', 'ADDITION');
    assert.equal(replacement.kind, 'ADDITION'); assert.equal(replacement.usable, false);
    // Not yet approved: refused, nothing changes.
    await assert.rejects(enrol(nexusId, { method: 'OTHER', reference: 'tablet', replacementId: replacement.replacementId, kind: 'ADDITION' }), /still on hold/);
    await s.requests.decideDeviceReplacement(phone.credentialId, nexusId, replacement.replacementId, 'APPROVE');
    const tablet = await enrol(nexusId, { method: 'OTHER', reference: 'tablet', replacementId: replacement.replacementId, kind: 'ADDITION' });
    assert.deepEqual(await active(nexusId), [phone.credentialId, tablet.credentialId]);
    const record = (await admin.query(`SELECT sealed_payload FROM evidence_records WHERE credential_id = $1 AND record_type = 'CREDENTIAL_ENROLLED'`, [tablet.credentialId])).rows[0];
    assert.match(JSON.stringify(record.sealed_payload), /"reason":"ADDITION"/);
    await assert.rejects(s.requests.requestDeviceReplacement(clientId, nexusId, 'OTHER', 'third', 'ADDITION'), /bank's limit/);
  });

  test('an addition request cannot be used as a replacement, nor a replacement as an addition', async () => {
    await setLimit(2);
    const { nexusId, phone } = await customer();
    const { replacement: add } = await s.requests.requestDeviceReplacement(clientId, nexusId, 'OTHER', 'x', 'ADDITION');
    await s.requests.decideDeviceReplacement(phone.credentialId, nexusId, add.replacementId, 'APPROVE');
    // A replacement token naming an addition request: refused, the phone stays.
    await assert.rejects(enrol(nexusId, { method: 'OTHER', reference: 'x', replacementId: add.replacementId, kind: 'REPLACEMENT' }), /REPLACEMENT_NOT_USABLE|still on hold|already used|cancelled/);
    assert.deepEqual(await active(nexusId), [phone.credentialId]);
    // While the addition is open, a replacement request is refused, not merged.
    await assert.rejects(s.requests.requestDeviceReplacement(clientId, nexusId, 'OTHER', 'y', 'REPLACEMENT'), /already open/);
  });

  test('the database enforces the limit also for concurrent writers', async () => {
    await setLimit(2);
    const { nexusId } = await customer();
    const insert = () => admin.query(`INSERT INTO credentials (credential_id, nexus_id, key_algorithm, public_key_pem, platform, security_level, state)
      VALUES ($1, $2, 'ES256', 'pem', 'OTHER', 'SOFTWARE', 'ACTIVE')`, [randomUUID(), nexusId]);
    const second = new pg.Client({ connectionString: db.url }); await second.connect();
    try {
      const other = () => second.query(`INSERT INTO credentials (credential_id, nexus_id, key_algorithm, public_key_pem, platform, security_level, state)
        VALUES ($1, $2, 'ES256', 'pem', 'OTHER', 'SOFTWARE', 'ACTIVE')`, [randomUUID(), nexusId]);
      const results = await Promise.allSettled([insert(), other()]);
      assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
      assert.match(String(results.find((r) => r.status === 'rejected').reason.message), /limit of its bank/);
    } finally { await second.end(); }
    assert.equal((await active(nexusId)).length, 2);
  });

  test('the customer removes a device from another one; open payments of that device end CANCELLED', async () => {
    await setLimit(2);
    const { nexusId, phone } = await customer();
    const tablet = await addDevice(nexusId, phone);
    const authId = randomUUID();
    await admin.query(`INSERT INTO authorization_requests (authorization_id, client_id, nexus_id, credential_id, transaction_reference, operation_type, amount_minor, currency, beneficiary, policy_reference, policy_version, canonical_payload_hash, nonce, issued_at, expires_at)
      VALUES ($1::uuid, $2, $3, $4, $1::text, 'TRANSFER', 100, 'EUR', '{}', 'p', '1', repeat('0', 64), $1::text, now(), now() + interval '5 minutes')`, [authId, clientId, nexusId, phone.credentialId]);
    const result = await s.credentials.revokeDeviceByCustomer(clientId, nexusId, tablet.credentialId, phone.credentialId);
    assert.equal(result.remainingActive, 1);
    assert.deepEqual(await active(nexusId), [tablet.credentialId]);
    assert.equal((await admin.query(`SELECT state FROM authorization_requests WHERE authorization_id = $1`, [authId])).rows[0].state, 'CANCELLED');
    const outcome = (await admin.query(`SELECT reason FROM evidence_outcomes WHERE credential_id = $1 AND subject = 'CREDENTIAL'`, [phone.credentialId])).rows[0];
    assert.match(outcome.reason, /REVOKED_BY_CUSTOMER/);
    // A removed device can remove nothing.
    await assert.rejects(s.credentials.revokeDeviceByCustomer(clientId, nexusId, phone.credentialId, tablet.credentialId), /Only an active device/);
    // Nor can a device of another customer.
    const other = await customer();
    await assert.rejects(s.credentials.revokeDeviceByCustomer(clientId, nexusId, other.phone.credentialId, tablet.credentialId), /Only an active device/);
  });

  test('a replacement revokes every active device', async () => {
    await setLimit(3);
    const { nexusId, phone } = await customer();
    await addDevice(nexusId, phone);
    const { replacement } = await s.requests.requestDeviceReplacement(clientId, nexusId, 'BRANCH_VISIT', 'lost', 'REPLACEMENT');
    await s.requests.decideDeviceReplacement(phone.credentialId, nexusId, replacement.replacementId, 'APPROVE');
    const next = await enrol(nexusId, { method: 'BRANCH_VISIT', reference: 'lost', replacementId: replacement.replacementId, kind: 'REPLACEMENT' });
    assert.deepEqual(await active(nexusId), [next.credentialId]);
  });
});
