// The console screens of the bank's staff for one customer's mandates and
// devices (bankConsoleService.ts), on PostgreSQL with the full schema: scope
// by bank, read-only platform operators, a bank hold on a mandate that the
// customer cannot lift and the same staff member cannot lift (four eyes),
// sealed events, device revocation and stopping an open device request.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';
import { verifyEvidenceChain } from '../../scripts/lib/evidence.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
};

describe('bank console: mandates and devices (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s; let hsm;
  const clientId = `bank-${randomBytes(4).toString('hex')}`;
  const otherBank = `bank-${randomBytes(4).toString('hex')}`;
  const anna = { username: 'anna', role: 'operator', clientId };
  const ben = { username: 'ben', role: 'operator', clientId };
  const platform = { username: 'platform', role: 'administrator', clientId: null };
  const stranger = { username: 'eve', role: 'administrator', clientId: otherBank };

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    s = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      mandates: loadTs('services/mandateService.ts', { stubs, cache }),
      requests: loadTs('services/deviceReplacementService.ts', { stubs, cache }),
      evidence: loadTs('services/evidenceService.ts', { stubs, cache }),
      console: loadTs('services/bankConsoleService.ts', { stubs, cache }),
      authorizations: loadTs('services/authorizationService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash, max_devices_per_identity, webhook_url, webhook_secret_encrypted)
      VALUES ($1, 'x', 2, 'https://bank.example/hooks', 'sealed'), ($2, 'x', 1, NULL, NULL)`, [clientId, otherBank]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  async function enrolDevice(nexusId, approver) {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    let replacement = null;
    if (approver) {
      const { replacement: request } = await s.requests.requestDeviceReplacement(clientId, nexusId, 'OTHER', 'tablet', 'ADDITION');
      await s.requests.decideDeviceReplacement(approver.credentialId, nexusId, request.replacementId, 'APPROVE');
      replacement = { method: 'OTHER', reference: 'tablet', replacementId: request.replacementId, kind: 'ADDITION' };
    }
    const credential = await s.credentials.createCredential({
      nexusId, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), platform: approver ? 'ANDROID' : 'IOS',
      securityLevel: approver ? 'STRONGBOX' : 'SECURE_ENCLAVE', attestationStatus: 'VERIFIED', clientId, hsm, replacement,
      enrolment: { reason: approver ? 'ADDITION' : 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    return { ...credential, privateKey, device: { clientId, nexusId, credentialId: credential.credentialId } };
  }
  async function customer() {
    const identity = await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`);
    return { nexusId: identity.nexusId, phone: await enrolDevice(identity.nexusId) };
  }
  async function activeMandate(c) {
    const m = await s.mandates.createMandate(clientId, {
      nexusId: c.nexusId, credentialId: c.phone.credentialId, mandateReference: `MANDATE-${randomUUID()}`,
      payee: { iban: 'PL61109010140000071219812874', name: 'Energy Co' }, currency: 'EUR', perPaymentLimitMinor: '15000',
      totalLimitMinor: null, frequency: 'MONTHLY', validFrom: new Date(Date.now() - 60_000).toISOString(),
      validUntil: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(), termsVersion: '2026-11',
    });
    const signature = sign('sha256', Buffer.from(m.termsBase64, 'base64'), { key: c.phone.privateKey, dsaEncoding: 'der' }).toString('base64');
    return s.mandates.signMandate(hsm, c.phone.device, m.mandateId, signature, 'der');
  }
  const debit = (m, amountMinor) => s.mandates.requestMandateDebit(clientId, m.mandateId, { debitReference: randomUUID(), amountMinor, currency: 'EUR' });
  const keys = async () => ({ [await hsm.evidenceKeyId()]: await hsm.evidencePublicKeyPem() });
  const chain = async (nexusId) => (await admin.query(`SELECT * FROM evidence_records WHERE nexus_id = $1 ORDER BY chain_sequence`, [nexusId])).rows.map((r) => s.evidence.mapEvidenceRow(r));

  test('staff see the bank\'s mandates with debits, sealed records and event log; other banks see nothing', async () => {
    const c = await customer();
    const m = await activeMandate(c);
    assert.equal((await debit(m, '9000')).decision, 'ALLOWED');
    const listed = await s.console.consoleMandates(anna, c.nexusId);
    assert.deepEqual(listed.map((x) => x.mandateId), [m.mandateId]);
    const detail = await s.console.consoleMandate(anna, m.mandateId);
    assert.equal(detail.mandate.state, 'ACTIVE');
    assert.equal(detail.debits.length, 1); assert.equal(detail.debits[0].amountMinor, '9000');
    assert.deepEqual(detail.evidence.map((r) => r.sealedPayload.event), ['SIGNED']);
    assert.ok(detail.events.some((e) => e.to === 'ACTIVE'));
    // A platform operator reads; the staff of another bank do not see the customer or the mandate.
    assert.equal((await s.console.consoleMandate(platform, m.mandateId)).mandate.mandateId, m.mandateId);
    await assert.rejects(s.console.consoleMandates(stranger, c.nexusId), /not found/i);
    await assert.rejects(s.console.consoleMandate(stranger, m.mandateId), /not found/i);
    // Every view is in the audit log under the staff member's name.
    const viewed = await admin.query(`SELECT actor FROM audit_logs WHERE event_type = 'admin_mandates_viewed' AND nexus_id = $1`, [c.nexusId]);
    assert.ok(viewed.rows.some((r) => r.actor === 'admin:anna'));
  });

  test('a bank hold stops debits; the customer and the same staff member cannot lift it; a second staff member can', async () => {
    const c = await customer();
    const m = await activeMandate(c);
    await assert.rejects(s.console.consoleMandateAction(hsm, platform, m.mandateId, 'HOLD', 'fraud check'), /bank's own staff/);
    await assert.rejects(s.console.consoleMandateAction(hsm, stranger, m.mandateId, 'HOLD', 'fraud check'), /not found/i);
    const held = await s.console.consoleMandateAction(hsm, anna, m.mandateId, 'HOLD', 'fraud check');
    assert.equal(held.state, 'SUSPENDED'); assert.match(held.stateReason, /^SUSPENDED_BY_BANK:anna:/);
    const refused = await debit(m, '1000');
    assert.equal(refused.decision, 'REFUSED'); assert.equal(refused.reason, 'MANDATE_NOT_ACTIVE');
    await assert.rejects(s.mandates.customerMandateAction(hsm, c.phone.device, m.mandateId, 'RESUME'), (e) => e.code === 'MANDATE_HELD_BY_BANK');
    await assert.rejects(s.console.consoleMandateAction(hsm, anna, m.mandateId, 'RELEASE', ''), (e) => e.code === 'SAME_STAFF_MEMBER');
    const released = await s.console.consoleMandateAction(hsm, ben, m.mandateId, 'RELEASE', '');
    assert.equal(released.state, 'ACTIVE');
    assert.equal((await debit(m, '1000')).decision, 'ALLOWED');
    // A suspension by the customer is not a bank hold: staff do not "release" it.
    await s.mandates.customerMandateAction(hsm, c.phone.device, m.mandateId, 'SUSPEND');
    await assert.rejects(s.console.consoleMandateAction(hsm, ben, m.mandateId, 'RELEASE', ''), (e) => e.code === 'MANDATE_STATE_CONFLICT');
    const sealed = (await chain(c.nexusId)).filter((r) => r.recordType === 'MANDATE').map((r) => r.sealedPayload.event);
    assert.deepEqual(sealed, ['SIGNED', 'SUSPENDED', 'RESUMED', 'SUSPENDED']);
    assert.deepEqual(verifyEvidenceChain(await chain(c.nexusId), await keys()), []);
    const actors = (await s.console.consoleMandate(anna, m.mandateId)).events.map((e) => e.actor);
    assert.ok(actors.includes('admin:anna') && actors.includes('admin:ben'));
  });

  test('staff withdraw a mandate from the console; it is final', async () => {
    const c = await customer();
    const m = await activeMandate(c);
    const withdrawn = await s.console.consoleMandateAction(hsm, ben, m.mandateId, 'WITHDRAW', 'customer called');
    assert.equal(withdrawn.state, 'WITHDRAWN'); assert.match(withdrawn.stateReason, /CONSOLE:ben:customer called/);
    await assert.rejects(s.console.consoleMandateAction(hsm, anna, m.mandateId, 'HOLD', 'x'), (e) => e.code === 'MANDATE_STATE_CONFLICT');
    assert.deepEqual(verifyEvidenceChain(await chain(c.nexusId), await keys()), []);
  });

  test('the payments screen lists the customer\'s authorizations with their state; other banks see nothing', async () => {
    const c = await customer();
    const created = await s.authorizations.createAuthorization({
      nexusId: c.nexusId, credentialId: c.phone.credentialId, transactionReference: `TX-${randomUUID()}`, operationType: 'TRANSFER',
      amountMinor: '125000', currency: 'EUR', beneficiary: { iban: 'PL61109010140000071219812874', name: 'Jan Kowalski' }, policyReference: 'default', policyVersion: '1',
    }, clientId);
    const listed = await s.console.consoleAuthorizations(anna, c.nexusId);
    assert.deepEqual(listed.map((a) => [a.authorizationId, a.state, a.amountMinor]), [[created.authorization.authorizationId, 'PENDING_USER', '125000']]);
    assert.deepEqual(await s.console.consoleAuthorizations(anna, c.nexusId, { filter: 'confirmed' }), []);
    assert.equal((await s.console.consoleAuthorizations(platform, c.nexusId)).length, 1);
    await assert.rejects(s.console.consoleAuthorizations(stranger, c.nexusId), /not found/i);
  });

  test('the device screen lists devices, requests, the bank limit and events; staff revoke a device and stop an open request', async () => {
    const c = await customer();
    const tablet = await enrolDevice(c.nexusId, c.phone);
    const view = await s.console.consoleDevices(anna, c.nexusId);
    assert.equal(view.maxDevicesPerIdentity, 2);
    assert.deepEqual(view.devices.map((d) => [d.platform, d.state, d.enrolmentReason]).sort(), [['ANDROID', 'ACTIVE', 'ADDITION'], ['IOS', 'ACTIVE', 'ENROLMENT']]);
    assert.deepEqual(view.requests.map((r) => [r.kind, r.state]), [['ADDITION', 'USED']]);
    assert.ok(view.securityEvents.some((e) => e.eventType === 'credential_created' || e.eventType === 'credential_added'));
    await assert.rejects(s.console.consoleDevices(stranger, c.nexusId), /not found/i);

    await assert.rejects(s.console.consoleRevokeDevice(platform, c.nexusId, tablet.credentialId, 'lost'), /bank's own staff/);
    const other = await customer();
    await assert.rejects(s.console.consoleRevokeDevice(anna, other.nexusId, tablet.credentialId, 'lost'), /not found/i);
    await s.console.consoleRevokeDevice(anna, c.nexusId, tablet.credentialId, 'reported lost by phone');
    await assert.rejects(s.console.consoleRevokeDevice(anna, c.nexusId, tablet.credentialId, 'again'), (e) => e.code === 'CREDENTIAL_NOT_ACTIVE');
    const after = await s.console.consoleDevices(ben, c.nexusId);
    assert.equal(after.devices.find((d) => d.credentialId === tablet.credentialId).state, 'REVOKED');
    // The revocation is recorded in its transaction and sealed by the outcome sealer (evidenceService.sealPendingOutcomes).
    while (await s.evidence.sealPendingOutcomes(hsm) > 0);
    const revoked = (await chain(c.nexusId)).filter((r) => r.recordType === 'CREDENTIAL_REVOKED');
    assert.equal(revoked.length, 1); assert.match(revoked[0].sealedPayload.reason, /CONSOLE:anna/);

    // An addition the customer did not ask for is stopped by the staff.
    const { replacement } = await s.requests.requestDeviceReplacement(clientId, c.nexusId, 'OTHER', 'unexpected', 'ADDITION');
    const cancelled = await s.console.consoleCancelDeviceRequest(ben, c.nexusId, replacement.replacementId);
    assert.equal(cancelled.state, 'CANCELLED');
    await assert.rejects(s.console.consoleCancelDeviceRequest(ben, c.nexusId, replacement.replacementId), (e) => e.code === 'REPLACEMENT_NOT_PENDING');
    const hook = await admin.query(`SELECT payload FROM webhook_deliveries WHERE client_id = $1 AND event_type = 'credential.replacement_cancelled' ORDER BY created_at DESC LIMIT 1`, [clientId]);
    assert.equal(hook.rows[0].payload.by, 'BANK_STAFF');
    assert.deepEqual(verifyEvidenceChain(await chain(c.nexusId), await keys()), []);
  });
});
