// Expiry is visible to every read path at once, the sweep moves overdue
// authorizations to EXPIRED with their plan and open sessions, and the bank is
// notified. (part): a confirmation notifies the bank with the chain head.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, call, deviceSignature, submitSignature } from './support/actors.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('authorization expiry', { skip: skipWithoutServices }, () => {
  let server; let bank; let device;
  before(async () => {
    server = await startAuthCore({ env: { AUTHORIZATION_EXPIRY_SWEEP_MS: '500' } });
    bank = await bankSession(server, await server.registerBank('bank-expiry', { webhookUrl: 'https://hooks.bank.example/nexus' }));
    await server.verificationSetup('operator', 'bank-expiry', 'AUDIO,VIDEO');
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
  });
  after(async () => { await server?.stop(); });

  // The test moves expires_at into the past instead of waiting (allowed for a
  // PENDING_USER row; a final row's expiry is immutable).
  const backdate = (id) => server.db.query(`UPDATE authorization_requests SET expires_at = now() - interval '1 second' WHERE authorization_id = $1`, [id]);
  const stateInDb = async (id) => (await server.db.query(`SELECT state FROM authorization_requests WHERE authorization_id = $1`, [id])).rows[0].state;

  test('bank and device read paths report EXPIRED as soon as expiresAt has passed', async () => {
    const auth = await bank.createAuthorization(device, { verificationPolicy: { requireAudio: true } });
    // Expiry 1.5 s ahead, then the row is locked so the sweep (SKIP LOCKED)
    // cannot move it while the read paths are checked after the expiry.
    await server.db.query(`UPDATE authorization_requests SET expires_at = now() + interval '1500 milliseconds' WHERE authorization_id = $1`, [auth.authorizationId]);
    const holder = await server.db.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(`SELECT 1 FROM authorization_requests WHERE authorization_id = $1 FOR UPDATE`, [auth.authorizationId]);
      await sleep(1700);
      const bankView = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}`);
      assert.equal(bankView.json.state, 'EXPIRED');
      const deviceView = await call(server.baseUrl, 'GET', `/v1/mobile/authorizations/${auth.authorizationId}`, { device });
      assert.equal(deviceView.json.state, 'EXPIRED');
      assert.equal(await stateInDb(auth.authorizationId), 'PENDING_USER', 'not yet swept: the row is locked');
    } finally {
      await holder.query('ROLLBACK');
      holder.release();
    }
  });

  test('the sweep expires the authorization, its plan and open sessions, and notifies the bank', async () => {
    const auth = await bank.createAuthorization(device, { verificationPolicy: { requireAudio: true } });
    const session = await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/verification-sessions`, { body: { channel: 'AUDIO' } });
    assert.equal(session.status, 201, session.text);
    await backdate(auth.authorizationId);
    for (let i = 0; i < 40 && (await stateInDb(auth.authorizationId)) !== 'EXPIRED'; i += 1) await sleep(100);
    assert.equal(await stateInDb(auth.authorizationId), 'EXPIRED');
    const plan = await server.db.query(`SELECT status FROM authorization_verification_plans WHERE authorization_id = $1`, [auth.authorizationId]);
    assert.equal(plan.rows[0].status, 'EXPIRED');
    const sessions = await server.db.query(`SELECT status FROM verification_sessions WHERE authorization_id = $1`, [auth.authorizationId]);
    assert.deepEqual(sessions.rows.map((r) => r.status), ['EXPIRED']);
    const webhook = await server.db.query(`SELECT payload FROM webhook_deliveries WHERE event_type = 'authorization.expired' AND payload->>'authorizationId' = $1`, [auth.authorizationId]);
    assert.equal(webhook.rows.length, 1);
    assert.equal(webhook.rows[0].payload.transactionReference, auth.transactionReference);
    const audit = await server.db.query(`SELECT actor FROM audit_logs WHERE event_type = 'authorization_expired' AND details->>'authorizationId' = $1`, [auth.authorizationId]);
    assert.deepEqual(audit.rows.map((r) => r.actor), ['system:expiry']);
  });

  test('a signature after expiry is refused with 410 and the authorization is not swept twice', async () => {
    const auth = await bank.createAuthorization(device);
    const { signature } = await deviceSignature(server, device, auth.authorizationId);
    await backdate(auth.authorizationId);
    const late = await submitSignature(server, device, auth.authorizationId, signature);
    assert.equal(late.status, 410);
    assert.equal(late.json.status, 'EXPIRED');
    await sleep(1200);
    const webhooks = await server.db.query(`SELECT count(*)::int AS n FROM webhook_deliveries WHERE event_type = 'authorization.expired' AND payload->>'authorizationId' = $1`, [auth.authorizationId]);
    assert.equal(webhooks.rows[0].n, 1);
  });

  test('a confirmation notifies the bank with the evidence position and the chain head', async () => {
    const auth = await bank.createAuthorization(device);
    const { signature } = await deviceSignature(server, device, auth.authorizationId);
    const confirmed = await submitSignature(server, device, auth.authorizationId, signature);
    assert.equal(confirmed.json.status, 'VERIFIED');
    const webhook = await server.db.query(`SELECT payload FROM webhook_deliveries WHERE event_type = 'authorization.verified' AND payload->>'authorizationId' = $1`, [auth.authorizationId]);
    assert.equal(webhook.rows.length, 1);
    const { evidence, evidenceHead } = webhook.rows[0].payload;
    assert.equal(evidence.evidenceHash, confirmed.json.evidence.evidenceHash);
    assert.deepEqual(evidenceHead, confirmed.json.evidence, 'the confirmation is the head of the chain when it is sealed');
  });
});
