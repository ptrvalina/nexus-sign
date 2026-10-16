// In-app audio/video calls (ADR 0017): who may join and signal, one operator
// per call, operator decisions, cancel, retry limit and unanswered sessions.
// Media itself is tested in test/media/webrtc-call.test.mjs (real WebRTC
// between two browsers).
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { adminSession, bankSession, call, deviceSignature, submitSignature } from './support/actors.mjs';

const TURN_SECRET = 'turn-shared-secret-for-tests';

describe('verification calls', { skip: skipWithoutServices }, () => {
  let server; let bank; let device; let otherDevice; let operator; let operator2; let otherBankOperator; let auditor;

  before(async () => {
    server = await startAuthCore({ env: {
      WEBRTC_STUN_URLS: 'stun:turn.bank.example:3478',
      WEBRTC_TURN_URLS: 'turn:turn.bank.example:3478?transport=udp,turns:turn.bank.example:5349?transport=tcp',
      WEBRTC_TURN_SECRET: TURN_SECRET,
      AUTHORIZATION_EXPIRY_SWEEP_MS: '500',
    } });
    bank = await bankSession(server, await server.registerBank('bank-calls'));
    await server.registerBank('bank-calls-other');
    await server.verificationSetup('operator', 'bank-calls', 'AUDIO,VIDEO');
    await server.verificationSetup('operator', 'bank-calls-other', 'AUDIO,VIDEO');
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    otherDevice = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    operator = await adminSession(server, await server.createAdmin('calls-op-1', 'operator', { clientId: 'bank-calls' }));
    operator2 = await adminSession(server, await server.createAdmin('calls-op-2', 'operator', { clientId: 'bank-calls' }));
    otherBankOperator = await adminSession(server, await server.createAdmin('calls-op-other', 'operator', { clientId: 'bank-calls-other' }));
    auditor = await adminSession(server, await server.createAdmin('calls-auditor', 'auditor', { clientId: 'bank-calls' }));
  });
  after(async () => { await server?.stop(); });

  async function openCall(channel = 'VIDEO') {
    const auth = await bank.createAuthorization(device, { verificationPolicy: channel === 'VIDEO' ? { requireVideo: true, audioAvailable: false } : { requireAudio: true } });
    const session = await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${auth.authorizationId}/verification-sessions`, { device, body: { channel } });
    assert.equal(session.status, 201, session.text);
    return { auth, sessionId: session.json.sessionId };
  }
  const deviceCall = (method, path, body, who = device) => call(server.baseUrl, method, `/v1/mobile/verification-sessions/${path}`, { device: who, body });
  const op = (who, method, path, body) => who.call(method, `/admin/api/verification-calls${path}`, body === undefined ? {} : { body });

  test('the device joins its own call and gets session-bound TURN credentials', async () => {
    const { sessionId } = await openCall();
    const joined = await deviceCall('GET', `${sessionId}/call`);
    assert.equal(joined.status, 200, joined.text);
    const [stun, turn] = joined.json.iceServers;
    assert.deepEqual(stun, { urls: ['stun:turn.bank.example:3478'] });
    const [expiry, user] = turn.username.split(':');
    assert.equal(user, sessionId);
    assert.ok(Number(expiry) * 1000 <= Date.parse(joined.json.expiresAt) + 1000, 'TURN credentials expire with the session');
    assert.equal(turn.credential, createHmac('sha1', TURN_SECRET).update(turn.username).digest('base64'), 'coturn use-auth-secret credential');
    assert.equal((await deviceCall('GET', `${sessionId}/call`, undefined, otherDevice)).status, 404, 'another customer cannot join');
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0' } }, otherDevice)).status, 404);
  });

  test('operators of the bank see the call with the transaction; others do not', async () => {
    const { auth, sessionId } = await openCall();
    const listed = (await op(operator, 'GET', '')).json.find((c) => c.sessionId === sessionId);
    assert.ok(listed, 'listed for an operator of the bank');
    assert.equal(listed.transaction.amountMinor, '125000');
    assert.equal(listed.transaction.beneficiary.iban, 'PL61109010140000071219812874');
    assert.equal(listed.authorizationId, auth.authorizationId);
    assert.ok(!(await op(otherBankOperator, 'GET', '')).json.some((c) => c.sessionId === sessionId), 'not listed for another bank');
    assert.equal((await op(otherBankOperator, 'POST', `/${sessionId}/claim`, {})).status, 404);
    assert.equal((await op(auditor, 'POST', `/${sessionId}/claim`, {})).status, 403, 'auditors are read-only');
  });

  test('one operator per call; signals are relayed in order between device and claiming operator', async () => {
    const { sessionId } = await openCall();
    assert.equal((await op(operator, 'GET', `/${sessionId}/signals`)).status, 403, 'signals need a claim');
    const claimed = await op(operator, 'POST', `/${sessionId}/claim`, {});
    assert.equal(claimed.status, 200, claimed.text);
    assert.equal(claimed.json.transaction.currency, 'PLN');
    assert.equal((await op(operator2, 'POST', `/${sessionId}/claim`, {})).status, 409, 'answered by another operator');
    assert.ok(!(await op(operator2, 'GET', '')).json.some((c) => c.sessionId === sessionId), 'no longer offered to others');
    assert.equal((await op(operator2, 'POST', `/${sessionId}/signals`, { type: 'answer', payload: { sdp: 'x' } })).status, 403);

    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0 offer' } })).status, 201);
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'candidate', payload: { candidate: 'candidate:1 1 udp 1 10.0.0.1 9 typ host', sdpMid: '0' } })).status, 201);
    const atOperator = await op(operator, 'GET', `/${sessionId}/signals?after=0`);
    assert.deepEqual(atOperator.json.signals.map((s) => [s.from, s.type]), [['device', 'offer'], ['device', 'candidate']]);
    assert.equal((await op(operator, 'POST', `/${sessionId}/signals`, { type: 'answer', payload: { sdp: 'v=0 answer' } })).status, 201);
    const atDevice = await deviceCall('GET', `${sessionId}/signals?after=0`);
    assert.deepEqual(atDevice.json.signals.map((s) => [s.from, s.type, s.payload.sdp]), [['operator', 'answer', 'v=0 answer']]);
    const none = await deviceCall('GET', `${sessionId}/signals?after=${atDevice.json.next}&waitMs=300`);
    assert.deepEqual(none.json.signals, [], 'after= returns only newer messages');
  });

  test('malformed signals are refused', async () => {
    const { sessionId } = await openCall();
    for (const body of [{ type: 'media', payload: {} }, { type: 'offer', payload: {} }, { type: 'offer', payload: { sdp: 'x'.repeat(16_385) } },
      { type: 'candidate', payload: { candidate: 'x'.repeat(3000) } }, { type: 'offer', payload: { sdp: 'v=0' }, extra: 1 }]) {
      assert.equal((await deviceCall('POST', `${sessionId}/signals`, body)).status, 400, JSON.stringify(body).slice(0, 60));
    }
  });

  test('the claiming operator decides; the device is told and must still sign; evidence names the operator', async () => {
    const { auth, sessionId } = await openCall();
    assert.equal((await op(operator, 'POST', `/${sessionId}/decision`, { result: 'VERIFIED' })).status, 403, 'no decision without the claim');
    await op(operator, 'POST', `/${sessionId}/claim`, {});
    assert.equal((await op(operator2, 'POST', `/${sessionId}/decision`, { result: 'VERIFIED' })).status, 403, 'only the claimer decides');
    const decided = await op(operator, 'POST', `/${sessionId}/decision`, { result: 'VERIFIED' });
    assert.equal(decided.status, 200, decided.text);
    assert.equal(decided.json.status, 'VERIFIED');
    const bye = await deviceCall('GET', `${sessionId}/signals?after=0`);
    assert.deepEqual(bye.json.signals.map((s) => [s.type, s.payload.reason]), [['bye', 'decided:VERIFIED']]);
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0' } })).status, 409, 'closed call');

    const state = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}`);
    assert.equal(state.json.state, 'PENDING_USER', 'the call alone does not authorize');
    const { signature } = await deviceSignature(server, device, auth.authorizationId);
    assert.equal((await submitSignature(server, device, auth.authorizationId, signature)).json.status, 'VERIFIED');
    const evidence = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/evidence`);
    const factor = evidence.json.sealedPayload.verificationFactors.find((f) => f.status === 'VERIFIED');
    assert.deepEqual([factor.channel, factor.method, factor.issuer], ['VIDEO', 'OPERATOR', 'calls-op-1']);
  });

  test('an operator FAILED rejects when no stronger channel exists', async () => {
    const { auth, sessionId } = await openCall();
    await op(operator, 'POST', `/${sessionId}/claim`, {});
    const decided = await op(operator, 'POST', `/${sessionId}/decision`, { result: 'FAILED' });
    assert.equal(decided.json.status, 'FAILED');
    assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}`)).json.state, 'REJECTED');
  });

  test('operator verification switched off: the call is neither listed nor claimable', async () => {
    const { sessionId } = await openCall('AUDIO');
    await server.verificationSetup('operator', 'bank-calls', 'VIDEO');
    try {
      assert.ok(!(await op(operator, 'GET', '')).json.some((c) => c.sessionId === sessionId));
      assert.equal((await op(operator, 'POST', `/${sessionId}/claim`, {})).status, 403);
    } finally {
      await server.verificationSetup('operator', 'bank-calls', 'AUDIO,VIDEO');
    }
  });

  test('the customer can decline and retry, at most three sessions per channel', async () => {
    const { auth, sessionId } = await openCall();
    assert.equal((await deviceCall('POST', `${sessionId}/cancel`)).status, 204);
    const plan = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/verification-plan`);
    assert.equal(plan.json.status, 'PENDING', 'declining verifies nothing and fails nothing');
    const open = () => call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${auth.authorizationId}/verification-sessions`, { device, body: { channel: 'VIDEO' } });
    assert.equal((await open()).status, 201);
    assert.equal((await open()).status, 201, 'third session (the second is superseded)');
    const fourth = await open();
    assert.equal(fourth.status, 409);
    assert.equal(fourth.json.code, 'VERIFICATION_ATTEMPTS_EXHAUSTED');
  });

  test('an unanswered session expires and the plan can be retried', async () => {
    const { auth, sessionId } = await openCall();
    await server.db.query(`UPDATE verification_sessions SET expires_at = now() - interval '1 second' WHERE session_id = $1`, [sessionId]);
    for (let i = 0; i < 40; i += 1) {
      if ((await server.db.query(`SELECT status FROM verification_sessions WHERE session_id = $1`, [sessionId])).rows[0].status === 'EXPIRED') break;
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.equal((await server.db.query(`SELECT status FROM verification_sessions WHERE session_id = $1`, [sessionId])).rows[0].status, 'EXPIRED');
    assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/verification-plan`)).json.status, 'PENDING');
    assert.equal((await deviceCall('GET', `${sessionId}/call`)).status, 409);
  });
});
