// In-app audio/video calls (ADR 0017): who may join and signal, one operator
// per call, operator decisions, cancel, retry limit and unanswered sessions.
// Media itself is tested in test/media/webrtc-call.test.mjs (real WebRTC
// between two browsers).
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { randomUUID } from 'node:crypto';
import { adminSession, bankSession, call, deviceHeaders, deviceSignature, submitSignature } from './support/actors.mjs';

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

  async function openCall(channel = 'VIDEO', who = device) {
    const auth = await bank.createAuthorization(who, { verificationPolicy: channel === 'VIDEO' ? { requireVideo: true, audioAvailable: false } : { requireAudio: true } });
    const session = await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${auth.authorizationId}/verification-sessions`, { device: who, body: { channel } });
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
    assert.deepEqual([bye.json.signals[0].from, bye.json.signals[0].type, bye.json.signals[0].payload.reason], ['operator', 'bye', 'decided:VERIFIED']);
    assert.ok(bye.json.signals.slice(1).every((s) => s.from === 'server' && s.type === 'bye'), 'at most a closure notice follows');
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

  test('signalling order: offers from the device only, answers from the operator only, candidates after the description', async () => {
    const { sessionId } = await openCall();
    await op(operator, 'POST', `/${sessionId}/claim`, {});
    const cand = { candidate: 'candidate:1 1 udp 1 10.0.0.1 9 typ host', sdpMid: '0' };
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'answer', payload: { sdp: 'v=0' } })).status, 400, 'the device never answers');
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'candidate', payload: cand })).status, 409, 'no candidate before the offer');
    assert.equal((await op(operator, 'POST', `/${sessionId}/signals`, { type: 'answer', payload: { sdp: 'v=0' } })).status, 409, 'no answer without an offer');
    assert.equal((await op(operator, 'POST', `/${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0' } })).status, 400, 'the operator never offers');
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0 1' } })).status, 201);
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0 2' } })).status, 409, 'one outstanding offer at a time');
    assert.equal((await op(operator, 'POST', `/${sessionId}/signals`, { type: 'candidate', payload: cand })).status, 409, 'operator candidates follow the answer');
    assert.equal((await op(operator, 'POST', `/${sessionId}/signals`, { type: 'answer', payload: { sdp: 'v=0 a1' } })).status, 201);
    assert.equal((await op(operator, 'POST', `/${sessionId}/signals`, { type: 'answer', payload: { sdp: 'v=0 a2' } })).status, 409, 'one answer per offer');
    // ICE restart after a drop: a new offer once the previous one is answered.
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0 restart' } })).status, 201);
    assert.equal((await op(operator, 'POST', `/${sessionId}/signals`, { type: 'answer', payload: { sdp: 'v=0 a-restart' } })).status, 201);
    const atOperator = await op(operator, 'GET', `/${sessionId}/signals?after=0`);
    assert.deepEqual(atOperator.json.signals.map((x) => x.payload.sdp), ['v=0 1', 'v=0 restart']);
    // After its bye a party sends nothing more.
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'bye', payload: { reason: 'hangup' } })).status, 201);
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'candidate', payload: cand })).status, 409);
  });

  test('a retried message (same messageId) is accepted once and relayed once', async () => {
    const { sessionId } = await openCall();
    await op(operator, 'POST', `/${sessionId}/claim`, {});
    const messageId = randomUUID();
    const first = await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0' }, messageId });
    const again = await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0' }, messageId });
    assert.equal(first.status, 201);
    assert.equal(again.status, 200);
    assert.deepEqual([again.json.seq, again.json.duplicate], [first.json.seq, true]);
    assert.equal((await op(operator, 'GET', `/${sessionId}/signals?after=0`)).json.signals.length, 1);
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0' }, messageId: 'not-a-uuid' })).status, 400);
  });

  test('a replayed signed device request is refused', async () => {
    const { sessionId } = await openCall();
    const path = `/v1/mobile/verification-sessions/${sessionId}/signals`;
    const raw = JSON.stringify({ type: 'offer', payload: { sdp: 'v=0' } });
    const headers = { ...deviceHeaders(device, 'POST', path, raw), 'Content-Type': 'application/json' };
    const send = () => fetch(`${server.baseUrl}${path}`, { method: 'POST', headers, body: raw });
    assert.equal((await send()).status, 201);
    const replay = await send();
    assert.ok(replay.status === 401 || replay.status === 409, `replay refused (${replay.status})`);
    assert.equal((await op(operator, 'POST', `/${sessionId}/claim`, {})).status, 200);
    assert.equal((await op(operator, 'GET', `/${sessionId}/signals?after=0`)).json.signals.length, 1, 'relayed once');
    // A forged signature (body changed after signing) is refused as well.
    const forged = await fetch(`${server.baseUrl}${path}`, { method: 'POST', headers: { ...deviceHeaders(device, 'POST', path, raw), 'Content-Type': 'application/json' }, body: raw.replace('v=0', 'v=1') });
    assert.equal(forged.status, 401);
  });

  test('two operators claiming at once: exactly one gets the call', async () => {
    const { sessionId } = await openCall();
    const results = await Promise.all([op(operator, 'POST', `/${sessionId}/claim`, {}), op(operator2, 'POST', `/${sessionId}/claim`, {})]);
    assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
  });

  test('the operator hangs up without a result: session closed, customer told, nothing verified or failed', async () => {
    const { auth, sessionId } = await openCall();
    assert.equal((await op(operator2, 'POST', `/${sessionId}/release`, {})).status, 403, 'only the claimer can release');
    await op(operator, 'POST', `/${sessionId}/claim`, {});
    assert.equal((await op(operator, 'POST', `/${sessionId}/release`, {})).status, 204);
    const signals = (await deviceCall('GET', `${sessionId}/signals?after=0`)).json.signals;
    assert.deepEqual([signals[0].from, signals[0].type, signals[0].payload.reason], ['operator', 'bye', 'operator_left']);
    assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/verification-plan`)).json.status, 'PENDING');
    const audit = await server.db.query(`SELECT details FROM audit_logs WHERE event_type = 'verification_session_cancelled' AND details->>'sessionId' = $1`, [sessionId]);
    assert.equal(audit.rows[0].details.by, 'admin:calls-op-1');
    assert.equal((await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0' } })).status, 409);
  });

  test('a session closed elsewhere is announced to both parties with a server bye', async () => {
    const { sessionId } = await openCall();
    await op(operator, 'POST', `/${sessionId}/claim`, {});
    await server.db.query(`UPDATE verification_sessions SET expires_at = now() - interval '1 second' WHERE session_id = $1`, [sessionId]);
    const atDevice = (await deviceCall('GET', `${sessionId}/signals?after=0`)).json.signals;
    const atOperator = (await op(operator, 'GET', `/${sessionId}/signals?after=0`)).json.signals;
    for (const signals of [atDevice, atOperator]) {
      assert.equal(signals.length, 1);
      assert.deepEqual([signals[0].from, signals[0].type, signals[0].payload.reason], ['server', 'bye', 'session_expired']);
    }
    assert.equal((await deviceCall('GET', `${sessionId}/signals?after=0`)).json.signals.length, 1, 'announced once');
    // The contract (see the test above): 410 while the session is past its time,
    // 409 once the expiry sweep has closed it. The sweep runs in the background
    // and may do so between these steps, so the status is read around the request.
    const status = async () => (await server.db.query(`SELECT status FROM verification_sessions WHERE session_id = $1`, [sessionId])).rows[0].status;
    const before = await status();
    const late = await deviceCall('POST', `${sessionId}/signals`, { type: 'offer', payload: { sdp: 'v=0' } });
    const after = await status();
    const expected = new Set([before, after].map((s) => (s === 'EXPIRED' ? 409 : 410)));
    assert.ok(expected.has(late.status), `${late.status} for a session that was ${before} then ${after}`);
  });

  test('a revoked device credential ends the call for the operator', async () => {
    const revokedDevice = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const { sessionId } = await openCall('VIDEO', revokedDevice);
    await op(operator, 'POST', `/${sessionId}/claim`, {});
    await server.db.query(`UPDATE credentials SET state = 'REVOKED', revoked_at = now() WHERE credential_id = $1`, [revokedDevice.credentialId]);
    const signals = (await op(operator, 'GET', `/${sessionId}/signals?after=0`)).json.signals;
    assert.deepEqual([signals[0].from, signals[0].payload.reason], ['server', 'credential_revoked']);
    assert.equal((await op(operator, 'POST', `/${sessionId}/signals`, { type: 'answer', payload: { sdp: 'v=0' } })).status, 409);
  });
});
