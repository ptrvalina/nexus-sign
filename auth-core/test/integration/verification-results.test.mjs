// FI-002: an audio or video factor is accepted only as a result token signed
// by a provider key the Auth Core operator registered for the bank, bound to
// the session, the transaction terms and the device, fresh and used once.
// FI-017: a channel is offered only when the bank can verify it.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, call } from './support/actors.mjs';

function providerKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const file = join(mkdtempSync(join(tmpdir(), 'nexus-provider-')), 'public.pem');
  writeFileSync(file, publicKey.export({ type: 'spki', format: 'pem' }));
  return { privateKey, publicFile: file };
}

const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

/** A result token as a provider signs it; `header`/`claims` override fields. */
function token(key, { header = {}, claims = {}, signWith } = {}) {
  const input = `${b64({ alg: 'ES256', typ: 'nexus-verification-result+jwt', kid: 'k1', ...header })}.${b64(claims)}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key: signWith ?? key.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

describe('verification results', { skip: skipWithoutServices }, () => {
  let server; let bank; let device; let other; let otherDevice;
  const audioKey = providerKey();
  const videoKey = providerKey();
  const otherBankKey = providerKey();

  before(async () => {
    server = await startAuthCore();
    bank = await bankSession(server, await server.registerBank('bank-results'));
    other = await bankSession(server, await server.registerBank('bank-results-other'));
    await server.verificationSetup('provider-add', 'bank-results', 'prov-a', 'k1', 'AUDIO', audioKey.publicFile);
    await server.verificationSetup('provider-add', 'bank-results', 'prov-v', 'k1', 'VIDEO', videoKey.publicFile);
    await server.verificationSetup('provider-add', 'bank-results-other', 'prov-a', 'k1', 'AUDIO,VIDEO', otherBankKey.publicFile);
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    otherDevice = await other.enrolDevice((await other.createIdentity()).nexusId);
  });
  after(async () => { await server?.stop(); });

  /** An AUDIO-required authorization with an open session, and valid claims for it. */
  async function openAudio(channel = 'AUDIO', policy = { requireAudio: true }) {
    const auth = await bank.createAuthorization(device, { verificationPolicy: policy });
    const session = await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${auth.authorizationId}/verification-sessions`, { device, body: { channel } });
    assert.equal(session.status, 201, session.text);
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: channel === 'AUDIO' ? 'prov-a' : 'prov-v', aud: 'nexus-sign:bank-results', sub: session.json.sessionId,
      authorization_id: auth.authorizationId, canonical_payload_hash: auth.canonicalPayloadHash, credential_id: device.credentialId,
      channel, result: 'VERIFIED', session_nonce_sha256: createHash('sha256').update(session.json.nonce).digest('hex'),
      iat: now, exp: now + 120, jti: `jti-${randomBytes(12).toString('hex')}`,
    };
    return { auth, session: session.json, claims };
  }
  const complete = (auth, session, resultToken, as = bank) => as.call('POST', `/v1/authorizations/${auth.authorizationId}/verification-sessions/${session.sessionId}/complete`, { body: { resultToken } });
  const sessionStatus = async (sessionId) => (await server.db.query(`SELECT status FROM verification_sessions WHERE session_id = $1`, [sessionId])).rows[0].status;

  test('a valid provider result advances the plan, names the key, and cannot be replayed', async () => {
    const { auth, session, claims } = await openAudio();
    const signed = token(audioKey, { claims });
    const done = await complete(auth, session, signed);
    assert.equal(done.status, 200, done.text);
    assert.equal(done.json.status, 'VERIFIED');
    const row = (await server.db.query(`SELECT status, result_method, result_issuer, result_jti, assertion_hash FROM verification_sessions WHERE session_id = $1`, [session.sessionId])).rows[0];
    assert.deepEqual({ ...row, assertion_hash: undefined }, { status: 'VERIFIED', result_method: 'PROVIDER', result_issuer: 'prov-a/k1', result_jti: claims.jti, assertion_hash: undefined });
    assert.equal(row.assertion_hash, createHash('sha256').update(signed).digest('hex'));
    assert.equal((await complete(auth, session, signed)).status, 409, 'the session is closed');
  });

  test('every binding, freshness and format violation is refused and leaves the session open', async () => {
    const { auth, session, claims } = await openAudio();
    const unregistered = providerKey();
    const now = Math.floor(Date.now() / 1000);
    const cases = {
      'signed by an unregistered key': token(audioKey, { claims, signWith: unregistered.privateKey }),
      'unknown kid': token(audioKey, { claims, header: { kid: 'k2' } }),
      'unknown issuer': token(audioKey, { claims: { ...claims, iss: 'prov-x' } }),
      'another bank as audience': token(audioKey, { claims: { ...claims, aud: 'nexus-sign:bank-results-other' } }),
      'another session': token(audioKey, { claims: { ...claims, sub: '00000000-0000-4000-8000-000000000000' } }),
      'another authorization': token(audioKey, { claims: { ...claims, authorization_id: '00000000-0000-4000-8000-000000000000' } }),
      'other transaction terms': token(audioKey, { claims: { ...claims, canonical_payload_hash: '0'.repeat(64) } }),
      'another device': token(audioKey, { claims: { ...claims, credential_id: otherDevice.credentialId } }),
      'wrong session nonce': token(audioKey, { claims: { ...claims, session_nonce_sha256: '1'.repeat(64) } }),
      'channel not of this session': token(audioKey, { claims: { ...claims, channel: 'VIDEO' } }),
      'result not in the enumeration': token(audioKey, { claims: { ...claims, result: 'OK' } }),
      expired: token(audioKey, { claims: { ...claims, iat: now - 300, exp: now - 1 } }),
      'issued in the future': token(audioKey, { claims: { ...claims, iat: now + 600, exp: now + 700 } }),
      'lifetime above 600 s': token(audioKey, { claims: { ...claims, exp: now + 3600 } }),
      'missing jti': token(audioKey, { claims: { ...claims, jti: undefined } }),
      'wrong typ': token(audioKey, { claims, header: { typ: 'JWT' } }),
      'embedded key header': token(audioKey, { claims, header: { jwk: { kty: 'EC' } } }),
      'alg none': `${b64({ alg: 'none', typ: 'nexus-verification-result+jwt', kid: 'k1' })}.${b64(claims)}.`,
      'alg HS256': `${b64({ alg: 'HS256', typ: 'nexus-verification-result+jwt', kid: 'k1' })}.${b64(claims)}.${b64('x'.repeat(32))}`,
      'not a JWS': 'VERIFIED',
    };
    for (const [name, resultToken] of Object.entries(cases)) {
      const r = await complete(auth, session, resultToken);
      assert.equal(r.status, 403, `${name}: ${r.status} ${r.text}`);
      assert.equal(await sessionStatus(session.sessionId), 'IN_PROGRESS', name);
    }
    const audited = await server.db.query(`SELECT count(*)::int AS n FROM audit_logs WHERE event_type = 'verification_result_rejected' AND details->>'sessionId' = $1`, [session.sessionId]);
    assert.equal(audited.rows[0].n, Object.keys(cases).length);
    assert.equal((await complete(auth, session, token(audioKey, { claims }))).status, 200, 'the genuine result still closes the session');
  });

  test('the old body (an unsigned result field from the gateway) is refused', async () => {
    const { auth, session } = await openAudio();
    const r = await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/verification-sessions/${session.sessionId}/complete`, {
      body: { sessionNonce: session.nonce, result: 'VERIFIED', providerReference: 'p', assertion: 'trust me' },
    });
    assert.equal(r.status, 400, r.text);
    assert.equal(await sessionStatus(session.sessionId), 'IN_PROGRESS');
  });

  test('a provider key registered for AUDIO cannot sign a VIDEO result', async () => {
    const { auth, session, claims } = await openAudio('VIDEO', { requireVideo: true, audioAvailable: false });
    const r = await complete(auth, session, token(audioKey, { claims: { ...claims, iss: 'prov-a' } }));
    assert.equal(r.status, 403, r.text);
    assert.equal((await complete(auth, session, token(videoKey, { claims }))).status, 200);
  });

  test("another bank's provider key and another bank's gateway are refused", async () => {
    const { auth, session, claims } = await openAudio();
    assert.equal((await complete(auth, session, token(otherBankKey, { claims }))).status, 403, 'same provider name, key of another bank');
    const viaOtherBank = await complete(auth, session, token(otherBankKey, { claims: { ...claims, aud: 'nexus-sign:bank-results-other' } }), other);
    assert.equal(viaOtherBank.status, 404, viaOtherBank.text);
    assert.equal(await sessionStatus(session.sessionId), 'IN_PROGRESS');
  });

  test('a result token accepted once cannot close another session', async () => {
    const first = await openAudio();
    const signed = token(audioKey, { claims: first.claims });
    assert.equal((await complete(first.auth, first.session, signed)).status, 200);
    const second = await openAudio();
    const reused = token(audioKey, { claims: { ...second.claims, jti: first.claims.jti } });
    const r = await complete(second.auth, second.session, reused);
    assert.equal(r.status, 403, r.text);
    assert.match(r.json.error, /jti already used/);
  });

  test('a retired provider key no longer verifies', async () => {
    const key = providerKey();
    await server.verificationSetup('provider-add', 'bank-results', 'prov-r', 'k1', 'AUDIO', key.publicFile);
    const { auth, session, claims } = await openAudio();
    await server.verificationSetup('provider-retire', 'bank-results', 'prov-r', 'k1');
    assert.equal((await complete(auth, session, token(key, { claims: { ...claims, iss: 'prov-r' } }))).status, 403);
  });

  test('FI-017: a channel without a verifier is not offered, and a requirement for it is refused', async () => {
    const plain = await bankSession(server, await server.registerBank('bank-results-none'));
    const plainDevice = await plain.enrolDevice((await plain.createIdentity()).nexusId);
    const r = await plain.call('POST', '/v1/authorizations', {
      headers: { 'Idempotency-Key': randomBytes(8).toString('hex') },
      body: { nexusId: plainDevice.nexusId, credentialId: plainDevice.credentialId, transactionReference: `tx-${randomBytes(6).toString('hex')}`,
        operationType: 'TRANSFER', amountMinor: '100', currency: 'EUR', beneficiary: { name: 'A' }, policyReference: 'p', policyVersion: '1',
        verificationPolicy: { requireAudio: true } },
    });
    assert.equal(r.status, 409, r.text);
    assert.equal(r.json.code, 'VERIFICATION_CHANNEL_UNAVAILABLE');
    const pushOnly = await plain.createAuthorization(plainDevice);
    assert.deepEqual(pushOnly.verificationPlan.allowedSteps, ['PUSH']);
    const escalate = await plain.call('POST', `/v1/authorizations/${pushOnly.authorizationId}/verification/escalate`, { body: { reason: 'PUSH_TIMEOUT' } });
    assert.equal(escalate.status, 409, 'nothing to escalate to');
    // Bank with VIDEO only: an AUDIO requirement is met by VIDEO.
    const videoOnly = await bank.createAuthorization(device, { verificationPolicy: { requireAudio: true, audioAvailable: false } });
    assert.deepEqual(videoOnly.verificationPlan.allowedSteps, ['PUSH', 'VIDEO']);
    assert.equal(videoOnly.verificationPlan.currentStep, 'VIDEO');
  });
});
