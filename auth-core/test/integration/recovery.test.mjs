// Recovery protocol 2: recovery needs the phrase, and nothing in
// the database is enough to complete it.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, call, deviceSignature, newKey, submitSignature } from './support/actors.mjs';
import { createRecoveryKey, openRecoveryKey, proofSigningInput, setupSigningInput, signDerB64 } from './support/recovery.mjs';

const PHRASE = ['legal', 'winner', 'thank', 'year', 'wave', 'sausage', 'worth', 'useful', 'legal', 'winner', 'thank', 'yellow'];

/** The SDK's generateRecoveryPhrase(): parameters, wrapped key, biometric signature. */
async function setUpRecovery(server, device, { words = PHRASE, signWith = device.signingKey, salt } = {}) {
  const parameters = (await call(server.baseUrl, 'GET', '/v1/mobile/recovery/setup', { device })).json;
  const saltB64 = salt ?? parameters.salt;
  const key = createRecoveryKey(words, saltB64, parameters.iterations, device.nexusId);
  const signature = signDerB64(signWith.privateKey, setupSigningInput({
    nexusId: device.nexusId, credentialId: device.credentialId, saltB64, recoveryPublicKey: key.publicKey, wrapped: key.wrapped,
  }));
  const response = await call(server.baseUrl, 'POST', '/v1/mobile/recovery/setup', {
    device, body: { protocol: 2, salt: saltB64, recoveryPublicKeyPem: key.publicKeyPem, wrappedRecoveryKey: key.wrapped.toString('base64'), signature },
  });
  return { response, key, parameters };
}

/** The SDK's recoverIdentity(): opens the wrapped key, signs the proof for new keys. */
function completeBody(session, words, { newSigning = newKey(), proofKeyOverride, proofFor } = {}) {
  const recoveryKey = proofKeyOverride ?? openRecoveryKey(words, session);
  const proof = signDerB64(recoveryKey, proofSigningInput({
    sessionId: session.sessionId, nonceB64: session.nonce, nexusId: session.nexusId, newSigningPublicKey: (proofFor ?? newSigning).publicKey,
  }));
  const auth = newKey();
  return { newSigning, auth, body: { proof, newPublicKeyPem: newSigning.publicKeyPem, authPublicKeyPem: auth.publicKeyPem, platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', deviceAttestation: { supported: false } } };
}

describe('recovery protocol 2', { skip: skipWithoutServices }, () => {
  let server; let bank;

  before(async () => {
    // RECOVERY_V1_ACCEPTED was the 1.x transition switch; it no longer exists and must change nothing.
    server = await startAuthCore({ env: { RECOVERY_V1_ACCEPTED: 'true' } });
    bank = await bankSession(server, await server.registerBank('bank-recovery', { webhookUrl: 'https://hooks.bank.example/nexus' }));
  });
  after(async () => { await server?.stop(); });

  async function customer() {
    const identity = await bank.createIdentity();
    const device = await bank.enrolDevice(identity.nexusId);
    return { ...identity, device };
  }

  test('setup is sealed and reported; recovery with the phrase replaces the device', async () => {
    const { nexusId, bankCustomerRef, device } = await customer();
    const { response } = await setUpRecovery(server, device);
    assert.equal(response.status, 204, response.text);
    const sealed = await server.db.query(`SELECT sealed_payload FROM evidence_records WHERE nexus_id = $1 AND record_type = 'RECOVERY_CONFIGURED'`, [nexusId]);
    assert.equal(sealed.rows.length, 1);
    const stored = await server.db.query(`SELECT recovery_protocol FROM nexus_identities WHERE nexus_id = $1`, [nexusId]);
    assert.equal(stored.rows[0].recovery_protocol, 2);

    const session = (await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } })).json;
    assert.ok(session.wrappedRecoveryKey && session.recoveryPublicKeyPem);
    const { newSigning, auth, body } = completeBody(session, PHRASE);
    const completed = await call(server.baseUrl, 'POST', `/v1/recovery/sessions/${session.sessionId}/complete`, { token: session.accessToken, body });
    assert.equal(completed.status, 200, completed.text);
    const recovered = { nexusId, credentialId: completed.json.credentialId, signingKey: newSigning, authKey: auth };

    assert.equal((await call(server.baseUrl, 'GET', '/v1/mobile/recovery/setup', { device })).status, 401, 'the old device is revoked');
    // The phrase is used up (audit finding A2-02) until the recovered device sets up a new one.
    const reuse = await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } });
    assert.equal(reuse.status, 409, reuse.text);
    assert.equal(reuse.json.code, 'RECOVERY_PHRASE_USED');
    const authorization = await bank.createAuthorization(recovered);
    const { signature } = await deviceSignature(server, recovered, authorization.authorizationId);
    assert.equal((await submitSignature(server, recovered, authorization.authorizationId, signature)).json.status, 'VERIFIED');
    const webhooks = await server.db.query(`SELECT event_type FROM webhook_deliveries WHERE payload->>'nexusId' = $1 ORDER BY created_at`, [nexusId]);
    assert.deepEqual(webhooks.rows.map((r) => r.event_type).filter((t) => t.startsWith('recovery') || t.startsWith('identity')), ['recovery.configured', 'identity.recovered']);
  });

  test('everything the database holds is not enough to complete a recovery', async () => {
    const { nexusId, bankCustomerRef, device } = await customer();
    await setUpRecovery(server, device);
    const row = (await server.db.query(`SELECT * FROM nexus_identities WHERE nexus_id = $1`, [nexusId])).rows[0];
    const session = (await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } })).json;
    const attempts = [
      // protocol 1 style: an HMAC keyed by whatever secret-looking value is stored
      { proof: createHmac('sha256', row.recovery_wrapped_key).update(Buffer.from(session.nonce, 'base64')).digest('base64') },
      // a signature by a key that is not the recovery key
      { proof: completeBody(session, PHRASE, { proofKeyOverride: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey }).body.proof },
    ];
    for (const { proof } of attempts) {
      const { body } = completeBody(session, PHRASE);
      const r = await call(server.baseUrl, 'POST', `/v1/recovery/sessions/${session.sessionId}/complete`, { token: session.accessToken, body: { ...body, proof } });
      assert.equal(r.status, 401, r.text);
    }
    assert.throws(() => openRecoveryKey([...PHRASE.slice(0, 11), 'zoo'], session), 'a wrong phrase does not open the wrapped key');
    const state = await server.db.query(`SELECT state FROM credentials WHERE credential_id = $1`, [device.credentialId]);
    assert.equal(state.rows[0].state, 'ACTIVE');
  });

  test('a proof is bound to the new device key', async () => {
    const { bankCustomerRef, device } = await customer();
    await setUpRecovery(server, device);
    const session = (await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } })).json;
    const other = newKey();
    const { body } = completeBody(session, PHRASE, { proofFor: other });
    const r = await call(server.baseUrl, 'POST', `/v1/recovery/sessions/${session.sessionId}/complete`, { token: session.accessToken, body });
    assert.equal(r.status, 401, r.text);
  });

  test('a recovery key substituted in the database is refused before it reaches the device', async () => {
    const { nexusId, bankCustomerRef, device } = await customer();
    await setUpRecovery(server, device);
    const attackerWords = ['zoo', 'zoo', 'zoo', 'zoo', 'zoo', 'zoo', 'zoo', 'zoo', 'zoo', 'zoo', 'zoo', 'wrong'];
    const salt = (await server.db.query(`SELECT recovery_kdf_salt FROM nexus_identities WHERE nexus_id = $1`, [nexusId])).rows[0].recovery_kdf_salt.toString('base64');
    const forged = createRecoveryKey(attackerWords, salt, 210000, nexusId);
    await server.db.query(`UPDATE nexus_identities SET recovery_public_key_pem = $2, recovery_wrapped_key = $3 WHERE nexus_id = $1`, [nexusId, forged.publicKeyPem, forged.wrapped]);
    const session = await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } });
    assert.equal(session.status, 409, session.text);
    assert.equal(session.json.code, 'RECOVERY_INTEGRITY');
  });

  test('a replaced recovery configuration cannot be restored from the database (red-team RT-01)', async () => {
    const { nexusId, bankCustomerRef, device } = await customer();
    await setUpRecovery(server, device);
    const first = (await server.db.query(`SELECT recovery_public_key_pem, recovery_wrapped_key, recovery_evidence_id FROM nexus_identities WHERE nexus_id = $1`, [nexusId])).rows[0];
    const newWords = ['abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'about'];
    assert.equal((await setUpRecovery(server, device, { words: newWords })).response.status, 204);
    // The customer replaced the phrase; a database writer puts the old configuration back.
    await server.db.query(`UPDATE nexus_identities SET recovery_public_key_pem = $2, recovery_wrapped_key = $3, recovery_evidence_id = $4 WHERE nexus_id = $1`,
      [nexusId, first.recovery_public_key_pem, first.recovery_wrapped_key, first.recovery_evidence_id]);
    const session = await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } });
    assert.equal(session.status, 409, session.text);
    assert.equal(session.json.code, 'RECOVERY_INTEGRITY');
    const audited = await server.db.query(`SELECT details->>'reason' AS reason FROM audit_logs WHERE event_type = 'integrity_violation' AND nexus_id = $1`, [nexusId]);
    assert.match(audited.rows[0].reason, /not the latest sealed one/);
  });

  test('the recovery attempt counters cannot be reset in the database', async () => {
    const { bankCustomerRef } = await customer().then(async (c) => { await setUpRecovery(server, c.device); return c; });
    const session = (await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } })).json;
    const { body } = completeBody(session, PHRASE, { proofKeyOverride: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey });
    assert.equal((await call(server.baseUrl, 'POST', `/v1/recovery/sessions/${session.sessionId}/complete`, { token: session.accessToken, body })).status, 401);
    await assert.rejects(server.db.query('UPDATE recovery_sessions SET failed_attempt_count = 0, attempt_count = 0 WHERE recovery_session_id = $1', [session.sessionId]), /only grow/);
    await assert.rejects(server.db.query("UPDATE recovery_sessions SET expires_at = now() + interval '1 day' WHERE recovery_session_id = $1", [session.sessionId]), /immutable/);
  });

  test('key derivation parameters changed in the database are refused (red-team RT-09)', async () => {
    const { nexusId, bankCustomerRef, device } = await customer();
    await setUpRecovery(server, device);
    await server.db.query(`UPDATE nexus_identities SET recovery_kdf_iterations = 100000 WHERE nexus_id = $1`, [nexusId]);
    const session = await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } });
    assert.equal(session.status, 409, session.text);
    assert.equal(session.json.code, 'RECOVERY_INTEGRITY');
  });

  test('setup needs the issued salt and the biometric signing key', async () => {
    const { device } = await customer();
    const wrongSalt = await setUpRecovery(server, device, { salt: Buffer.alloc(16, 9).toString('base64') });
    assert.equal(wrongSalt.response.status, 409);
    assert.equal(wrongSalt.response.json.code, 'RECOVERY_SETUP_EXPIRED');
    const signedByAuthKey = await setUpRecovery(server, device, { signWith: device.authKey });
    assert.equal(signedByAuthKey.response.status, 400, 'the request-signing key alone cannot set the phrase');
  });

  test('failed proofs across sessions lock recovery for the identity', async () => {
    const { bankCustomerRef, device } = await customer();
    await setUpRecovery(server, device);
    let locked = null;
    for (let i = 0; i < 4 && !locked; i += 1) {
      const opened = await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } });
      if (opened.status === 409) { locked = opened; break; }
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const { body } = completeBody(opened.json, PHRASE, { proofKeyOverride: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey });
        await call(server.baseUrl, 'POST', `/v1/recovery/sessions/${opened.json.sessionId}/complete`, { token: opened.json.accessToken, body });
      }
    }
    locked ??= await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } });
    assert.equal(locked.status, 409, locked.text);
    assert.equal(locked.json.code, 'RECOVERY_LOCKED');
  });

  test('an identity still on protocol 1 must set up a new phrase, whatever the environment says', async () => {
    const { nexusId, bankCustomerRef } = await customer();
    await server.db.query(`UPDATE nexus_identities SET recovery_protocol = 1, recovery_kdf_salt = $2, recovery_kdf_iterations = 210000 WHERE nexus_id = $1`,
      [nexusId, Buffer.alloc(16, 2)]);
    const r = await bank.call('POST', '/v1/recovery/sessions', { body: { bankCustomerRef } });
    assert.equal(r.status, 409);
    assert.equal(r.json.code, 'RECOVERY_PROTOCOL_RETIRED');
  });
});
