// Who can produce an offline code that Auth Core accepts.
//
// Without the credential's offline key K nobody can: random and guessed
// codes, codes for another authorization, for changed terms, from another
// device, replays, revoked credentials and expired authorizations are all
// refused; the attempt limit rejects the authorization. The daily limit per
// credential bounds how many authorizations even a valid code can confirm.
//
// The last test documents the residual risk rather than a defence: whoever
// holds K (database copy plus the device master key) computes valid codes.
// With MASTER_KEY_SOURCE=hsm that additionally needs the HSM
// (master-key-hsm.test.mjs); docs/security/offline-confirmation-threat-model.md.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, createHash, createHmac } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, offlineCode } from './support/actors.mjs';

/** The code for K and the canonical bytes (device protocols v1). */
function codeFor(key, canonical) {
  const tag = createHmac('sha256', key)
    .update(Buffer.concat([Buffer.from('NEXUS-SIGN/OFFLINE-CODE/v1'), Buffer.from([0]), createHash('sha256').update(canonical).digest()]))
    .digest();
  const o = tag[31] & 0x0f;
  return String((((tag[o] & 0x7f) << 24) | (tag[o + 1] << 16) | (tag[o + 2] << 8) | tag[o + 3]) % 1e8).padStart(8, '0');
}

describe('offline confirmation v1: forgery resistance and residual risk', { skip: skipWithoutServices }, () => {
  let server; let bank; let device; let other;
  before(async () => {
    // Offline confirmation v1 (code only), still available outside production;
    // v2 is covered by offline-deferred-signature.test.mjs.
    server = await startAuthCore({ env: { OFFLINE_CONFIRMATION_MODE: 'immediate', OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY: '3', AUTHORIZATION_EXPIRY_SWEEP_MS: '300000' } });
    bank = await bankSession(server, await server.registerBank('bank-offline-forgery'));
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    other = await bank.enrolDevice((await bank.createIdentity()).nexusId);
  });
  after(async () => { await server?.stop(); });

  const submit = (auth, code) => bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code } });
  const canonicalOf = async (auth, who = device) => (await deviceSignature(server, who, auth.authorizationId)).canonical;

  test('codes made without the credential key are refused; five wrong codes reject the authorization', async () => {
    const auth = await bank.createAuthorization(device);
    const canonical = await canonicalOf(auth);
    const valid = offlineCode(device, canonical);
    const guesses = new Set();
    while (guesses.size < 5) {
      const guess = String(Math.floor(Math.random() * 1e8)).padStart(8, '0');
      if (guess !== valid) guesses.add(guess);
    }
    const results = [];
    for (const guess of guesses) results.push((await submit(auth, guess)).json.status);
    assert.deepEqual(results, ['FAILED', 'FAILED', 'FAILED', 'FAILED', 'FAILED']);
    assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}`)).json.state, 'REJECTED');
    assert.equal((await submit(auth, valid)).json.status, 'FAILED', 'the correct code after rejection');
  });

  test('a code is bound to its authorization, its exact terms and its device', async () => {
    const a = await bank.createAuthorization(device);
    const b = await bank.createAuthorization(device);
    const codeA = offlineCode(device, await canonicalOf(a));
    assert.equal((await submit(b, codeA)).json.status, 'FAILED', 'code of another authorization');

    const c = await bank.createAuthorization(device);
    const canonical = await canonicalOf(c);
    const changed = Buffer.from(canonical.toString('utf8').replace('"amount_minor":"125000"', '"amount_minor":"999999"'));
    assert.notDeepEqual(changed, canonical);
    assert.equal((await submit(c, offlineCode(device, changed))).json.status, 'FAILED', 'code over changed terms');
    assert.equal((await submit(c, offlineCode(other, canonical))).json.status, 'FAILED', 'code from another enrolled device');
    // What the server published (its offline public key) and the device's
    // public key do not give K.
    const guessedKey = createHash('sha256').update(device.offlineServerPublicKeyPem + device.offlineKey.publicKeyPem).digest();
    assert.equal((await submit(c, codeFor(guessedKey, canonical))).json.status, 'FAILED');
  });

  test('the stored terms cannot be changed to match a code for other terms', async () => {
    const auth = await bank.createAuthorization(device);
    await assert.rejects(server.db.query(`UPDATE authorization_requests SET amount_minor = '1' WHERE authorization_id = $1`, [auth.authorizationId]), /immutable/);
  });

  test('a valid code is single-use, and refused for a revoked credential or after expiry', async () => {
    const auth = await bank.createAuthorization(device);
    const code = offlineCode(device, await canonicalOf(auth));
    assert.equal((await submit(auth, code)).json.status, 'VERIFIED');
    assert.equal((await submit(auth, code)).json.status, 'FAILED', 'replay');

    const short = await bank.createAuthorization(device);
    const shortCode = offlineCode(device, await canonicalOf(short));
    await server.db.query(`UPDATE authorization_requests SET expires_at = now() - interval '1 second' WHERE authorization_id = $1`, [short.authorizationId]);
    const late = await submit(short, shortCode);
    assert.equal(late.status, 410, late.text);
    assert.equal(late.json.status, 'EXPIRED');

    const victim = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const pending = await bank.createAuthorization(victim);
    const victimCode = offlineCode(victim, await canonicalOf(pending, victim));
    const revoked = await bank.call('POST', `/v1/credentials/${victim.credentialId}/revoke`, { body: { reason: 'test' } });
    assert.ok(revoked.status < 300, revoked.text);
    const afterRevoke = await submit(pending, victimCode);
    assert.notEqual(afterRevoke.json?.status, 'VERIFIED', `revoked credential: ${afterRevoke.text}`);
  });

  test('a credential confirms at most the configured number of authorizations offline per 24 hours', async () => {
    const fresh = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const statuses = [];
    for (let i = 0; i < 4; i += 1) {
      const auth = await bank.createAuthorization(fresh);
      statuses.push((await submit(auth, offlineCode(fresh, await canonicalOf(auth, fresh)))).json);
    }
    assert.deepEqual(statuses.map((s) => s.status), ['VERIFIED', 'VERIFIED', 'VERIFIED', 'FAILED']);
    assert.match(statuses[3].reason, /offline confirmation limit/);
    const audit = await server.db.query(`SELECT count(*)::int AS n FROM audit_logs WHERE event_type = 'offline_confirmation_limit_reached' AND details->>'credentialId' = $1`, [fresh.credentialId]);
    assert.equal(audit.rows[0].n, 1);
  });

  test('RESIDUAL RISK (documented, not a defence): with the database and the device master key, a valid code can be computed without the device', async () => {
    const auth = await bank.createAuthorization(other);
    const canonical = await canonicalOf(auth, other);
    // The insider's view: the stored ciphertext and, with MASTER_KEY_SOURCE=env,
    // the master key from the configuration.
    const row = (await server.db.query(`SELECT offline_secret_encrypted FROM credentials WHERE credential_id = $1`, [other.credentialId])).rows[0];
    const [, , ivB64, tagB64, ctB64] = row.offline_secret_encrypted.split('$');
    const d = createDecipheriv('aes-256-gcm', Buffer.from(server.env.DEVICE_SECRET_ENCRYPTION_KEY, 'base64'), Buffer.from(ivB64, 'base64'));
    d.setAAD(Buffer.from(`device:${other.credentialId}`));
    d.setAuthTag(Buffer.from(tagB64, 'base64'));
    const k = Buffer.concat([d.update(Buffer.from(ctB64, 'base64')), d.final()]);
    const forged = await submit(auth, codeFor(k, canonical));
    assert.equal(forged.json.status, 'VERIFIED', 'this is the residual risk');
    const evidence = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/evidence`);
    assert.equal(evidence.json.sealedPayload.confirmationMethod, 'OFFLINE_CODE', 'the evidence says it was a symmetric code');
  });
});
