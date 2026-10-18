// FI-004, phase 10: evidence records carrying a VALID HSM seal (made with the
// real evidence key on the SoftHSM token, as an attacker with HSM access
// could) but a wrong device signature, altered terms, another authorization,
// another key, a stale enrolment, a missing field, a code-only method or a
// wrong chain position. Each is appended exactly where Auth Core would append
// it, and the bank commit must refuse it with EVIDENCE_INVALID and an audit
// event; the independent verifier must refuse it too. A correctly built
// record (positive control) is accepted, which shows the seals made here are
// genuine and the refusals come from the checks under test.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { ROOT, skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, newKey, submitSignature } from './support/actors.mjs';
import { SOFTHSM_MODULE, generateKeyPair, initToken, skipWithoutSoftHsm, softHsmDirectory } from './support/softhsm.mjs';
import { canonicalJson, verifyEvidenceChain, verifyEvidenceRecord } from '../../scripts/lib/evidence.mjs';

const sha256hex = (b) => createHash('sha256').update(b).digest('hex');

/** ECDSA P-256 raw r||s → DER, as the PKCS#11 adapter stores seals. */
function rawToDer(raw) {
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i += 1; let v = b.subarray(i); if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0]), v]); return Buffer.concat([Buffer.from([0x02, v.length]), v]); };
  const body = Buffer.concat([int(raw.subarray(0, 32)), int(raw.subarray(32))]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

describe('forged evidence with a valid HSM seal (SoftHSM)', { skip: skipWithoutServices || skipWithoutSoftHsm }, () => {
  let server; let bank; let conf; let evidenceKeyPem;

  /** Seals an evidence hash with the token's evidence key, in a child process. */
  function hsmSeal(evidenceHashHex) {
    const script = `
      const p11 = require('pkcs11js'); const p = new p11.PKCS11(); p.load(process.env.M); p.C_Initialize();
      const slot = p.C_GetSlotList(true).find((s) => p.C_GetTokenInfo(s).label.trim() === 'nexus-main');
      const s = p.C_OpenSession(slot, p11.CKF_SERIAL_SESSION); p.C_Login(s, p11.CKU_USER, '12345678');
      p.C_FindObjectsInit(s, [{ type: p11.CKA_CLASS, value: p11.CKO_PRIVATE_KEY }, { type: p11.CKA_LABEL, value: 'nexus-evidence' }]);
      const [key] = p.C_FindObjects(s, 1); p.C_FindObjectsFinal(s);
      p.C_SignInit(s, { mechanism: p11.CKM_ECDSA_SHA256 }, key);
      const sig = p.C_Sign(s, Buffer.from(process.env.H, 'hex'), Buffer.alloc(72));
      console.log(Buffer.from(sig).toString('hex')); p.C_Logout(s); p.C_Finalize();`;
    const run = spawnSync(process.execPath, ['-e', script], { cwd: ROOT, env: { ...process.env, SOFTHSM2_CONF: conf, M: SOFTHSM_MODULE, H: evidenceHashHex }, encoding: 'utf8' });
    if (run.status !== 0) throw new Error(`seal failed: ${run.stderr}`);
    return rawToDer(Buffer.from(run.stdout.trim(), 'hex')).toString('base64');
  }

  before(async () => {
    conf = softHsmDirectory();
    generateKeyPair(conf, initToken(conf, 'nexus-main'), { label: 'nexus-evidence' });
    server = await startAuthCore({ env: {
      SOFTHSM2_CONF: conf, HSM_ADAPTER: 'pkcs11', PKCS11_MODULE_PATH: SOFTHSM_MODULE, PKCS11_PIN: '12345678',
      PKCS11_TOKEN_LABEL: 'nexus-main', PKCS11_EVIDENCE_KEY_LABEL: 'nexus-evidence',
    } });
    bank = await bankSession(server, await server.registerBank('bank-forgery'));
  });
  after(async () => { await server?.stop(); });

  const q = (sql, args) => server.db.query(sql, args);
  const commit = (id) => bank.call('POST', `/v1/authorizations/${id}/bank-commit-request`, { body: { bankTransactionReference: `B-${randomBytes(4).toString('hex')}` } });

  /**
   * A fresh device with one genuine online confirmation (the template record),
   * and a pending target authorization with its canonical bytes.
   */
  async function stage() {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const genuine = await bank.createAuthorization(device);
    const g = await deviceSignature(server, device, genuine.authorizationId);
    assert.equal((await submitSignature(server, device, genuine.authorizationId, g.signature)).json.status, 'VERIFIED');
    const template = (await bank.call('GET', `/v1/authorizations/${genuine.authorizationId}/evidence`)).json;
    evidenceKeyPem ??= template.evidencePublicKeyPem;
    const target = await bank.createAuthorization(device);
    const t = await deviceSignature(server, device, target.authorizationId);
    return { device, template, genuineId: genuine.authorizationId, targetId: target.authorizationId, targetRef: target.transactionReference ?? t.authorization.transactionReference, canonical: t.canonical };
  }

  /**
   * Builds a record for the target from the template, lets `change` alter the
   * payload, appends it at the head of the chain (or where `position` says)
   * with a genuine HSM seal, and marks the target VERIFIED in the database.
   */
  async function forge(s, change, { position, method = 'DEVICE_SIGNATURE' } = {}) {
    const head = (await q(`SELECT chain_sequence, evidence_hash FROM evidence_records WHERE nexus_id = $1 ORDER BY chain_sequence DESC LIMIT 1`, [s.device.nexusId])).rows[0];
    const sequence = position?.sequence ?? Number(head.chain_sequence) + 1;
    const previous = position?.previous ?? head.evidence_hash;
    const payload = {
      ...s.template.sealedPayload,
      authorizationId: s.targetId,
      transactionReference: JSON.parse(s.canonical.toString('utf8')).transaction_reference,
      canonicalPayloadHash: sha256hex(s.canonical),
      signedPayloadBase64: s.canonical.toString('base64'),
      signature: sign('sha256', s.canonical, { key: s.device.signingKey.privateKey, dsaEncoding: 'der' }).toString('base64'),
      signatureFormat: 'der',
      confirmationMethod: method,
      chainSequence: sequence,
      previousEvidenceHash: previous,
      verifiedAt: new Date().toISOString(),
    };
    change?.(payload);
    const hash = sha256hex(canonicalJson(payload));
    const seal = hsmSeal(hash);
    await q(`INSERT INTO evidence_records (record_type, authorization_id, nexus_id, credential_id, chain_sequence, transaction_reference, canonical_payload_hash,
               signature, signature_algorithm, key_version, policy_version, attestation_verdict, verified_at, consumed_at, result, correlation_id,
               previous_evidence_hash, evidence_hash, hsm_signature, hsm_key_version, seal_key_id, schema_version, verification_factors, sealed_payload, created_at)
             VALUES ('AUTHORIZATION', $1, $2, $3, $4, $5, $6, $7, 'ES256', 1, $8, 'UNKNOWN', now(), now(), 'VERIFIED', NULL, $9, $10, $11, 1, $12, '3', '[]', $13, now())`,
      [s.targetId, s.device.nexusId, s.device.credentialId, sequence, payload.transactionReference, sha256hex(s.canonical), payload.signature ?? 'x',
        payload.policyVersion, previous, hash, seal, payload.sealKeyId, JSON.stringify(payload)]);
    await q(`UPDATE authorization_requests SET state = 'VERIFIED', signature = $2, signature_format = $3, confirmation_method = $4, verified_at = now()
             WHERE authorization_id = $1`, [s.targetId, payload.signature ?? 'x', method === 'OFFLINE_CODE' ? 'hmac' : 'der', method]);
    return (await bank.call('GET', `/v1/authorizations/${s.targetId}/evidence`)).json;
  }

  async function expectRefused(s, reason) {
    const view = (await bank.call('GET', `/v1/authorizations/${s.targetId}`)).json;
    assert.equal(view.confirmed, false, 'GET does not report the forged record as confirmed');
    assert.match(view.evidenceProblem, reason);
    const r = await commit(s.targetId);
    assert.equal(r.status, 409, r.text);
    assert.equal(r.json.code, 'EVIDENCE_INVALID');
    assert.match(r.json.error, reason);
    const audit = await q(`SELECT details FROM audit_logs WHERE event_type = 'integrity_violation' AND details->>'authorizationId' = $1`, [s.targetId]);
    assert.equal(audit.rows.length, 1, 'security event recorded');
    const bankState = (await q(`SELECT bank_transaction_state FROM authorization_requests WHERE authorization_id = $1`, [s.targetId])).rows[0];
    assert.equal(bankState.bank_transaction_state, 'PENDING', 'no partial commit');
  }

  test('positive control: a correctly built record with a genuine seal is accepted, by the commit and by the verifier', async () => {
    const s = await stage();
    const exported = await forge(s);
    assert.deepEqual(verifyEvidenceRecord(exported, exported.evidencePublicKeys ?? exported.evidencePublicKeyPem), []);
    assert.equal((await bank.call('GET', `/v1/authorizations/${s.targetId}`)).json.confirmed, true);
    const r = await commit(s.targetId);
    assert.equal(r.status, 202, r.text);
  });

  test('valid seal, device signature by another key: refused by the commit and the verifier', async () => {
    const s = await stage();
    const intruder = newKey();
    const exported = await forge(s, (p) => { p.signature = sign('sha256', s.canonical, { key: intruder.privateKey, dsaEncoding: 'der' }).toString('base64'); });
    await expectRefused(s, /device signature in the evidence does not verify/);
    assert.ok(verifyEvidenceRecord(exported, exported.evidencePublicKeyPem).some((x) => /device signature does not verify/.test(x)));
  });

  test('valid seal, valid device signature over altered terms: refused', async () => {
    const s = await stage();
    const altered = Buffer.from(s.canonical.toString('utf8').replace('"amount_minor":"125000"', '"amount_minor":"1"'));
    await forge(s, (p) => {
      p.signedPayloadBase64 = altered.toString('base64');
      p.signature = sign('sha256', altered, { key: s.device.signingKey.privateKey, dsaEncoding: 'der' }).toString('base64');
    });
    await expectRefused(s, /does not carry the stored terms/);
  });

  test('valid seal, the genuine record of another authorization re-pointed at the target: refused', async () => {
    const s = await stage();
    await forge(s, (p) => { Object.assign(p, s.template.sealedPayload, { chainSequence: p.chainSequence, previousEvidenceHash: p.previousEvidenceHash }); });
    await expectRefused(s, /names another authorization/);
  });

  test('valid seal, signature and key of another device (not the enrolled one): refused', async () => {
    const s = await stage();
    const intruder = newKey();
    await forge(s, (p) => {
      p.credentialPublicKeyPem = intruder.publicKeyPem;
      p.signature = sign('sha256', s.canonical, { key: intruder.privateKey, dsaEncoding: 'der' }).toString('base64');
    });
    await expectRefused(s, /another device key/);
  });

  test('valid seal, stale or unknown enrolment reference: refused', async () => {
    const s = await stage();
    await forge(s, (p) => { p.enrolmentEvidenceHash = sha256hex(randomBytes(8)); });
    await expectRefused(s, /another enrolment/);
  });

  test('seal by a key the deployment does not know: refused', async () => {
    const s = await stage();
    await forge(s, (p) => { p.sealKeyId = sha256hex(randomBytes(8)); });
    await expectRefused(s, /unknown evidence key/);
  });

  test('valid seal, required field missing: refused', async () => {
    const s = await stage();
    await forge(s, (p) => { delete p.signature; });
    await expectRefused(s, /device signature in the evidence does not verify/);
  });

  test('valid seal, code-only method on a v2 deployment: refused', async () => {
    const s = await stage();
    await forge(s, (p) => { p.signatureFormat = 'hmac'; p.signatureAlgorithm = 'HMAC-SHA256'; }, { method: 'OFFLINE_CODE' });
    await expectRefused(s, /code-only offline confirmation is not accepted/);
  });

  test('valid seal, record outside its chain position: refused by the commit and the chain verifier', async () => {
    const s = await stage();
    const head = (await q(`SELECT chain_sequence FROM evidence_records WHERE nexus_id = $1 ORDER BY chain_sequence DESC LIMIT 1`, [s.device.nexusId])).rows[0];
    await forge(s, null, { position: { sequence: Number(head.chain_sequence) + 5, previous: sha256hex(randomBytes(8)) } });
    await expectRefused(s, /does not link to its predecessor/);
    const chain = (await bank.call('GET', `/v1/nexus-identities/${s.device.nexusId}/evidence`)).json;
    assert.ok(verifyEvidenceChain(chain.records, evidenceKeyPem).some((x) => /chain|position/.test(x)), 'the chain verifier sees the gap');
  });

  test('a forged record does not move a pending authorization, and an altered verified row is not committable', async () => {
    const s = await stage();
    // The genuine record for the target, appended and sealed, but the row left PENDING_USER.
    await forge(s);
    await q(`ALTER TABLE authorization_requests DISABLE TRIGGER authorization_lifecycle;
      UPDATE authorization_requests SET state = 'PENDING_USER', signature = NULL, signature_format = NULL, confirmation_method = NULL, verified_at = NULL WHERE authorization_id = '${s.targetId}';
      ALTER TABLE authorization_requests ENABLE TRIGGER authorization_lifecycle;`);
    assert.equal((await bank.call('GET', `/v1/authorizations/${s.targetId}`)).json.state, 'PENDING_USER', 'evidence alone changes no state');
    assert.equal((await commit(s.targetId)).status, 409);

    // A genuinely verified authorization whose payee is changed afterwards (trigger bypassed).
    const v = await bank.createAuthorization(s.device);
    const sig = await deviceSignature(server, s.device, v.authorizationId);
    assert.equal((await submitSignature(server, s.device, v.authorizationId, sig.signature)).json.status, 'VERIFIED');
    await q(`ALTER TABLE authorization_requests DISABLE TRIGGER authorization_lifecycle;
      UPDATE authorization_requests SET beneficiary = '{"name":"Mallory","iban":"PL27114020040000300201355387"}' WHERE authorization_id = '${v.authorizationId}';
      ALTER TABLE authorization_requests ENABLE TRIGGER authorization_lifecycle;`);
    const r = await commit(v.authorizationId);
    assert.equal(r.status, 409, r.text);
    assert.match(r.json.error, /names another authorization|does not carry the stored terms/);
  });

  test('concurrent and repeated commit requests: one commit, idempotent for the same reference', async () => {
    const s = await stage();
    const ok = await bank.createAuthorization(s.device);
    const sig = await deviceSignature(server, s.device, ok.authorizationId);
    assert.equal((await submitSignature(server, s.device, ok.authorizationId, sig.signature)).json.status, 'VERIFIED');
    const same = await Promise.all(Array.from({ length: 20 }, () => bank.call('POST', `/v1/authorizations/${ok.authorizationId}/bank-commit-request`, { body: { bankTransactionReference: 'B-same' } })));
    assert.ok(same.every((r) => r.status === 202), JSON.stringify(same.map((r) => r.status)));
    const audits = await q(`SELECT count(*)::int AS n FROM audit_logs WHERE event_type = 'bank_commit_requested' AND details->>'authorizationId' = $1`, [ok.authorizationId]);
    assert.equal(audits.rows[0].n, 1, 'one commit request recorded');

    const other = await bank.createAuthorization(s.device);
    const sig2 = await deviceSignature(server, s.device, other.authorizationId);
    assert.equal((await submitSignature(server, s.device, other.authorizationId, sig2.signature)).json.status, 'VERIFIED');
    const different = await Promise.all(Array.from({ length: 10 }, (_, i) => bank.call('POST', `/v1/authorizations/${other.authorizationId}/bank-commit-request`, { body: { bankTransactionReference: `B-${i}` } })));
    assert.equal(different.filter((r) => r.status === 202).length, 1, JSON.stringify(different.map((r) => r.status)));
  });

  test('a device revoked after confirmation cannot be committed', async () => {
    const s = await stage();
    const v = await bank.createAuthorization(s.device);
    const sig = await deviceSignature(server, s.device, v.authorizationId);
    assert.equal((await submitSignature(server, s.device, v.authorizationId, sig.signature)).json.status, 'VERIFIED');
    assert.ok((await bank.call('POST', `/v1/credentials/${s.device.credentialId}/revoke`, { body: { reason: 'lost' } })).status < 300);
    const r = await commit(v.authorizationId);
    assert.equal(r.status, 409, r.text);
    assert.equal(r.json.code, 'CREDENTIAL_NOT_ACTIVE');
  });
});
