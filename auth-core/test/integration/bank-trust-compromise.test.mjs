// Phase 12: a fully compromised Auth Core (its own code run with its database
// and its evidence key in the HSM, SoftHSM here) registers or substitutes a
// device key, and the attacker signs with it. Auth Core then reports the
// authorization VERIFIED and confirmed, accepts the commit request, and its
// export verifies with the pinned evidence keys: none of that can tell the
// bank anything. The bank decides with its own trust source: credential
// approvals it signed with its own key (from the key fingerprint its app
// reported), its revocations, its pinned evidence keys and kept chain heads,
// and the terms it asked for (scripts/lib/bankTrust.mjs).
//
// SoftHSM is a software PKCS#11 token, not the bank's vendor HSM.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, newKey, submitSignature } from './support/actors.mjs';
import { SOFTHSM_MODULE, generateKeyPair, initToken, skipWithoutSoftHsm, softHsmDirectory } from './support/softhsm.mjs';
import { asCompromisedAuthCore } from './support/compromise.mjs';
import { verifyEvidenceChain, verifyEvidenceRecord } from '../../scripts/lib/evidence.mjs';

// Loaded lazily so that the Auth Core half of every case runs even where the
// bank-side check does not exist yet.
const bankTrust = () => import('../../scripts/lib/bankTrust.mjs');

describe('a compromised Auth Core cannot make the bank execute (SoftHSM)', { skip: skipWithoutServices || skipWithoutSoftHsm }, () => {
  let server; let bank; let client; let pinnedEvidenceKeys;
  // The bank's own trust key: generated and held by the bank, never given to Auth Core.
  const bankKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const bankTrustKeys = [bankKey.publicKey.export({ type: 'spki', format: 'pem' }).toString()];
  const registry = []; // the bank's signed statements

  before(async () => {
    const conf = softHsmDirectory();
    generateKeyPair(conf, initToken(conf, 'nexus-main'), { label: 'nexus-evidence' });
    server = await startAuthCore({ env: {
      SOFTHSM2_CONF: conf, HSM_ADAPTER: 'pkcs11', PKCS11_MODULE_PATH: SOFTHSM_MODULE, PKCS11_PIN: '12345678',
      PKCS11_TOKEN_LABEL: 'nexus-main', PKCS11_EVIDENCE_KEY_LABEL: 'nexus-evidence',
    } });
    client = await server.registerBank('bank-trust');
    bank = await bankSession(server, client);
    // Key ceremony, before any compromise: the bank records the evidence public key.
    const probe = await approvedDevice();
    const auth = await confirm(probe.device);
    pinnedEvidenceKeys = Object.values((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/evidence`)).json.evidencePublicKeys);
  });
  after(async () => { await server?.stop(); });

  const q = (sql, args) => server.db.query(sql, args);

  /** Enrolment through the API, and the bank's approval from what its app reported. */
  async function approvedDevice() {
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const { approvalStatement, signStatement, signingKeyFingerprint } = await bankTrust().catch(() => ({}));
    if (signStatement) {
      // The app reports the fingerprint of the key it holds, computed on the device.
      registry.push(signStatement(approvalStatement({
        nexusId: device.nexusId, credentialId: device.credentialId,
        signingKeySha256: signingKeyFingerprint(device.signingKey.publicKeyPem), reference: `app-${device.credentialId}`,
      }), bankKey.privateKey));
    }
    return { device };
  }

  async function confirm(device, overrides) {
    const auth = await bank.createAuthorization(device, overrides);
    const s = await deviceSignature(server, device, auth.authorizationId);
    const r = await submitSignature(server, device, auth.authorizationId, s.signature);
    assert.equal(r.json.status, 'VERIFIED', r.text);
    return { ...auth, terms: s.authorization };
  }

  /** What the bank asked for when it created the authorization. */
  const expectedOf = (auth, device) => ({
    authorizationId: auth.authorizationId, nexusId: device.nexusId, transactionReference: auth.transactionReference,
    amountMinor: '125000', currency: 'PLN', beneficiary: { name: 'Anna Nowak', iban: 'PL61109010140000071219812874' },
  });

  /** Everything Auth Core says, all of it positive in these cases. */
  async function authCoreSaysYes(auth) {
    const view = (await bank.call('GET', `/v1/authorizations/${auth.authorizationId}`)).json;
    assert.equal(view.state, 'VERIFIED');
    assert.equal(view.confirmed, true, JSON.stringify(view.evidenceProblem));
    const commit = await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/bank-commit-request`, { body: { bankTransactionReference: `B-${randomBytes(4).toString('hex')}` } });
    assert.equal(commit.status, 202, commit.text);
    const evidence = (await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/evidence`)).json;
    assert.deepEqual(verifyEvidenceRecord(evidence, pinnedEvidenceKeys, { standalone: true, rejectOfflineCode: true }), [],
      'the export verifies with the pinned evidence keys');
    return evidence;
  }

  const chainOf = async (nexusId) => (await bank.call('GET', `/v1/nexus-identities/${nexusId}/evidence`)).json;

  async function decide(evidence, expected, extra = {}) {
    const { bankExecutionDecision } = await bankTrust();
    return bankExecutionDecision({ evidence, evidenceKeys: pinnedEvidenceKeys, bankTrustKeys, registry, expected, ...extra });
  }

  test('1. positive control: a device the bank approved, the terms it asked for', async () => {
    const { device } = await approvedDevice();
    const auth = await confirm(device);
    const evidence = await authCoreSaysYes(auth);
    const decision = await decide(evidence, expectedOf(auth, device), { chain: await chainOf(device.nexusId) });
    assert.deepEqual(decision.problems, []);
    assert.equal(decision.allowed, true);
  });

  test('2. a credential enrolled by Auth Core alone (no bank token, invented replacement, claimed attestation)', async () => {
    const { device } = await approvedDevice();
    const attacker = { signingKey: newKey(), authKey: newKey(), offlineKey: newKey(), nexusId: device.nexusId };
    const rogue = await asCompromisedAuthCore(server, {
      kind: 'enrol', nexusId: device.nexusId, clientId: client.clientId,
      signingPublicKeyPem: attacker.signingKey.publicKeyPem, authPublicKeyPem: attacker.authKey.publicKeyPem, offlinePublicKeyPem: attacker.offlineKey.publicKeyPem,
    });
    attacker.credentialId = rogue.credentialId;
    // Auth Core tells the bank (webhook credential.replaced, GET credential)
    // that this is the customer's device now; the bank creates the payment for it.
    assert.equal((await bank.call('GET', `/v1/credentials/${rogue.credentialId}`)).json.state, 'ACTIVE');
    const auth = await confirm(attacker);
    const evidence = await authCoreSaysYes(auth);
    const decision = await decide(evidence, expectedOf(auth, attacker));
    assert.equal(decision.allowed, false);
    assert.ok(decision.problems.some((p) => /not approved by the bank/.test(p)), JSON.stringify(decision.problems));
    // With the chain, the unapproved enrolment itself is reported.
    const withChain = await decide(evidence, expectedOf(auth, attacker), { chain: await chainOf(device.nexusId) });
    assert.equal(withChain.allowed, false);
    assert.ok(withChain.problems.some((p) => new RegExp(`enrolment of credential ${rogue.credentialId} .*not approved`).test(p)), JSON.stringify(withChain.problems));
  });

  test('3. the key of an approved credential substituted (same credentialId, new sealed enrolment)', async () => {
    const { device } = await approvedDevice();
    const attacker = { ...device, signingKey: newKey(), authKey: newKey(), offlineKey: newKey() };
    await asCompromisedAuthCore(server, {
      kind: 'substitute-keys', nexusId: device.nexusId, credentialId: device.credentialId,
      signingPublicKeyPem: attacker.signingKey.publicKeyPem, authPublicKeyPem: attacker.authKey.publicKeyPem, offlinePublicKeyPem: attacker.offlineKey.publicKeyPem,
    });
    const auth = await confirm(attacker);
    const evidence = await authCoreSaysYes(auth);
    const decision = await decide(evidence, expectedOf(auth, device));
    assert.equal(decision.allowed, false);
    assert.ok(decision.problems.some((p) => /signing key .* differs from the key the bank approved/.test(p)), JSON.stringify(decision.problems));
    // The customer's genuine device no longer gets anything through Auth Core
    // (its key was replaced there); the bank sees why from its own records.
  });

  test('4. an approval not signed by a bank trust key, or altered after signing, does not count', async () => {
    const { approvalStatement, signStatement, signingKeyFingerprint } = await bankTrust();
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const auth = await confirm(device);
    const evidence = await authCoreSaysYes(auth);
    const forgerKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }); // e.g. a key Auth Core holds
    const statement = approvalStatement({ nexusId: device.nexusId, credentialId: device.credentialId, signingKeySha256: signingKeyFingerprint(device.signingKey.publicKeyPem), reference: 'x' });
    const forged = signStatement(statement, forgerKey.privateKey);
    const altered = signStatement({ ...statement, signingKeySha256: 'a'.repeat(64) }, bankKey.privateKey);
    altered.statement = { ...altered.statement, signingKeySha256: statement.signingKeySha256 };
    for (const entry of [forged, altered]) {
      const { bankExecutionDecision } = await bankTrust();
      const d = bankExecutionDecision({ evidence, evidenceKeys: pinnedEvidenceKeys, bankTrustKeys, registry: [...registry, entry], expected: expectedOf(auth, device) });
      assert.equal(d.allowed, false);
      assert.ok(d.problems.some((p) => /not approved by the bank/.test(p)), JSON.stringify(d.problems));
      assert.ok(d.problems.some((p) => /unknown bank key|signature of a bank statement does not verify/.test(p)), JSON.stringify(d.problems));
    }
  });

  test('5. revoked by the bank while Auth Core keeps it active; replaced: the old refused, the new allowed', async () => {
    const { revocationStatement, signStatement, approvalStatement, signingKeyFingerprint } = await bankTrust();
    const { device } = await approvedDevice();
    registry.push(signStatement(revocationStatement({ nexusId: device.nexusId, credentialId: device.credentialId, reason: 'lost' }), bankKey.privateKey));
    const auth = await confirm(device);
    const evidence = await authCoreSaysYes(auth);
    const decision = await decide(evidence, expectedOf(auth, device));
    assert.equal(decision.allowed, false);
    assert.ok(decision.problems.some((p) => /revoked by the bank/.test(p)), JSON.stringify(decision.problems));

    // Replacement through the bank's own flow: new token, new device, new approval.
    const replacement = await bank.enrolDevice(device.nexusId, { replacement: { method: 'BRANCH', reference: 'R-1' } });
    registry.push(signStatement(approvalStatement({ nexusId: replacement.nexusId, credentialId: replacement.credentialId, signingKeySha256: signingKeyFingerprint(replacement.signingKey.publicKeyPem), reference: 'R-1' }), bankKey.privateKey));
    const next = await confirm(replacement);
    const fresh = await authCoreSaysYes(next);
    assert.deepEqual((await decide(fresh, expectedOf(next, replacement))).problems, []);
  });

  test('6. evidence keys: an export sealed with a key the bank did not pin, or no pinned keys', async () => {
    const { device } = await approvedDevice();
    const auth = await confirm(device);
    const evidence = await authCoreSaysYes(auth);
    // A compromised Auth Core re-seals with a key of its own and ships it in the export.
    const { bankExecutionDecision } = await bankTrust();
    const own = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const { createHash, sign } = await import('node:crypto');
    const ownPem = own.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const ownId = createHash('sha256').update(own.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    const { canonicalJson } = await import('../../scripts/lib/evidence.mjs');
    const resealed = structuredClone(evidence);
    for (const record of [resealed, resealed.credentialEnrolment]) {
      record.sealedPayload.sealKeyId = ownId;
      record.sealKeyId = ownId;
      record.evidenceHash = createHash('sha256').update(canonicalJson(record.sealedPayload)).digest('hex');
      record.hsmSignature = sign('sha256', Buffer.from(record.evidenceHash, 'hex'), { key: own.privateKey, dsaEncoding: 'der' }).toString('base64');
    }
    resealed.sealedPayload.enrolmentEvidenceHash = resealed.credentialEnrolment.evidenceHash;
    resealed.evidenceHash = createHash('sha256').update(canonicalJson(resealed.sealedPayload)).digest('hex');
    resealed.hsmSignature = sign('sha256', Buffer.from(resealed.evidenceHash, 'hex'), { key: own.privateKey, dsaEncoding: 'der' }).toString('base64');
    resealed.evidencePublicKeys = { [ownId]: ownPem };
    resealed.evidencePublicKeyPem = ownPem;
    // Consistent with the key inside the export ...
    assert.deepEqual(verifyEvidenceRecord(resealed, resealed.evidencePublicKeys, { standalone: true }), []);
    // ... refused with the bank's pinned keys, and refused when no keys are pinned.
    const d = bankExecutionDecision({ evidence: resealed, evidenceKeys: pinnedEvidenceKeys, bankTrustKeys, registry, expected: expectedOf(auth, device) });
    assert.equal(d.allowed, false);
    assert.ok(d.problems.some((p) => /HSM seal does not verify/.test(p)), JSON.stringify(d.problems));
    const none = bankExecutionDecision({ evidence, evidenceKeys: [], bankTrustKeys, registry, expected: expectedOf(auth, device) });
    assert.equal(none.allowed, false);
    assert.ok(none.problems.some((p) => /no pinned evidence keys/.test(p)), JSON.stringify(none.problems));
  });

  test('7. chain heads: a kept head changed or removed is detected; records after the last kept head are not', async () => {
    const { device } = await approvedDevice();
    const first = await confirm(device);
    const firstEvidence = await authCoreSaysYes(first);
    const kept = { chainSequence: firstEvidence.chainSequence, evidenceHash: firstEvidence.evidenceHash };
    const second = await confirm(device);
    const evidence = await authCoreSaysYes(second);
    const chain = await chainOf(device.nexusId);
    assert.deepEqual((await decide(evidence, expectedOf(second, device), { chain, expectedHead: kept })).problems, []);
    // The record at the kept position replaced (another hash there).
    const changed = await decide(evidence, expectedOf(second, device), { chain, expectedHead: { ...kept, evidenceHash: 'f'.repeat(64) } });
    assert.equal(changed.allowed, false);
    assert.ok(changed.problems.some((p) => /differs from the head the bank received/.test(p)), JSON.stringify(changed.problems));
    // The chain cut before the kept head.
    const cut = { ...chain, records: chain.records.filter((r) => r.chainSequence < kept.chainSequence) };
    const truncated = await decide(evidence, expectedOf(second, device), { chain: cut, expectedHead: kept });
    assert.equal(truncated.allowed, false);
    assert.ok(truncated.problems.some((p) => /records missing at the end of the chain|not in the chain/.test(p)), JSON.stringify(truncated.problems));
    // Limit: without a kept head after it, a cut after the last kept head
    // leaves a chain that is consistent in itself.
    const afterHead = chain.records.filter((r) => r.chainSequence <= kept.chainSequence);
    assert.deepEqual(verifyEvidenceChain(afterHead, pinnedEvidenceKeys, { expectedHead: kept }), []);
  });

  test('8. terms other than the bank asked for, signed by an approved device, are refused', async () => {
    const { device } = await approvedDevice();
    const auth = await confirm(device, { amountMinor: '990000' });
    const evidence = await authCoreSaysYes(auth);
    const d = await decide(evidence, expectedOf(auth, device)); // the bank asked for 125000
    assert.equal(d.allowed, false);
    assert.ok(d.problems.some((p) => /amount_minor/.test(p)), JSON.stringify(d.problems));
  });

  test('9. no negative case changed the bank side: the decision is the only execution signal used here', async () => {
    // Auth Core's 202 in the cases above recorded COMMIT_REQUESTED there; the
    // bank executes only on its own decision, which refused every one of them.
    const rows = await q(`SELECT count(*)::int AS n FROM authorization_requests WHERE client_id = $1 AND bank_transaction_state = 'COMMITTED'`, [client.clientId]);
    assert.equal(rows.rows[0].n, 0, 'nothing reported as executed to Auth Core');
  });
});
