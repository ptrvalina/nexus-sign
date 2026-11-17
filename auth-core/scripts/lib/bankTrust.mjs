// The bank's own decision before it executes a NEXUS-SIGN confirmed
// operation. Nothing here trusts Auth Core: the inputs that decide are the
// bank's (its trust keys, its signed credential approvals and revocations,
// the evidence keys it pinned at the key ceremony, the chain heads it kept,
// the terms it asked for); Auth Core only supplies the evidence export, which
// is checked against them. No Auth Core imports.
//
// Why: a compromised Auth Core (its code, its database, its HSM session) can
// enrol a device key or substitute one, seal the enrolment with the real
// evidence key and accept confirmations signed by that key. Everything it
// reports is then positive and the export verifies (bank-trust-compromise
// tests). Only a decision on the bank's side, from the bank's own record of
// which device key it approved for which customer, refuses it.
import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import { canonicalJson, verifyEvidenceChain, verifyEvidenceRecord, verifyRetainedHeads } from './evidence.mjs';

export const APPROVAL = 'NEXUS_CREDENTIAL_APPROVAL';
export const REVOCATION = 'NEXUS_CREDENTIAL_REVOCATION';

const sha256hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const spki = (pem) => createPublicKey(pem).export({ type: 'spki', format: 'der' });
const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NEXUS_ID = /^[0-9]{9}$/;

/**
 * Fingerprint of a device signing key: lowercase hex SHA-256 of its DER
 * SubjectPublicKeyInfo. The bank's app gets it from the SDK, which computes it
 * on the device from the key it holds (not from anything Auth Core returned).
 */
export function signingKeyFingerprint(publicKeyPem) {
  return sha256hex(spki(publicKeyPem));
}

/** Key ID of a bank trust key: the same SHA-256 of its SubjectPublicKeyInfo. */
export const bankKeyId = signingKeyFingerprint;

/** The bank approves this device key for this customer. */
export function approvalStatement({ nexusId, credentialId, signingKeySha256, reference, approvedAt = new Date().toISOString() }) {
  return { type: APPROVAL, version: 1, nexusId, credentialId, signingKeySha256, reference, approvedAt };
}

/** The bank no longer accepts this credential (lost, replaced, recovered, closed). Final. */
export function revocationStatement({ nexusId, credentialId, reason, revokedAt = new Date().toISOString() }) {
  return { type: REVOCATION, version: 1, nexusId, credentialId, reason, revokedAt };
}

/**
 * Signs a statement with a bank trust key (ECDSA P-256, SHA-256, DER over the
 * canonical JSON of the statement including its bankKeyId). In production the
 * key lives in the bank's HSM; this function is for tools and tests.
 */
export function signStatement(statement, privateKey) {
  const keyId = sha256hex(createPublicKey(privateKey).export({ type: 'spki', format: 'der' }));
  const bound = { ...statement, bankKeyId: keyId };
  return { statement: bound, signature: sign('sha256', canonicalJson(bound), { key: privateKey, dsaEncoding: 'der' }).toString('base64') };
}

function malformed(s) {
  if (!s || typeof s !== 'object' || s.version !== 1) return 'unknown version';
  if (!NEXUS_ID.test(String(s.nexusId)) || !UUID.test(String(s.credentialId)) || !HEX64.test(String(s.bankKeyId))) return 'malformed identifiers';
  if (s.type === APPROVAL) return HEX64.test(String(s.signingKeySha256)) && typeof s.approvedAt === 'string' ? null : 'malformed approval';
  if (s.type === REVOCATION) return typeof s.revokedAt === 'string' ? null : 'malformed revocation';
  return 'unknown statement type';
}

/**
 * Checks the bank's statements against its trust keys. Returns the valid
 * approvals and revocations, and a problem for every entry that is malformed,
 * names an unknown bank key or does not verify (the registry is the bank's
 * own: such an entry means it was changed, and the decision fails closed).
 */
export function readRegistry(entries, bankTrustKeys) {
  const keys = new Map((bankTrustKeys ?? []).map((pem) => [bankKeyId(pem), pem]));
  const approvals = []; const revocations = []; const problems = [];
  (entries ?? []).forEach((entry, index) => {
    const s = entry?.statement;
    const label = `bank statement ${index + 1}`;
    const bad = malformed(s);
    if (bad) { problems.push(`${label}: ${bad}`); return; }
    const key = keys.get(s.bankKeyId);
    if (!key) { problems.push(`${label}: signed with an unknown bank key ${s.bankKeyId}`); return; }
    let ok = false;
    try { ok = verify('sha256', canonicalJson(s), { key, dsaEncoding: 'der' }, Buffer.from(String(entry.signature), 'base64')); } catch { ok = false; }
    if (!ok) { problems.push(`${label}: the signature of a bank statement does not verify`); return; }
    (s.type === APPROVAL ? approvals : revocations).push(s);
  });
  return { approvals, revocations, problems };
}

/** Whether the bank approved, and has not revoked, this key for this customer. */
function credentialProblems(nexusId, credentialId, signingPublicKeyPem, { approvals, revocations }, label) {
  let fingerprint;
  try { fingerprint = signingKeyFingerprint(signingPublicKeyPem); } catch { return [`${label}: the device key of credential ${credentialId} is not a public key`]; }
  const mine = approvals.filter((a) => a.nexusId === nexusId && a.credentialId === credentialId);
  const problems = [];
  if (mine.length === 0) problems.push(`${label}: credential ${credentialId} of NEXUS ID ${nexusId} is not approved by the bank`);
  else if (!mine.some((a) => a.signingKeySha256 === fingerprint)) {
    problems.push(`${label}: the signing key of credential ${credentialId} (${fingerprint}) differs from the key the bank approved (${mine.map((a) => a.signingKeySha256).join(', ')})`);
  }
  const revoked = revocations.find((r) => r.credentialId === credentialId);
  if (revoked) problems.push(`${label}: credential ${credentialId} was revoked by the bank at ${revoked.revokedAt} (${revoked.reason ?? 'no reason'})`);
  return problems;
}

/** The signed terms against what the bank asked for. */
function termsProblems(payload, expected) {
  if (!expected) return ['the bank gave no expected terms: nothing to compare the signed transaction with'];
  let signed;
  try { signed = JSON.parse(Buffer.from(String(payload.signedPayloadBase64), 'base64').toString('utf8')); } catch { return ['the signed bytes are not readable']; }
  const pairs = [
    ['authorization_id', expected.authorizationId], ['nexus_id', expected.nexusId],
    ['transaction_reference', expected.transactionReference], ['amount_minor', expected.amountMinor],
    ['currency', expected.currency], ['operation_type', expected.operationType],
    ['beneficiary', expected.beneficiary],
  ];
  const problems = [];
  for (const [field, want] of pairs) {
    // Every field, operation_type included: the signed operation type is a
    // term the customer saw (finding C-17).
    if (want === undefined) { problems.push(`expected ${field} not given`); continue; }
    const same = typeof want === 'object' ? canonicalJson(want).equals(canonicalJson(signed[field] ?? null)) : String(signed[field]) === String(want);
    if (!same) problems.push(`the signed ${field} (${JSON.stringify(signed[field])}) is not what the bank asked for (${JSON.stringify(want)})`);
  }
  return problems;
}

/**
 * The bank's execution decision for one confirmed operation.
 *
 *   evidence      GET /v1/authorizations/{id}/evidence (the record with its enrolment)
 *   evidenceKeys  evidence public keys the bank pinned (PEM list), never the export's
 *   bankTrustKeys the bank's own statement-signing public keys (PEM list)
 *   registry      the bank's signed approvals and revocations
 *   expected      { authorizationId, nexusId, transactionReference, amountMinor, currency, beneficiary, operationType }
 *   chain         optional GET /v1/nexus-identities/{nexusId}/evidence; with it every
 *                 enrolment in the chain must be approved, and kept heads are checked
 *   expectedHead, heads   chain heads the bank kept (need `chain`)
 *
 * Returns { allowed, problems }. Allowed only with no problem at all.
 */
export function bankExecutionDecision({ evidence, evidenceKeys, bankTrustKeys, registry, expected, chain, expectedHead, heads, rejectOfflineCode = true } = {}) {
  const problems = [];
  const pinned = Array.isArray(evidenceKeys) ? evidenceKeys.filter(Boolean) : [];
  if (pinned.length === 0) problems.push('no pinned evidence keys: the keys inside an export are Auth Core\'s claim');
  if (!Array.isArray(bankTrustKeys) || bankTrustKeys.length === 0) problems.push('no bank trust keys');
  const payload = evidence?.sealedPayload;
  if (!payload || payload.schemaVersion !== '3' || payload.recordType !== 'AUTHORIZATION') {
    return { allowed: false, problems: [...problems, 'the evidence is not a schema 3 AUTHORIZATION record'] };
  }
  if (pinned.length > 0) problems.push(...verifyEvidenceRecord(evidence, pinned, { standalone: true, rejectOfflineCode }));
  problems.push(...termsProblems(payload, expected));

  const trust = readRegistry(registry, bankTrustKeys);
  problems.push(...trust.problems);
  problems.push(...credentialProblems(payload.nexusId, payload.credentialId, payload.credentialPublicKeyPem, trust, 'authorization'));
  const enrolledKey = evidence.credentialEnrolment?.sealedPayload?.keys?.signingPublicKeyPem;
  if (enrolledKey && enrolledKey !== payload.credentialPublicKeyPem) {
    problems.push(...credentialProblems(payload.nexusId, payload.credentialId, enrolledKey, trust, 'enrolment'));
  }

  if (chain) {
    const records = Array.isArray(chain.records) ? chain.records : [];
    if (pinned.length > 0) problems.push(...verifyEvidenceChain(records, pinned, { expectedHead, rejectOfflineCode }));
    if (pinned.length > 0 && Array.isArray(heads) && heads.length > 0) problems.push(...verifyRetainedHeads(records, heads, pinned));
    if (!records.some((r) => r.evidenceHash === evidence.evidenceHash)) problems.push('the authorization record is not in the chain export');
    for (const record of records) {
      const p = record.sealedPayload ?? {};
      if (p.schemaVersion !== '3' || p.recordType !== 'CREDENTIAL_ENROLLED' || p.nexusId !== payload.nexusId) continue;
      const found = credentialProblems(p.nexusId, p.credentialId, p.keys?.signingPublicKeyPem, { ...trust, revocations: [] }, `chain #${record.chainSequence}`);
      for (const problem of found) problems.push(problem.replace(/^(chain #\d+): credential/, `$1: enrolment of credential`));
    }
  } else if (expectedHead || (Array.isArray(heads) && heads.length > 0)) {
    problems.push('kept chain heads can only be checked against the chain export');
  }
  return { allowed: problems.length === 0, problems };
}
