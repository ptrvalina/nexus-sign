// Independent verification of NEXUS-SIGN evidence (schemas 2 and 3).
// No Auth Core imports: this is what an auditor runs.
import { createHash, createPublicKey, verify } from 'node:crypto';

const normalize = (v) => (Array.isArray(v)
  ? v.map(normalize)
  : v && typeof v === 'object'
    ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, normalize(v[k])]))
    : v);

/** Canonical JSON: keys sorted recursively, JSON.stringify escaping, UTF-8. */
export const canonicalJson = (value) => Buffer.from(JSON.stringify(normalize(value)), 'utf8');

const sha256hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** Key ID of a PEM public key: SHA-256 of its SubjectPublicKeyInfo. */
export function evidenceKeyId(pem) {
  return sha256hex(createPublicKey(pem).export({ type: 'spki', format: 'der' }));
}

function sameKey(a, b) {
  if (!a || !b) return !a && !b;
  try {
    return createPublicKey(a).export({ type: 'spki', format: 'der' }).equals(createPublicKey(b).export({ type: 'spki', format: 'der' }));
  } catch {
    return false;
  }
}

/** Accepts one PEM, a list of PEMs, or { keyId: pem } and returns { keyId: pem }. */
export function keyring(keys) {
  if (!keys) return {};
  if (typeof keys === 'string') return { [evidenceKeyId(keys)]: keys };
  if (Array.isArray(keys)) return Object.fromEntries(keys.map((pem) => [evidenceKeyId(pem), pem]));
  return Object.fromEntries(Object.values(keys).map((pem) => [evidenceKeyId(pem), pem]));
}

function sealVerifies(record, keys) {
  const candidates = record.sealedPayload?.schemaVersion === '3' ? [keys[record.sealedPayload.sealKeyId]].filter(Boolean) : Object.values(keys);
  return candidates.some((pem) => {
    try {
      return verify('sha256', Buffer.from(record.evidenceHash, 'hex'), { key: pem, dsaEncoding: 'der' }, Buffer.from(record.hsmSignature, 'base64'));
    } catch {
      return false;
    }
  });
}

const labelOf = (record) => record.authorizationId ?? `${record.recordType ?? 'record'}#${record.chainSequence ?? '?'}`;

/**
 * Checks one exported record on its own:
 *  1. the evidence hash is the hash of the sealed payload;
 *  2. the HSM seal verifies with the evidence key the record names (schema 3)
 *     or with one of the given keys (schema 2);
 *  3. the record's metadata matches the sealed payload;
 *  4. AUTHORIZATION: the signed bytes hash to canonicalPayloadHash, name the
 *     same authorization, identity and credential, and the device signature
 *     verifies over them with the sealed device key (not applicable to
 *     offline confirmations, whose code is an HMAC);
 *  5. AUTHORIZATION (schema 3) exported alone (`standalone`): the attached
 *     enrolment record is present, valid, is the one the authorization names,
 *     and sealed the same key.
 * Returns a list of problems (empty when the record is valid).
 */
export function verifyEvidenceRecord(record, evidenceKeys, { standalone = false, rejectOfflineCode = false } = {}) {
  const keys = keyring(evidenceKeys);
  const label = labelOf(record);
  const payload = record.sealedPayload;
  if (!payload || !['2', '3'].includes(payload.schemaVersion)) return [`${label}: unsupported or missing sealed payload`];
  const problems = [];
  if (sha256hex(canonicalJson(payload)) !== record.evidenceHash) problems.push(`${label}: evidence hash does not match the sealed payload`);
  if (!sealVerifies(record, keys)) problems.push(`${label}: HSM seal does not verify with the evidence key it names`);
  if (payload.nexusId !== record.nexusId) problems.push(`${label}: record metadata does not match the sealed payload`);
  if ((payload.previousEvidenceHash ?? null) !== (record.previousEvidenceHash ?? null)) {
    problems.push(`${label}: previousEvidenceHash differs between record and payload`);
  }
  const recordType = payload.schemaVersion === '3' ? payload.recordType : 'AUTHORIZATION';
  if (payload.schemaVersion === '3') {
    if (payload.recordType !== record.recordType) problems.push(`${label}: record type differs between record and payload`);
    if (payload.chainSequence !== record.chainSequence) problems.push(`${label}: chain position differs between record and payload`);
  }
  if (recordType === 'AUTHORIZATION') {
    if (payload.authorizationId !== record.authorizationId) problems.push(`${label}: record metadata does not match the sealed payload`);
    problems.push(...verifyDeviceSignature(payload, { rejectOfflineCode }).map((p) => `${label}: ${p}`));
    if (payload.schemaVersion === '3' && (standalone || record.credentialEnrolment !== undefined)) {
      // Exported alone, the record must bring the enrolment that proves its
      // key; removing the field must not skip the check.
      if (!record.credentialEnrolment) problems.push(`${label}: the enrolment record of the signing credential is missing`);
      else problems.push(...verifyEnrolmentLink(payload, record.credentialEnrolment, keys).map((p) => `${label}: ${p}`));
    }
  } else if (recordType === 'CREDENTIAL_ENROLLED') {
    if (!payload.keys || typeof payload.keys.signingPublicKeyPem !== 'string' || payload.credentialId !== record.credentialId) {
      problems.push(`${label}: enrolment record does not carry the credential and its keys`);
    }
  } else if (recordType === 'RECOVERY_CONFIGURED') {
    if (typeof payload.recoveryPublicKeyPem !== 'string') problems.push(`${label}: recovery record does not carry the recovery key`);
  } else {
    problems.push(`${label}: unknown record type ${recordType}`);
  }
  return problems;
}

/** An authorization's attached enrolment record proves the signing key. */
function verifyEnrolmentLink(authorization, enrolment, keys) {
  if (!enrolment) return ['the enrolment record of the signing credential is missing'];
  const problems = verifyEvidenceRecord(enrolment, keys).map((p) => `enrolment: ${p}`);
  const sealed = enrolment.sealedPayload ?? {};
  if (sealed.recordType !== 'CREDENTIAL_ENROLLED' || enrolment.evidenceHash !== authorization.enrolmentEvidenceHash) {
    problems.push('the attached enrolment is not the one the authorization names');
  } else if (sealed.credentialId !== authorization.credentialId || !sameKey(sealed.keys?.signingPublicKeyPem, authorization.credentialPublicKeyPem)) {
    problems.push('the device key differs from the key sealed at enrolment');
  }
  return problems;
}

/** Steps 4 of verifyEvidenceRecord, on an AUTHORIZATION payload alone. */
export function verifyDeviceSignature(payload, { rejectOfflineCode = false } = {}) {
  if (typeof payload.signedPayloadBase64 !== 'string' || typeof payload.credentialPublicKeyPem !== 'string') {
    return ['sealed payload does not carry the signed bytes and device key'];
  }
  const signed = Buffer.from(payload.signedPayloadBase64, 'base64');
  const problems = [];
  if (sha256hex(signed) !== payload.canonicalPayloadHash) problems.push('signed bytes do not match canonicalPayloadHash');
  let fields = null;
  try {
    fields = JSON.parse(signed.toString('utf8'));
  } catch {
    problems.push('signed bytes are not JSON');
  }
  if (fields && (fields.authorization_id !== payload.authorizationId || fields.nexus_id !== payload.nexusId
      || fields.credential_id !== payload.credentialId || fields.transaction_reference !== payload.transactionReference)) {
    problems.push('signed bytes name a different authorization, identity, credential or reference');
  }
  // An offline confirmation carries an HMAC with a key shared by the device
  // and Auth Core: nothing a third party can re-verify.
  if (payload.confirmationMethod === 'OFFLINE_CODE') {
    if (payload.signatureFormat !== 'hmac' || payload.signatureAlgorithm !== 'HMAC-SHA256') {
      problems.push('offline confirmation record does not carry an HMAC tag');
    }
    // A bank that has moved to offline confirmation v2 accepts no code-only
    // confirmation: whoever controls Auth Core can compute such a code.
    if (rejectOfflineCode) problems.push('offline code without a device signature (OFFLINE_CODE) is not accepted (--reject-offline-code)');
    return problems;
  }
  // Offline confirmation v2: the accepted code plus the device's ECDSA
  // signature over the same bytes; the signature is checked like an online one.
  if (payload.confirmationMethod === 'OFFLINE_SIGNED') {
    if (typeof payload.offlineCodeTag !== 'string' || Buffer.from(payload.offlineCodeTag, 'base64').length !== 32
        || typeof payload.offlineCodeAcceptedAt !== 'string' || typeof payload.deferredSignatureReceivedAt !== 'string') {
      problems.push('offline confirmation v2 record does not carry the accepted code and its times');
    }
    if (payload.signatureFormat !== 'der' && payload.signatureFormat !== 'raw') problems.push('offline confirmation v2 record does not carry an ECDSA signature');
  } else if (payload.confirmationMethod !== undefined && payload.confirmationMethod !== 'DEVICE_SIGNATURE') {
    return [...problems, `unknown confirmation method ${payload.confirmationMethod}`];
  }
  let deviceOk = false;
  try {
    deviceOk = verify('sha256', signed,
      { key: payload.credentialPublicKeyPem, dsaEncoding: payload.signatureFormat === 'raw' ? 'ieee-p1363' : 'der' },
      Buffer.from(payload.signature, 'base64'));
  } catch {
    deviceOk = false;
  }
  if (!deviceOk) problems.push('device signature does not verify over the signed bytes');
  return problems;
}

/** Human-readable summary of what the customer signed, for audit reports. */
export function describeSignedTransaction(payload) {
  const f = JSON.parse(Buffer.from(payload.signedPayloadBase64, 'base64').toString('utf8'));
  const beneficiary = Object.entries(f.beneficiary).map(([k, v]) => `${k}=${v}`).join(', ');
  const how = payload.confirmationMethod === 'OFFLINE_CODE' ? 'confirmed offline with a code'
    : payload.confirmationMethod === 'OFFLINE_SIGNED' ? 'confirmed offline with a code and signed (signature received later)' : 'signed';
  return `${f.operation_type} ${f.amount_minor} (minor units) ${f.currency} to [${beneficiary}], ref ${f.transaction_reference}, ${how} at ${payload.verifiedAt}`;
}

/**
 * Checks a NEXUS ID's complete chain:
 *  - every record valid (verifyEvidenceRecord);
 *  - numbered 1, 2, 3 ... and each linked to its predecessor (no gap, no fork);
 *  - every schema 3 AUTHORIZATION signed with a key whose CREDENTIAL_ENROLLED
 *    record appears earlier in the chain and is the one it names;
 *  - with `expectedHead` ({ chainSequence, evidenceHash } that the bank kept
 *    from a confirmation), the chain reaches that record unchanged: records
 *    removed from the end are reported.
 */
export function verifyEvidenceChain(records, evidenceKeys, { expectedHead, rejectOfflineCode = false } = {}) {
  const keys = keyring(evidenceKeys);
  const problems = [];
  const ordered = [...records].sort((a, b) => (a.chainSequence ?? 0) - (b.chainSequence ?? 0));
  const enrolments = new Map();
  let previous = null;
  ordered.forEach((record, index) => {
    const label = labelOf(record);
    problems.push(...verifyEvidenceRecord(record, keys, { rejectOfflineCode }));
    if (record.chainSequence !== undefined && record.chainSequence !== index + 1) {
      problems.push(`${label}: chain position ${record.chainSequence} where ${index + 1} was expected (records missing or duplicated)`);
    }
    if ((record.sealedPayload?.previousEvidenceHash ?? null) !== previous) {
      problems.push(`${label}: chain broken (expected previous ${previous ?? 'none'})`);
    }
    const payload = record.sealedPayload ?? {};
    if (payload.schemaVersion === '3' && payload.recordType === 'CREDENTIAL_ENROLLED') {
      enrolments.set(record.evidenceHash, payload);
    }
    if (payload.schemaVersion === '3' && payload.recordType === 'AUTHORIZATION') {
      const enrolment = enrolments.get(payload.enrolmentEvidenceHash);
      if (!enrolment) {
        problems.push(`${label}: the enrolment of the signing credential is not earlier in the chain`);
      } else if (enrolment.credentialId !== payload.credentialId || !sameKey(enrolment.keys?.signingPublicKeyPem, payload.credentialPublicKeyPem)) {
        problems.push(`${label}: the device key differs from the key sealed at enrolment`);
      }
    }
    previous = record.evidenceHash;
  });
  if (expectedHead) {
    const head = ordered.find((r) => r.chainSequence === expectedHead.chainSequence);
    if (!head) {
      problems.push(`records missing at the end of the chain: the bank's head is record ${expectedHead.chainSequence}, the export ends at ${ordered.length}`);
    } else if (head.evidenceHash !== expectedHead.evidenceHash) {
      problems.push(`record ${expectedHead.chainSequence} differs from the head the bank received`);
    }
  }
  return problems;
}

/**
 * Checks a chain export against the heads the bank kept from
 * `evidence.appended` webhooks (FI-019): each head must be HSM-sealed by a
 * known key (so the bank's own store can be trusted to be what Auth Core
 * sent), and the export must contain that record unchanged. A head beyond
 * the end of the export means records were removed; a head whose hash
 * differs means the chain was rewritten.
 */
export function verifyRetainedHeads(records, heads, evidenceKeys) {
  const keys = keyring(evidenceKeys);
  const problems = [];
  const bySequence = new Map(records.map((r) => [r.chainSequence, r]));
  const last = Math.max(0, ...records.map((r) => r.chainSequence ?? 0));
  for (const head of heads) {
    const label = `head #${head.chainSequence}`;
    if (!Number.isInteger(head.chainSequence) || typeof head.evidenceHash !== 'string') { problems.push(`${label}: malformed (needs chainSequence and evidenceHash)`); continue; }
    if (head.hsmSignature !== undefined) {
      const key = keys[head.sealKeyId];
      let sealed = false;
      try { sealed = Boolean(key) && verify('sha256', Buffer.from(head.evidenceHash, 'hex'), { key, dsaEncoding: 'der' }, Buffer.from(head.hsmSignature, 'base64')); } catch { sealed = false; }
      if (!sealed) problems.push(`${label}: its HSM seal does not verify with the given keys (not a head Auth Core sent)`);
    }
    const record = bySequence.get(head.chainSequence);
    if (!record) problems.push(`records missing at the end of the chain: the bank holds head #${head.chainSequence}, the export ends at ${last}`);
    else if (record.evidenceHash !== head.evidenceHash) problems.push(`record ${head.chainSequence} differs from the head the bank holds`);
  }
  return problems;
}

/** Records of a chain sealed before schema 3, whose key provenance cannot be checked. */
export function legacyRecords(records) {
  return records.filter((r) => r.sealedPayload?.schemaVersion !== '3');
}
