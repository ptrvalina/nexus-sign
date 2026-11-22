// The bank's own check of a confirmation, before any money moves. It uses the
// independent evidence verifier shipped with Auth Core
// (auth-core/scripts/lib/evidence.mjs, imported unchanged: it has no Auth Core
// imports and is what an auditor runs), and then compares the signed terms
// with the transaction the bank recorded (transaction binding).
import { evidenceKeyId, verifyEvidenceChain, verifyEvidenceRecord } from '../../../auth-core/scripts/lib/evidence.mjs';

/** Problems with the evidence record (empty when it verifies), and what was signed. */
export function checkEvidence(record, pinnedKeys) {
  const problems = [];
  const offeredKeys = record.evidencePublicKeys ?? (record.evidencePublicKeyPem ? [record.evidencePublicKeyPem] : []);
  const offered = new Map(offeredKeys.map((pem) => [evidenceKeyId(pem), pem]));
  const sealKeyId = record.sealedPayload?.sealKeyId ?? null;
  // The bank verifies the HSM seal only with keys it has pinned; a key Auth
  // Core offers for the first time is pinned by the caller (trust on first use
  // in the sandbox; a real bank pins its Auth Core keys out of band).
  const trusted = [...pinnedKeys.entries()].filter(([id]) => offered.has(id) || id === sealKeyId).map(([, pem]) => pem);
  if (trusted.length === 0) problems.push('the HSM seal key is not pinned by the bank');
  else problems.push(...verifyEvidenceRecord(record, trusted, { standalone: true, rejectOfflineCode: true }));
  let signed = null;
  try {
    signed = JSON.parse(Buffer.from(record.sealedPayload.signedPayloadBase64, 'base64').toString('utf8'));
  } catch {
    problems.push('signed bytes are not readable');
  }
  return { problems, signed, offered, sealKeyId };
}

/** Compares what the customer signed with what the bank recorded. */
export function checkBinding(transaction, signed, { authorizationId, nexusId, credentialId, canonicalPayloadHash }, record) {
  const expected = signedTermsOf(transaction);
  const problems = [];
  if (!signed) return ['nothing signed'];
  if (signed.authorization_id !== authorizationId) problems.push('authorization_id');
  if (signed.nexus_id !== nexusId) problems.push('nexus_id');
  if (signed.credential_id !== credentialId) problems.push('credential_id');
  if (signed.transaction_reference !== expected.transactionReference) problems.push('transaction_reference');
  if (String(signed.operation_type).toLowerCase() !== expected.operationType) problems.push('operation_type');
  if (signed.amount_minor !== expected.amountMinor) problems.push('amount_minor');
  if (signed.currency !== expected.currency) problems.push('currency');
  const signedBeneficiary = signed.beneficiary ?? {};
  for (const [key, value] of Object.entries(expected.beneficiary)) if (signedBeneficiary[key] !== value) problems.push(`beneficiary.${key}`);
  for (const key of Object.keys(signedBeneficiary)) if (!(key in expected.beneficiary)) problems.push(`beneficiary.${key} (not recorded by the bank)`);
  if (record.sealedPayload?.canonicalPayloadHash !== canonicalPayloadHash) problems.push('canonical payload hash differs from the one returned at creation');
  return problems.map((field) => `signed terms differ from the bank's record: ${field}`);
}

/** The terms the bank asks the customer to sign for a transaction. */
export function signedTermsOf(t) {
  const beneficiary = { name: t.beneficiary_name, iban: t.beneficiary_iban };
  if (t.fee_minor > 0) beneficiary.fee = `${(t.fee_minor / 100).toFixed(2)} ${t.currency}`;
  return {
    transactionReference: t.reference,
    operationType: t.kind === 'INTERNAL_TRANSFER' ? 'transfer' : 'payment',
    amountMinor: String(t.amount_minor),
    currency: t.currency,
    beneficiary,
  };
}

/**
 * The customer's whole chain from Auth Core, checked with the bank's pinned
 * keys; with expectedHead (the newest position the bank stored), records
 * removed from the end are reported.
 */
export function checkChain(chain, pinnedKeys, expectedHead) {
  const records = chain?.records ?? [];
  if (pinnedKeys.size === 0) return { records: records.length, problems: ['no evidence key is pinned yet: execute one payment first'] };
  const problems = verifyEvidenceChain(records, [...pinnedKeys.values()], { ...(expectedHead ? { expectedHead } : {}), rejectOfflineCode: true });
  return { records: records.length, head: chain?.head ?? null, problems: Array.isArray(problems) ? problems : problems?.problems ?? [] };
}
