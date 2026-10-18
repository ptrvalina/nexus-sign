import { createPublicKey, verify } from 'node:crypto';
import type { PoolClient } from 'pg';
import { env } from '../config/env';
import { authorizationObjectOf, mapAuthorization, type AuthorizationRow } from './authorizationRecord';
import { canonicalizeAuthorization } from './canonicalAuthorization';
import { assertCredentialIntegrity, CredentialIntegrityError, sealProblem } from './credentialIntegrity';
import { getCredentialForClient } from './credentialService';
import { mapEvidenceRow, type EvidenceRow } from './evidenceService';

/**
 * FI-004, phase 9: before Auth Core lets the bank commit a VERIFIED
 * authorization, it re-checks the sealed AUTHORIZATION evidence of that
 * authorization instead of trusting the `state` column:
 *
 *  - exactly one record, HSM seal valid with a known evidence key;
 *  - it names this authorization, its credential and the exact canonical
 *    bytes of the stored (immutable) terms;
 *  - the confirmation method matches the row, and is a device signature
 *    (DEVICE_SIGNATURE or OFFLINE_SIGNED) that verifies with the signing key
 *    sealed at the credential's enrolment;
 *  - OFFLINE_CODE (a code only) is accepted only on a deployment that runs
 *    offline confirmation v1 (`immediate`, never production).
 *
 * A database writer who sets `state = 'VERIFIED'` (the trigger permits the
 * transition with any non-empty signature value) or inserts a record without
 * a valid seal or signature therefore cannot get a commit. What this does not
 * cover: a party controlling the running Auth Core, which holds the HSM
 * session (offline-confirmation-threat-model.md).
 *
 * Returns why the authorization must not be committed, or null.
 */
export async function authorizationEvidenceProblem(tx: PoolClient, auth: AuthorizationRow): Promise<string | null> {
  const records = await tx.query<EvidenceRow>(
    `SELECT * FROM evidence_records WHERE authorization_id = $1 AND record_type = 'AUTHORIZATION'`, [auth.authorization_id]);
  if (records.rows.length !== 1) return records.rows.length === 0 ? 'no sealed evidence for this authorization' : 'more than one evidence record';
  const record = mapEvidenceRow(records.rows[0]);
  const seal = await sealProblem(record);
  if (seal) return seal;
  const p = record.sealedPayload as Record<string, unknown>;
  if (p.recordType !== 'AUTHORIZATION' || p.authorizationId !== auth.authorization_id || p.credentialId !== auth.credential_id
      || p.nexusId !== auth.nexus_id || p.canonicalPayloadHash !== auth.canonical_payload_hash) {
    return 'the evidence names another authorization, identity, credential or terms';
  }
  const canonical = canonicalizeAuthorization(authorizationObjectOf(mapAuthorization(auth)));
  if (typeof p.signedPayloadBase64 !== 'string' || !Buffer.from(p.signedPayloadBase64, 'base64').equals(canonical)) {
    return 'the evidence does not carry the stored terms';
  }
  if (p.confirmationMethod !== auth.confirmation_method) return 'the evidence and the authorization disagree on the confirmation method';

  if (p.confirmationMethod === 'OFFLINE_CODE') {
    return env.OFFLINE_CONFIRMATION_MODE === 'immediate' ? null : 'a code-only offline confirmation is not accepted on this deployment';
  }
  if (p.confirmationMethod !== 'DEVICE_SIGNATURE' && p.confirmationMethod !== 'OFFLINE_SIGNED') return 'unknown confirmation method';
  if (!auth.credential_id) return 'the authorization has no credential';

  // The signing key must be the one sealed at enrolment, and must have signed the bytes.
  let enrolmentHash: string;
  try {
    enrolmentHash = await assertCredentialIntegrity(await getCredentialForClient(auth.credential_id, auth.client_id), tx);
  } catch (error) {
    if (error instanceof CredentialIntegrityError) return 'credential_integrity';
    throw error;
  }
  if (p.enrolmentEvidenceHash !== enrolmentHash) return 'the evidence names another enrolment of the credential';
  const credential = await tx.query<{ public_key_pem: string }>(`SELECT public_key_pem FROM credentials WHERE credential_id = $1`, [auth.credential_id]);
  const key = credential.rows[0]?.public_key_pem;
  if (!key || typeof p.credentialPublicKeyPem !== 'string'
      || !createPublicKey(key).export({ type: 'spki', format: 'der' }).equals(createPublicKey(p.credentialPublicKeyPem).export({ type: 'spki', format: 'der' }))) {
    return 'the evidence names another device key';
  }
  let ok = false;
  try {
    ok = verify('sha256', canonical, { key, dsaEncoding: p.signatureFormat === 'raw' ? 'ieee-p1363' : 'der' }, Buffer.from(String(p.signature), 'base64'));
  } catch {
    ok = false;
  }
  return ok ? null : 'the device signature in the evidence does not verify';
}
