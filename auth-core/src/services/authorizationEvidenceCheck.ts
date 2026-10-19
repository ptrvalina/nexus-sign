import { createPublicKey, verify } from 'node:crypto';
import type { PoolClient } from 'pg';
import { env } from '../config/env';
import { pool } from '../db/pool';
import { authorizationObjectOf, mapAuthorization, type AuthorizationRow } from './authorizationRecord';
import { canonicalizeAuthorization } from './canonicalAuthorization';
import { assertCredentialIntegrity, CredentialIntegrityError, recordMetadataProblem, sealProblem, type DeferredAudits } from './credentialIntegrity';
import { getCredentialForClient } from './credentialService';
import { mapEvidenceRow, type EvidenceRow } from './evidenceService';

/**
 * FI-004, phase 9: before Auth Core lets the bank commit a VERIFIED
 * authorization, it re-checks the sealed AUTHORIZATION evidence of that
 * authorization instead of trusting the `state` column:
 *
 *  - exactly one record, HSM seal valid with a known evidence key, every
 *    column that repeats a sealed value equal to it (identity, credential,
 *    authorization, type, position, seal key, schema), at its sealed position
 *    in the identity's chain and linked to its predecessor;
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
 * Everything is read through `tx` (the caller may hold the authorization
 * row lock); with `deferred`, security events are queued for after the
 * transaction.
 *
 * Returns why the authorization must not be committed, or null.
 */
export async function authorizationEvidenceProblem(tx: Pick<PoolClient, 'query'>, auth: AuthorizationRow, deferred?: DeferredAudits): Promise<string | null> {
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
  // Its place in the identity's chain: the sealed position must be the stored
  // one, and the predecessor it names must be the record before it. A record
  // sealed outside the normal append (even with a valid seal) is refused.
  if (p.chainSequence !== record.chainSequence || (p.previousEvidenceHash ?? null) !== (record.previousEvidenceHash ?? null)) {
    return 'the evidence is not consistent with its position in the chain';
  }
  const predecessor = record.chainSequence > 1
    ? (await tx.query<{ evidence_hash: string }>(
      `SELECT evidence_hash FROM evidence_records WHERE nexus_id = $1 AND chain_sequence = $2`, [auth.nexus_id, record.chainSequence - 1])).rows[0]?.evidence_hash ?? null
    : null;
  if (predecessor !== (record.previousEvidenceHash ?? null)) return 'the evidence does not link to its predecessor in the chain';
  // Phase 11: the row's remaining columns (identity, credential, position, seal
  // key, schema) must be what was sealed, not only the payload.
  const metadata = recordMetadataProblem(record);
  if (metadata) return metadata;
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
    enrolmentHash = await assertCredentialIntegrity(await getCredentialForClient(auth.credential_id, auth.client_id, tx), tx, deferred);
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

/**
 * What the bank's GET reports: `confirmed` is true only for a VERIFIED
 * authorization whose sealed evidence passes authorizationEvidenceProblem
 * now. A VERIFIED row whose evidence does not (a database write, a damaged
 * record) reports confirmed: false and the reason; nothing is changed or
 * audited here (the commit request audits). Not a cryptographic fact by
 * itself: a bank that needs one verifies the exported evidence.
 */
export async function confirmationView(authorizationId: string, clientId: string, state: string): Promise<{ confirmed: boolean; evidenceProblem?: string }> {
  if (state !== 'VERIFIED') return { confirmed: false };
  const row = await pool.query<AuthorizationRow>(`SELECT * FROM authorization_requests WHERE authorization_id = $1 AND client_id = $2`, [authorizationId, clientId]);
  if (!row.rows[0] || row.rows[0].state !== 'VERIFIED') return { confirmed: false };
  const problem = await authorizationEvidenceProblem(pool, row.rows[0]);
  return problem ? { confirmed: false, evidenceProblem: problem } : { confirmed: true };
}
