import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { pool } from '../db/pool';
import { canonicalJson } from './canonicalAuthorization';
import { NotFoundError } from './errors';
import { enqueueWebhook } from './webhookService';

/**
 * Evidence, schema version 3 (docs/protocol/evidence-format.md, ADR 0009).
 *
 * Every NEXUS ID has one hash chain of sealed records, numbered from 1:
 *
 *   AUTHORIZATION        a confirmed transaction: the exact bytes the device
 *                        signed, the signature, and the hash of the
 *                        CREDENTIAL_ENROLLED record of the signing credential;
 *   CREDENTIAL_ENROLLED  the public keys of a credential and the attestation
 *                        material that admitted them;
 *   RECOVERY_CONFIGURED  the recovery public key a device registered.
 *
 * Each record seals { schemaVersion, recordType, nexusId, chainSequence,
 * previousEvidenceHash, sealKeyId, ...body }:
 *
 *   evidenceHash = hex(SHA-256(canonicalJson(sealedPayload)))
 *   hsmSignature = ECDSA-P256-SHA256(evidence key, bytes(evidenceHash))   (DER, base64)
 *   sealKeyId    = hex(SHA-256(SubjectPublicKeyInfo of the evidence key))
 *
 * Why enrolment is sealed: the device key used to verify a customer's
 * signature is a database value. A database writer who replaced it could
 * otherwise produce an approval that verifies. With the enrolment sealed,
 * Auth Core compares a credential's keys with its sealed enrolment before
 * using them (credentialIntegrity.ts), and an auditor checks that every
 * approval was signed by a key whose enrolment is in the same chain.
 *
 * Why records are numbered: chainSequence and the head (sequence and hash)
 * that the bank receives with every confirmation let a verifier detect
 * records removed from the end of a chain, which links alone cannot show.
 */
export const EVIDENCE_SCHEMA_VERSION = '3';

export type EvidenceRecordType = 'AUTHORIZATION' | 'CREDENTIAL_ENROLLED' | 'RECOVERY_CONFIGURED';

export interface ChainPosition {
  evidenceId: string;
  chainSequence: number;
  evidenceHash: string;
}

export interface AuthorizationEvidenceInput {
  authorizationId: string;
  nexusId: string;
  credentialId: string;
  transactionReference: string;
  canonicalPayloadHash: string;
  /** The canonical authorization bytes the device signed. */
  signedPayload: Buffer;
  credentialPublicKeyPem: string;
  /** evidenceHash of the credential's CREDENTIAL_ENROLLED record. */
  enrolmentEvidenceHash: string;
  signature: string;
  signatureFormat: 'der' | 'raw' | 'hmac';
  signatureAlgorithm: string;
  /** DEVICE_SIGNATURE: ECDSA by the device signing key, verifiable by anyone.
   * OFFLINE_CODE: HMAC with a key shared by device and Auth Core; proves the
   * device produced the code but is not verifiable by a third party.
   * OFFLINE_SIGNED (offline confirmation v2): the accepted code and the
   * device's ECDSA signature over the same bytes, uploaded later; the
   * signature is verifiable like DEVICE_SIGNATURE. */
  confirmationMethod: 'DEVICE_SIGNATURE' | 'OFFLINE_CODE' | 'OFFLINE_SIGNED';
  /** OFFLINE_SIGNED only: the accepted code's tag and the two times. */
  offline?: { offlineCodeTag: string; offlineCodeAcceptedAt: string; deferredSignatureReceivedAt: string };
  keyVersion: number;
  policyReference: string;
  policyVersion: string;
  attestationVerdict: string;
  verifiedAt: Date;
  result: string;
  correlationId: string | null;
}

/** Why a credential was enrolled. */
/** Reasons sealed by this version. Chains written by 1.x and 2.0.0-rc.1 can
 * also hold `ROTATION` and `BANK_PROVISIONED`, from the removed bank-side
 * provisioning endpoints; verifiers accept any reason string. */
export type EnrolmentReason = 'ENROLMENT' | 'REPLACEMENT' | 'RECOVERY' | 'BASELINE';

/** The attestation material that admitted a credential, as stored in the
 * sealed record. `material` holds what a third party can re-check (the App
 * Attest object, Android key attestation chains) and digests of what it
 * cannot (Play Integrity tokens are decoded by Google). */
export interface EnrolmentAttestation {
  status: 'VERIFIED' | 'UNKNOWN' | 'FAILED' | 'EXPIRED';
  bindingSha256: string | null;
  material: Record<string, unknown>;
}

export interface CredentialEnrolmentInput {
  nexusId: string;
  credentialId: string;
  reason: EnrolmentReason;
  platform: string;
  securityLevel: string;
  signingPublicKeyPem: string;
  authPublicKeyPem: string | null;
  offlinePublicKeyPem: string | null;
  attestation: EnrolmentAttestation;
  replacedCredentialIds: string[];
  /** For REPLACEMENT: how the bank re-identified the customer. */
  replacementAuthorization: { method: string; reference: string; clientId: string } | null;
}

export interface RecoveryConfigurationInput {
  nexusId: string;
  /** The device credential that registered the recovery key. */
  credentialId: string;
  recoveryProtocol: number;
  recoveryPublicKeyPem: string;
  /** SHA-256 (hex) of the wrapped recovery key held for the device. */
  wrappedRecoveryKeySha256: string;
  kdfSaltB64: string;
  kdfIterations: number;
}

export interface SealedEvidence {
  evidenceId: string;
  recordType: EvidenceRecordType;
  authorizationId: string | null;
  nexusId: string;
  credentialId: string;
  chainSequence: number;
  sealedPayload: Record<string, unknown>;
  evidenceHash: string;
  previousEvidenceHash: string | null;
  hsmSignature: string;
  hsmKeyVersion: number;
  sealKeyId: string | null;
  schemaVersion: string;
  createdAt: string;
}

export function evidenceHash(sealedPayload: Record<string, unknown>): string {
  return createHash('sha256').update(canonicalJson(sealedPayload)).digest('hex');
}

interface RecordColumns {
  authorizationId: string | null;
  credentialId: string;
  transactionReference?: string;
  canonicalPayloadHash?: string;
  signature?: string;
  signatureAlgorithm?: string;
  keyVersion?: number;
  policyVersion?: string;
  attestationVerdict?: string;
  verifiedAt?: Date;
  result?: string;
  correlationId?: string | null;
  verificationFactors?: unknown[];
}

/**
 * Appends one sealed record to the NEXUS ID's chain in the caller's
 * transaction. The advisory lock serialises writers of one chain, and the
 * unique indexes on (nexus_id, chain_sequence) and on the predecessor reject
 * a fork even if the lock were bypassed.
 */
async function appendRecord(
  tx: PoolClient,
  hsm: HsmAdapter,
  nexusId: string,
  recordType: EvidenceRecordType,
  body: Record<string, unknown>,
  columns: RecordColumns,
): Promise<ChainPosition> {
  await tx.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [nexusId]);
  const previous = await tx.query<{ evidence_hash: string; chain_sequence: string }>(
    `SELECT evidence_hash, chain_sequence FROM evidence_records WHERE nexus_id = $1 ORDER BY chain_sequence DESC LIMIT 1`, [nexusId]);
  const previousEvidenceHash = previous.rows[0]?.evidence_hash ?? null;
  const chainSequence = Number(previous.rows[0]?.chain_sequence ?? 0) + 1;
  const sealKeyId = await hsm.evidenceKeyId();

  const sealedPayload = {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    recordType,
    nexusId,
    chainSequence,
    previousEvidenceHash,
    sealKeyId,
    ...body,
  };
  const hash = evidenceHash(sealedPayload);
  const seal = await hsm.signEvidence(Buffer.from(hash, 'hex'));
  if (seal.keyId !== sealKeyId) throw new Error('The HSM evidence key changed while a record was being sealed');

  const inserted = await tx.query<{ evidence_id: string }>(
    `INSERT INTO evidence_records (
       record_type, authorization_id, nexus_id, credential_id, chain_sequence, transaction_reference, canonical_payload_hash,
       signature, signature_algorithm, key_version, policy_version, attestation_verdict, verified_at, consumed_at, result,
       correlation_id, previous_evidence_hash, evidence_hash, hsm_signature, hsm_key_version, seal_key_id, schema_version,
       verification_factors, sealed_payload, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,clock_timestamp())
     RETURNING evidence_id`,
    [recordType, columns.authorizationId, nexusId, columns.credentialId, chainSequence, columns.transactionReference ?? null,
      columns.canonicalPayloadHash ?? null, columns.signature ?? null, columns.signatureAlgorithm ?? null, columns.keyVersion ?? null,
      columns.policyVersion ?? null, columns.attestationVerdict ?? null, columns.verifiedAt ?? null, columns.result ?? null,
      columns.correlationId ?? null, previousEvidenceHash, hash, seal.signature.toString('base64'), seal.keyVersion, sealKeyId,
      EVIDENCE_SCHEMA_VERSION, JSON.stringify(columns.verificationFactors ?? []), JSON.stringify(sealedPayload)],
  );
  // FI-019: every new chain head goes to the bank (transactional outbox), so
  // the bank holds HSM-sealed checkpoints that Auth Core cannot take back;
  // verify-evidence --heads detects records removed after any of them.
  const owner = await tx.query<{ client_id: string }>(`SELECT client_id FROM nexus_identities WHERE nexus_id = $1`, [nexusId]);
  if (owner.rows[0]) {
    await enqueueWebhook(owner.rows[0].client_id, 'evidence.appended', {
      nexusId, recordType, evidenceId: inserted.rows[0].evidence_id, chainSequence, evidenceHash: hash,
      previousEvidenceHash, sealKeyId, hsmSignature: seal.signature.toString('base64'),
    }, tx);
  }
  return { evidenceId: inserted.rows[0].evidence_id, chainSequence, evidenceHash: hash };
}

/** Seals a confirmed authorization, in the transaction that consumes it. */
export async function sealAuthorizationEvidence(tx: PoolClient, hsm: HsmAdapter, input: AuthorizationEvidenceInput): Promise<ChainPosition> {
  const factors = await tx.query<{ channel: string; status: string; provider_reference: string | null; assertion_hash: string | null; completed_at: Date | null; result_method: string | null; result_issuer: string | null }>(
    `SELECT channel, status, provider_reference, assertion_hash, completed_at, result_method, result_issuer
     FROM verification_sessions WHERE authorization_id = $1 ORDER BY created_at ASC`, [input.authorizationId]);
  // method: PROVIDER (signed result token; issuer "<providerId>/<keyId>",
  // assertionHash = SHA-256 of the token) or OPERATOR (issuer = the bank
  // operator's username). Sessions closed without a result have neither.
  const verificationFactors = factors.rows.map((row) => ({
    channel: row.channel,
    status: row.status,
    method: row.result_method,
    issuer: row.result_issuer,
    providerReference: row.provider_reference,
    assertionHash: row.assertion_hash,
    completedAt: row.completed_at?.toISOString() ?? null,
  }));
  return appendRecord(tx, hsm, input.nexusId, 'AUTHORIZATION', {
    authorizationId: input.authorizationId,
    credentialId: input.credentialId,
    transactionReference: input.transactionReference,
    canonicalPayloadHash: input.canonicalPayloadHash,
    signedPayloadBase64: input.signedPayload.toString('base64'),
    credentialPublicKeyPem: input.credentialPublicKeyPem,
    enrolmentEvidenceHash: input.enrolmentEvidenceHash,
    signature: input.signature,
    signatureFormat: input.signatureFormat,
    signatureAlgorithm: input.signatureAlgorithm,
    confirmationMethod: input.confirmationMethod,
    ...(input.offline ?? {}),
    keyVersion: input.keyVersion,
    policyReference: input.policyReference,
    policyVersion: input.policyVersion,
    attestationVerdict: input.attestationVerdict,
    verifiedAt: input.verifiedAt.toISOString(),
    result: input.result,
    correlationId: input.correlationId,
    verificationFactors,
  }, {
    authorizationId: input.authorizationId,
    credentialId: input.credentialId,
    transactionReference: input.transactionReference,
    canonicalPayloadHash: input.canonicalPayloadHash,
    signature: input.signature,
    signatureAlgorithm: input.signatureAlgorithm,
    keyVersion: input.keyVersion,
    policyVersion: input.policyVersion,
    attestationVerdict: input.attestationVerdict,
    verifiedAt: input.verifiedAt,
    result: input.result,
    correlationId: input.correlationId,
    verificationFactors,
  });
}

/** Seals the keys of a new credential and points the credential at the
 * record, in the transaction that creates it. */
export async function sealCredentialEnrolment(tx: PoolClient, hsm: HsmAdapter, input: CredentialEnrolmentInput): Promise<ChainPosition> {
  const position = await appendRecord(tx, hsm, input.nexusId, 'CREDENTIAL_ENROLLED', {
    credentialId: input.credentialId,
    reason: input.reason,
    enrolledAt: new Date().toISOString(),
    platform: input.platform,
    securityLevel: input.securityLevel,
    keys: {
      signingPublicKeyPem: input.signingPublicKeyPem,
      authPublicKeyPem: input.authPublicKeyPem,
      offlinePublicKeyPem: input.offlinePublicKeyPem,
    },
    attestation: input.attestation,
    replacedCredentialIds: input.replacedCredentialIds,
    replacementAuthorization: input.replacementAuthorization,
  }, { authorizationId: null, credentialId: input.credentialId, attestationVerdict: input.attestation.status });
  await tx.query(`UPDATE credentials SET enrolment_evidence_id = $2 WHERE credential_id = $1`, [input.credentialId, position.evidenceId]);
  return position;
}

/** Seals a registered recovery public key and points the identity at it. */
export async function sealRecoveryConfiguration(tx: PoolClient, hsm: HsmAdapter, input: RecoveryConfigurationInput): Promise<ChainPosition> {
  const position = await appendRecord(tx, hsm, input.nexusId, 'RECOVERY_CONFIGURED', {
    credentialId: input.credentialId,
    configuredAt: new Date().toISOString(),
    recoveryProtocol: input.recoveryProtocol,
    recoveryPublicKeyPem: input.recoveryPublicKeyPem,
    wrappedRecoveryKeySha256: input.wrappedRecoveryKeySha256,
    kdfSaltB64: input.kdfSaltB64,
    kdfIterations: input.kdfIterations,
  }, { authorizationId: null, credentialId: input.credentialId });
  await tx.query(`UPDATE nexus_identities SET recovery_evidence_id = $2 WHERE nexus_id = $1`, [input.nexusId, position.evidenceId]);
  return position;
}

/** One record by ID, for integrity checks. */
export async function getEvidenceRecord(runner: Pick<PoolClient, 'query'>, evidenceId: string): Promise<SealedEvidence | null> {
  const result = await runner.query<EvidenceRow>(`SELECT * FROM evidence_records WHERE evidence_id = $1`, [evidenceId]);
  return result.rows[0] ? mapEvidence(result.rows[0]) : null;
}

/** Evidence for one authorization of this bank client, in export form, with
 * the enrolment record of its credential so the export verifies on its own. */
export async function getEvidenceForAuthorization(authorizationId: string, clientId: string): Promise<SealedEvidence & { credentialEnrolment: SealedEvidence | null }> {
  const result = await pool.query<EvidenceRow>(
    `SELECT e.* FROM evidence_records e
     JOIN authorization_requests a ON a.authorization_id = e.authorization_id
     WHERE e.authorization_id = $1 AND a.client_id = $2`, [authorizationId, clientId]);
  if (!result.rows[0]) throw new NotFoundError('No evidence exists for this authorization');
  const record = mapEvidence(result.rows[0]);
  const enrolmentHash = record.sealedPayload.enrolmentEvidenceHash;
  let credentialEnrolment: SealedEvidence | null = null;
  if (typeof enrolmentHash === 'string') {
    const enrolment = await pool.query<EvidenceRow>(
      `SELECT * FROM evidence_records WHERE nexus_id = $1 AND evidence_hash = $2 AND record_type = 'CREDENTIAL_ENROLLED'`,
      [record.nexusId, enrolmentHash]);
    credentialEnrolment = enrolment.rows[0] ? mapEvidence(enrolment.rows[0]) : null;
  }
  return { ...record, credentialEnrolment };
}

/** The evidence chain of one NEXUS ID, in sequence order. */
export async function getEvidenceChain(nexusId: string, clientId: string, page: { after?: number; limit?: number } = {}): Promise<SealedEvidence[]> {
  const identity = await pool.query(`SELECT 1 FROM nexus_identities WHERE nexus_id = $1 AND client_id = $2`, [nexusId, clientId]);
  if (!identity.rows[0]) throw new NotFoundError(`NEXUS ID ${nexusId} was not found`);
  const result = await pool.query<EvidenceRow>(
    `SELECT * FROM evidence_records WHERE nexus_id = $1 AND chain_sequence > $2 ORDER BY chain_sequence ASC LIMIT $3`,
    [nexusId, page.after ?? 0, page.limit ?? 1000]);
  return result.rows.map(mapEvidence);
}

/** The latest record of a chain: what the bank keeps to detect truncation. */
export async function getChainHead(runner: Pick<PoolClient, 'query'>, nexusId: string): Promise<ChainPosition | null> {
  const result = await runner.query<{ evidence_id: string; chain_sequence: string; evidence_hash: string }>(
    `SELECT evidence_id, chain_sequence, evidence_hash FROM evidence_records WHERE nexus_id = $1 ORDER BY chain_sequence DESC LIMIT 1`, [nexusId]);
  const row = result.rows[0];
  return row ? { evidenceId: row.evidence_id, chainSequence: Number(row.chain_sequence), evidenceHash: row.evidence_hash } : null;
}

/** The chain position of an authorization's record, if it has one. */
export async function getAuthorizationEvidencePosition(authorizationId: string): Promise<ChainPosition | null> {
  const result = await pool.query<{ evidence_id: string; chain_sequence: string; evidence_hash: string }>(
    `SELECT evidence_id, chain_sequence, evidence_hash FROM evidence_records WHERE authorization_id = $1`, [authorizationId]);
  const row = result.rows[0];
  return row ? { evidenceId: row.evidence_id, chainSequence: Number(row.chain_sequence), evidenceHash: row.evidence_hash } : null;
}

export interface EvidenceRow {
  evidence_id: string; record_type: EvidenceRecordType; authorization_id: string | null; nexus_id: string; credential_id: string;
  chain_sequence: string; sealed_payload: Record<string, unknown> | null; evidence_hash: string; previous_evidence_hash: string | null;
  hsm_signature: string; hsm_key_version: number; seal_key_id: string | null; schema_version: string; created_at: Date;
}

export function mapEvidenceRow(row: EvidenceRow): SealedEvidence { return mapEvidence(row); }

function mapEvidence(row: EvidenceRow): SealedEvidence {
  return {
    evidenceId: row.evidence_id,
    recordType: row.record_type,
    authorizationId: row.authorization_id,
    nexusId: row.nexus_id,
    credentialId: row.credential_id,
    chainSequence: Number(row.chain_sequence),
    sealedPayload: row.sealed_payload ?? {},
    evidenceHash: row.evidence_hash,
    previousEvidenceHash: row.previous_evidence_hash,
    hsmSignature: row.hsm_signature,
    hsmKeyVersion: row.hsm_key_version,
    sealKeyId: row.seal_key_id,
    schemaVersion: row.schema_version,
    createdAt: row.created_at.toISOString(),
  };
}
