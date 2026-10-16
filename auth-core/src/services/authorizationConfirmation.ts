import { timingSafeEqual } from 'node:crypto';
import type { PoolClient } from 'pg';
import { withTransaction } from '../db/pool';
import { recordAuditEvent, type AuditContext } from './auditService';
import { getNexusIdentityForClient } from './nexusIdentityService';
import { getCredentialForClient } from './credentialService';
import { canonicalizeAuthorization, hashCanonicalAuthorization } from './canonicalAuthorization';
import { sealAuthorizationEvidence, type ChainPosition } from './evidenceService';
import { assertCredentialIntegrity, CredentialIntegrityError } from './credentialIntegrity';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { decryptSecretBytes } from '../crypto/secretBox';
import { env } from '../config/env';
import { OFFLINE_CODE_DIGITS, offlineCodeFromTag, offlineConfirmationTag, offlineQrPayload } from './deviceProtocol';
import { settlePlanForConfirmation } from './adaptiveVerificationService';
import {
  AuthorizationNotFoundError,
  FINAL_STATES,
  OPEN_STATES,
  authorizationObjectOf,
  getAuthorizationForClient,
  mapAuthorization,
  type AuthorizationRow,
} from './authorizationRecord';
import { ConflictError } from './errors';
import { markExpired } from './authorizationExpiry';
import { enqueueWebhook } from './webhookService';
import { getChainHead } from './evidenceService';

const MAX_SIGNATURE_ATTEMPTS = 5;

export type VerificationResult =
  | { status: 'VERIFIED'; evidence: ChainPosition }
  | { status: 'FAILED'; reason: string; attempts?: number }
  | { status: 'EXPIRED'; reason?: string };

/** How the customer confirmed: a device signature, or an offline code. */
export type ConfirmationProof =
  | { kind: 'DEVICE_SIGNATURE'; signatureB64: string; signatureFormat: 'der' | 'raw' }
  | { kind: 'OFFLINE_CODE'; code: string };

/**
 * Verifies the device signature over the canonical bytes and, if valid and
 * the verification plan is satisfied, consumes the authorization and seals
 * the evidence. Every invalid signature counts toward MAX_SIGNATURE_ATTEMPTS.
 */
export async function verifyAuthorization(
  hsmAdapter: HsmAdapter,
  id: string,
  clientId: string,
  signatureB64: string,
  signatureFormat: 'der' | 'raw',
  auditContext: AuditContext = {},
): Promise<VerificationResult> {
  return confirmAuthorization(hsmAdapter, id, clientId, { kind: 'DEVICE_SIGNATURE', signatureB64, signatureFormat }, auditContext);
}

/**
 * Offline confirmation: the bank relays the 8-digit code the customer read
 * from the phone. The code shares the attempt limit with device signatures.
 */
export async function confirmAuthorizationOffline(
  hsmAdapter: HsmAdapter,
  id: string,
  clientId: string,
  code: string,
  auditContext: AuditContext = {},
): Promise<VerificationResult> {
  return confirmAuthorization(hsmAdapter, id, clientId, { kind: 'OFFLINE_CODE', code }, auditContext);
}

/** QR content for offline confirmation of a pending authorization. */
export async function getOfflineChallenge(id: string, clientId: string): Promise<{ authorizationId: string; qrPayload: string; codeDigits: number; expiresAt: string }> {
  if (!env.OFFLINE_CONFIRMATION_ENABLED) throw new ConflictError('Offline confirmation is not enabled on this deployment');
  const auth = await getAuthorizationForClient(id, clientId);
  if (!OPEN_STATES.includes(auth.state) || Date.now() >= auth.expiresAt.getTime()) throw new ConflictError(`Authorization is ${auth.state}`);
  if (!auth.credentialId) throw new ConflictError('Authorization has no bound credential');
  const credential = await getCredentialForClient(auth.credentialId, clientId);
  if (!credential.offlineEnabled) throw new ConflictError('The customer\'s device is not enrolled for offline confirmation');
  return {
    authorizationId: auth.authorizationId,
    qrPayload: offlineQrPayload(canonicalizeAuthorization(authorizationObjectOf(auth))),
    codeDigits: OFFLINE_CODE_DIGITS,
    expiresAt: auth.expiresAt.toISOString(),
  };
}

async function confirmAuthorization(
  hsmAdapter: HsmAdapter,
  id: string,
  clientId: string,
  proof: ConfirmationProof,
  auditContext: AuditContext,
): Promise<VerificationResult> {
  const auth = await getAuthorizationForClient(id, clientId);
  if (auth.state === 'EXPIRED') return { status: 'EXPIRED' };
  if (!OPEN_STATES.includes(auth.state)) return { status: 'FAILED', reason: `Authorization is ${auth.state}` };
  if (Date.now() >= auth.expiresAt.getTime()) {
    await transitionTerminal(id, clientId, 'EXPIRED', auditContext);
    return { status: 'EXPIRED' };
  }

  const identity = await getNexusIdentityForClient(auth.nexusId, clientId);
  if (identity.status !== 'ACTIVE') return { status: 'FAILED', reason: `NEXUS ID is ${identity.status}` };
  if (!auth.credentialId) return { status: 'FAILED', reason: 'Authorization has no bound credential' };
  const credential = await getCredentialForClient(auth.credentialId, clientId);
  if (credential.state !== 'ACTIVE' || credential.nexusId !== auth.nexusId) return { status: 'FAILED', reason: 'Credential is not valid for this authorization' };

  const authorizationObject = authorizationObjectOf(auth);
  if (hashCanonicalAuthorization(authorizationObject) !== auth.canonicalPayloadHash) return { status: 'FAILED', reason: 'Authorization integrity check failed' };
  const canonical = canonicalizeAuthorization(authorizationObject);
  // The key that decides the outcome must be the key whose enrolment is sealed.
  let enrolmentEvidenceHash: string;
  try {
    enrolmentEvidenceHash = await assertCredentialIntegrity(credential);
  } catch (error) {
    if (error instanceof CredentialIntegrityError) return { status: 'FAILED', reason: 'credential_integrity' };
    throw error;
  }

  let details: VerifiedDetails;
  if (proof.kind === 'DEVICE_SIGNATURE') {
    const signature = decodeBase64Strict(proof.signatureB64);
    const valid = signature !== null
      && await hsmAdapter.verifySignature(credential.publicKeyPem, canonical, signature, proof.signatureFormat);
    if (!valid) {
      return recordInvalidAttempt(id, clientId, credential.credentialId, signature ? 'signature_verification_failed' : 'malformed_signature', auditContext);
    }
    details = { signature: proof.signatureB64, signatureFormat: proof.signatureFormat, credentialId: credential.credentialId, hsmAdapter, confirmationMethod: 'DEVICE_SIGNATURE',
      signedBytes: canonical, publicKeyPem: credential.publicKeyPem, enrolmentEvidenceHash };
  } else {
    if (!env.OFFLINE_CONFIRMATION_ENABLED) return { status: 'FAILED', reason: 'Offline confirmation is not enabled on this deployment' };
    const checked = await checkOfflineCode(id, clientId, credential.credentialId, canonical, proof.code, auditContext);
    if ('result' in checked) return checked.result;
    details = { signature: checked.tag.toString('base64'), signatureFormat: 'hmac', credentialId: credential.credentialId, hsmAdapter, confirmationMethod: 'OFFLINE_CODE',
      signedBytes: canonical, publicKeyPem: credential.publicKeyPem, enrolmentEvidenceHash };
  }

  // The plan, the expiry and the state are re-checked under lock in the
  // transaction that consumes the authorization.
  const transition = await transitionTerminal(id, clientId, 'VERIFIED', auditContext, details);
  if (transition.ok) return { status: 'VERIFIED', evidence: transition.evidence as ChainPosition };
  return transition.reason === 'expired' ? { status: 'EXPIRED' } : { status: 'FAILED', reason: transition.reason };
}

/**
 * Compares an offline code under a row lock on the authorization, so parallel
 * guesses are serialized: each wrong code is counted before the next one is
 * compared, and the fifth rejects the authorization. An 8-digit code with five
 * attempts leaves a guessing chance of 5 in 100 million.
 */
async function checkOfflineCode(
  id: string,
  clientId: string,
  credentialId: string,
  canonical: Buffer,
  code: string,
  auditContext: AuditContext,
): Promise<{ tag: Buffer } | { result: VerificationResult }> {
  return withTransaction(async (tx) => {
    const locked = await tx.query<{ state: string; nexus_id: string }>(
      `SELECT state, nexus_id FROM authorization_requests WHERE authorization_id = $1 AND client_id = $2 FOR UPDATE`, [id, clientId]);
    const row = locked.rows[0];
    if (!row) throw new AuthorizationNotFoundError(id);
    if (!OPEN_STATES.includes(row.state)) return { result: { status: 'FAILED', reason: `Authorization is ${row.state}` } };

    const stored = await tx.query<{ offline_secret_encrypted: string | null }>(
      `SELECT offline_secret_encrypted FROM credentials WHERE credential_id = $1`, [credentialId]);
    const encrypted = stored.rows[0]?.offline_secret_encrypted;
    if (!encrypted) return { result: { status: 'FAILED', reason: 'The device is not enrolled for offline confirmation' } };

    const tag = offlineConfirmationTag(decryptSecretBytes(encrypted, 'device', credentialId), canonical);
    const expected = Buffer.from(offlineCodeFromTag(tag), 'utf8');
    const given = Buffer.from(code, 'utf8');
    if (given.length === expected.length && timingSafeEqual(given, expected)) return { tag };

    return { result: await countFailedAttempt(tx, id, credentialId, row.nexus_id, 'offline_code_invalid', auditContext) };
  });
}

async function recordInvalidAttempt(id: string, clientId: string, credentialId: string, reason: string, auditContext: AuditContext): Promise<VerificationResult> {
  return withTransaction(async (tx) => {
    const locked = await tx.query<{ nexus_id: string }>(
      `SELECT nexus_id FROM authorization_requests WHERE authorization_id = $1 AND client_id = $2 FOR UPDATE`, [id, clientId]);
    const row = locked.rows[0];
    if (!row) throw new AuthorizationNotFoundError(id);
    return countFailedAttempt(tx, id, credentialId, row.nexus_id, reason, auditContext);
  });
}

/**
 * Records a failed signature or offline code. The caller holds the row lock
 * on the authorization, so attempts are numbered without gaps or duplicates;
 * the attempt that reaches MAX_SIGNATURE_ATTEMPTS rejects the authorization.
 */
async function countFailedAttempt(tx: PoolClient, id: string, credentialId: string, nexusId: string, reason: string, auditContext: AuditContext): Promise<VerificationResult> {
  const count = await tx.query<{ attempts: number }>(
    `SELECT COALESCE(MAX(attempt_number), 0) + 1 AS attempts FROM authorization_attempts WHERE authorization_id = $1`, [id]);
  const attempt = Number(count.rows[0]?.attempts ?? 1);
  await tx.query(
    `INSERT INTO authorization_attempts (authorization_id, credential_id, attempt_number, result, reason_code, source_ip, user_agent)
     VALUES ($1, $2, $3, 'INVALID_SIGNATURE', $4, $5, $6)`,
    [id, credentialId, attempt, reason, auditContext.ipAddress ?? null, auditContext.userAgent ?? null]);
  const context = { ...auditContext, nexusId };
  await recordAuditEvent('authorization_rejected', context, { authorizationId: id, attempt, reason }, tx);
  if (attempt < MAX_SIGNATURE_ATTEMPTS) return { status: 'FAILED', reason, attempts: attempt };
  const rejected = await tx.query<{ client_id: string; transaction_reference: string }>(
    `UPDATE authorization_requests SET state = 'REJECTED' WHERE authorization_id = $1 AND state = 'PENDING_USER' RETURNING client_id, transaction_reference`, [id]);
  await recordAuditEvent('authorization_rejected', context, { authorizationId: id, reason: 'REJECTED' }, tx);
  if (rejected.rows[0]) {
    await enqueueWebhook(rejected.rows[0].client_id, 'authorization.rejected', {
      authorizationId: id, nexusId, transactionReference: rejected.rows[0].transaction_reference, reason: 'signature_attempt_limit' }, tx);
  }
  return { status: 'FAILED', reason: 'signature_attempt_limit', attempts: attempt };
}

interface VerifiedDetails {
  signature: string;
  signatureFormat: 'der' | 'raw' | 'hmac';
  credentialId: string;
  hsmAdapter: HsmAdapter;
  confirmationMethod: 'DEVICE_SIGNATURE' | 'OFFLINE_CODE';
  /** The exact bytes the signature or code was checked against. */
  signedBytes: Buffer;
  /** The key the signature was checked with, after the integrity check. */
  publicKeyPem: string;
  enrolmentEvidenceHash: string;
}

type Transition = { ok: true; evidence?: ChainPosition } | { ok: false; reason: string };

async function transitionTerminal(id: string, clientId: string, state: 'VERIFIED' | 'EXPIRED' | 'REJECTED', auditContext: AuditContext, verified?: VerifiedDetails): Promise<Transition> {
  return withTransaction(async (tx) => {
    // Lock order: verification plan, then authorization.
    const planGap = state === 'VERIFIED' ? await settlePlanForConfirmation(tx, id, clientId) : null;
    const locked = await tx.query<AuthorizationRow>(
      `SELECT * FROM authorization_requests WHERE authorization_id = $1 AND client_id = $2 FOR UPDATE`, [id, clientId]);
    const auth = locked.rows[0];
    if (!auth || FINAL_STATES.includes(auth.state)) return { ok: false, reason: 'Authorization was finalized concurrently' };
    const context: AuditContext = { ...auditContext, nexusId: auth.nexus_id };

    if (state === 'EXPIRED') {
      await markExpired(tx, auth, auditContext);
      return { ok: true };
    }
    if (state !== 'VERIFIED' || !verified) {
      await tx.query(`UPDATE authorization_requests SET state = $2 WHERE authorization_id = $1`, [id, state]);
      await recordAuditEvent('authorization_rejected', context, { authorizationId: id, reason: state }, tx);
      await enqueueWebhook(clientId, 'authorization.rejected', { authorizationId: id, nexusId: auth.nexus_id, transactionReference: auth.transaction_reference, reason: state }, tx);
      return { ok: true };
    }
    if (planGap) return { ok: false, reason: planGap };
    if (Date.now() >= new Date(auth.expires_at).getTime()) {
      await markExpired(tx, auth, auditContext);
      return { ok: false, reason: 'expired' };
    }
    if (auth.credential_id !== verified.credentialId) return { ok: false, reason: 'Credential is not valid for this authorization' };
    const credential = await tx.query<{ state: string; public_key_pem: string }>(
      `SELECT state, public_key_pem FROM credentials WHERE credential_id = $1 FOR SHARE`, [verified.credentialId]);
    if (credential.rows[0]?.state !== 'ACTIVE') return { ok: false, reason: 'Credential is not valid for this authorization' };
    // The signature was checked against rows read before these locks; the
    // locked rows must still be what was checked.
    if (credential.rows[0].public_key_pem !== verified.publicKeyPem) return { ok: false, reason: 'credential_integrity' };
    const lockedBytes = canonicalizeAuthorization(authorizationObjectOf(mapAuthorization(auth)));
    if (!lockedBytes.equals(verified.signedBytes) || auth.canonical_payload_hash !== hashCanonicalAuthorization(authorizationObjectOf(mapAuthorization(auth)))) {
      return { ok: false, reason: 'Authorization integrity check failed' };
    }

    const updated = await tx.query<AuthorizationRow>(
      `UPDATE authorization_requests
       SET state = 'VERIFIED', signature = $2, signature_format = $3, confirmation_method = $4, verified_at = now(), consumed_at = now()
       WHERE authorization_id = $1 RETURNING *`,
      [id, verified.signature, verified.signatureFormat, verified.confirmationMethod]);
    const row = updated.rows[0];
    await tx.query(`UPDATE credentials SET last_used_at = now() WHERE credential_id = $1`, [verified.credentialId]);
    await tx.query(`UPDATE nexus_identities SET last_used_at = now(), updated_at = now() WHERE nexus_id = $1`, [auth.nexus_id]);
    await tx.query(
      `INSERT INTO authorization_attempts (authorization_id, credential_id, attempt_number, result, source_ip, user_agent)
       VALUES ($1,$2,(SELECT COALESCE(MAX(attempt_number),0)+1 FROM authorization_attempts WHERE authorization_id=$1),'VERIFIED',$3,$4)`,
      [id, verified.credentialId, auditContext.ipAddress ?? null, auditContext.userAgent ?? null]);
    await recordAuditEvent('authorization_consumed', context, { authorizationId: id, transactionReference: auth.transaction_reference }, tx);
    const evidence = await recordEvidence(tx, verified, row, context);
    // The bank keeps the chain head it receives here; a verifier given that
    // head detects records removed from the end of the chain (FI-019).
    await enqueueWebhook(clientId, 'authorization.verified', {
      authorizationId: id,
      nexusId: auth.nexus_id,
      transactionReference: auth.transaction_reference,
      confirmationMethod: verified.confirmationMethod,
      evidence,
      evidenceHead: await getChainHead(tx, auth.nexus_id),
    }, tx);
    return { ok: true, evidence };
  });
}

async function recordEvidence(tx: PoolClient, verified: VerifiedDetails, auth: AuthorizationRow, context: AuditContext): Promise<ChainPosition> {
  const credential = await tx.query<{ key_version: number; attestation_status: string }>(
    `SELECT key_version, attestation_status FROM credentials WHERE credential_id = $1`, [verified.credentialId]);
  const position = await sealAuthorizationEvidence(tx, verified.hsmAdapter, {
    authorizationId: auth.authorization_id,
    nexusId: auth.nexus_id,
    credentialId: verified.credentialId,
    transactionReference: auth.transaction_reference,
    canonicalPayloadHash: auth.canonical_payload_hash,
    signedPayload: verified.signedBytes,
    credentialPublicKeyPem: verified.publicKeyPem,
    enrolmentEvidenceHash: verified.enrolmentEvidenceHash,
    signature: verified.signature,
    signatureFormat: verified.signatureFormat,
    signatureAlgorithm: verified.confirmationMethod === 'OFFLINE_CODE' ? 'HMAC-SHA256' : auth.signature_algorithm,
    confirmationMethod: verified.confirmationMethod,
    keyVersion: credential.rows[0]?.key_version ?? 1,
    policyReference: auth.policy_reference,
    policyVersion: auth.policy_version,
    attestationVerdict: credential.rows[0]?.attestation_status ?? 'UNKNOWN',
    verifiedAt: auth.verified_at ?? new Date(),
    result: 'VERIFIED',
    correlationId: auth.correlation_id,
  });
  await recordAuditEvent('evidence_sealed', context, { authorizationId: auth.authorization_id, chainSequence: position.chainSequence, evidenceHash: position.evidenceHash }, tx);
  return position;
}

function decodeBase64Strict(value: string): Buffer | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) return null;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length ? decoded : null;
}
