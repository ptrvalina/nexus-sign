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
import { parseOfflineLimits } from '../config/productionPosture';
import { env } from '../config/env';
import { OFFLINE_CODE_DIGITS, offlineCodeFromTag, offlineConfirmationTag, offlineQrPayload } from './deviceProtocol';
import { settlePlanForConfirmation } from './adaptiveVerificationService';
import {
  AuthorizationNotFoundError,
  OPEN_STATES,
  PROVISIONAL_STATE,
  authorizationObjectOf,
  getAuthorizationForClient,
  mapAuthorization,
  type AuthorizationRow,
  type ConfirmationMethod,
} from './authorizationRecord';
import { ConflictError, ForbiddenError, UnprocessableError } from './errors';
import { markExpired } from './authorizationExpiry';
import { enqueueWebhook } from './webhookService';
import { getChainHead } from './evidenceService';
import { setOutcomeReason } from './outcomeReason';

const MAX_SIGNATURE_ATTEMPTS = 5;

export type VerificationResult =
  | { status: 'VERIFIED'; evidence: ChainPosition }
  /** Offline confirmation v2: code accepted; VERIFIED only once the device's
   * signature over the same bytes arrives, before signatureDeadline. */
  | { status: 'PROVISIONAL'; signatureDeadline: string }
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
/**
 * Offline codes are symmetric, so their reach is capped per currency
 * by the deployment (OFFLINE_CONFIRMATION_MAX_AMOUNT). Returns why the
 * amount may not be confirmed offline, or null.
 */
export function offlineLimitExceeded(currency: string, amountMinor: string): string | null {
  const configured = env.OFFLINE_CONFIRMATION_MAX_AMOUNT?.trim();
  if (!configured) return null;
  const limit = parseOfflineLimits(configured).get(currency);
  if (limit === undefined) return `Offline confirmation is not offered for ${currency}`;
  if (BigInt(amountMinor) > limit) return `The amount exceeds the offline confirmation limit for ${currency}`;
  return null;
}

/** offline confirmation v2: a code alone does not verify. */
export function deferredSignatureMode(): boolean {
  return env.OFFLINE_CONFIRMATION_MODE === 'deferred_signature';
}

export async function getOfflineChallenge(id: string, clientId: string): Promise<{ authorizationId: string; qrPayload: string; codeDigits: number; expiresAt: string }> {
  if (!env.OFFLINE_CONFIRMATION_ENABLED) throw new ConflictError('Offline confirmation is not enabled on this deployment');
  const auth = await getAuthorizationForClient(id, clientId);
  if (!OPEN_STATES.includes(auth.state) || Date.now() >= auth.expiresAt.getTime()) throw new ConflictError(`Authorization is ${auth.state}`);
  if (!auth.credentialId) throw new ConflictError('Authorization has no bound credential');
  const credential = await getCredentialForClient(auth.credentialId, clientId);
  if (!credential.offlineEnabled) throw new ConflictError('The customer\'s device is not enrolled for offline confirmation');
  const limitReason = offlineLimitExceeded(auth.currency, auth.amountMinor);
  if (limitReason) throw new ConflictError(limitReason, 'OFFLINE_LIMIT_EXCEEDED');
  return {
    authorizationId: auth.authorizationId,
    qrPayload: offlineQrPayload(canonicalizeAuthorization(authorizationObjectOf(auth)), deferredSignatureMode() ? 2 : 1),
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
    const limitReason = offlineLimitExceeded(auth.currency, auth.amountMinor);
    if (limitReason) return { status: 'FAILED', reason: limitReason };
    const checked = await checkOfflineCode(id, clientId, credential.credentialId, canonical, proof.code, auditContext);
    if ('result' in checked) return checked.result;
    details = { signature: checked.tag.toString('base64'), signatureFormat: 'hmac', credentialId: credential.credentialId, hsmAdapter, confirmationMethod: 'OFFLINE_CODE',
      signedBytes: canonical, publicKeyPem: credential.publicKeyPem, enrolmentEvidenceHash, offlineCodeTag: checked.tag.toString('base64') };
    if (deferredSignatureMode()) {
      const accepted = await acceptOfflineCode(id, clientId, auditContext, details);
      if (accepted.ok) return accepted.result;
      return accepted.reason === 'expired' ? { status: 'EXPIRED' } : { status: 'FAILED', reason: accepted.reason };
    }
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

    // A per-credential daily ceiling, checked under the lock so
    // parallel submissions cannot pass it together.
    const ceiling = env.OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY;
    if (ceiling !== undefined) {
      await tx.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [`offline:${credentialId}`]);
      if (await offlineConfirmationsInLastDay(tx, credentialId) >= ceiling) {
        await recordAuditEvent('offline_confirmation_limit_reached', { ...auditContext, nexusId: row.nexus_id, clientId },
          { authorizationId: id, credentialId, limit: ceiling }, tx);
        return { result: { status: 'FAILED', reason: OFFLINE_LIMIT_REASON } };
      }
    }
    const stored = await tx.query<{ offline_secret_encrypted: string | null }>(
      `SELECT offline_secret_encrypted FROM credentials WHERE credential_id = $1`, [credentialId]);
    const encrypted = stored.rows[0]?.offline_secret_encrypted;
    if (!encrypted) return { result: { status: 'FAILED', reason: 'The device is not enrolled for offline confirmation' } };

    // K is needed for this one comparison; the copy is wiped afterwards (the
    // master key that decrypts it stays in memory, KEY_MANAGEMENT.md).
    const offlineKey = decryptSecretBytes(encrypted, 'device', credentialId);
    let tag: Buffer;
    try {
      tag = offlineConfirmationTag(offlineKey, canonical);
    } finally {
      offlineKey.fill(0);
    }
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
  await setOutcomeReason(tx, 'SIGNATURE_ATTEMPTS_EXHAUSTED');
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
  confirmationMethod: ConfirmationMethod;
  /** Offline code: base64 HMAC tag of the accepted code. */
  offlineCodeTag?: string;
  /** OFFLINE_SIGNED: when the code was accepted and the signature received. */
  offlineCodeAcceptedAt?: Date;
  deferredSignatureReceivedAt?: Date;
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
    // Only an open authorization moves on here; OFFLINE_PROVISIONAL is
    // finalized by the deferred signature alone.
    if (!auth || !OPEN_STATES.includes(auth.state)) return { ok: false, reason: 'Authorization was finalized concurrently' };
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
    const gap = await recheckUnderLock(tx, auth, verified, auditContext);
    if (gap) return { ok: false, reason: gap };
    if (verified.confirmationMethod === 'OFFLINE_CODE') {
      const limit = await offlineCeilingReached(tx, auth, verified.credentialId, auditContext);
      if (limit) return { ok: false, reason: limit };
    }
    return { ok: true, evidence: await finalizeVerified(tx, auth, verified, auditContext) };
  });
}

/**
 * The checks every confirmation repeats on the locked rows: not expired, the
 * bound credential still ACTIVE with the key that was checked, the terms
 * still the bytes that were checked. Returns why not, or null.
 */
async function recheckUnderLock(tx: PoolClient, auth: AuthorizationRow, verified: VerifiedDetails, auditContext: AuditContext, { ignoreExpiry = false } = {}): Promise<string | null> {
  if (!ignoreExpiry && Date.now() >= new Date(auth.expires_at).getTime()) {
    await markExpired(tx, auth, auditContext);
    return 'expired';
  }
  if (auth.credential_id !== verified.credentialId) return 'Credential is not valid for this authorization';
  const credential = await tx.query<{ state: string; public_key_pem: string }>(
    `SELECT state, public_key_pem FROM credentials WHERE credential_id = $1 FOR SHARE`, [verified.credentialId]);
  if (credential.rows[0]?.state !== 'ACTIVE') return 'Credential is not valid for this authorization';
  // The signature was checked against rows read before these locks; the
  // locked rows must still be what was checked.
  if (credential.rows[0].public_key_pem !== verified.publicKeyPem) return 'credential_integrity';
  const identity = await tx.query<{ status: string }>(`SELECT status FROM nexus_identities WHERE nexus_id = $1 FOR SHARE`, [auth.nexus_id]);
  if (identity.rows[0]?.status !== 'ACTIVE') return `NEXUS ID is ${identity.rows[0]?.status ?? 'missing'}`;
  const lockedObject = authorizationObjectOf(mapAuthorization(auth));
  const lockedBytes = canonicalizeAuthorization(lockedObject);
  if (!lockedBytes.equals(verified.signedBytes) || auth.canonical_payload_hash !== hashCanonicalAuthorization(lockedObject)) {
    return 'Authorization integrity check failed';
  }
  return null;
}

/**
 * The per-credential daily ceiling on accepted offline codes, checked
 * in the transaction that records the acceptance, under a per-credential lock,
 * so parallel codes for different authorizations cannot pass it together.
 */
async function offlineCeilingReached(tx: PoolClient, auth: AuthorizationRow, credentialId: string, auditContext: AuditContext): Promise<string | null> {
  const ceiling = env.OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY;
  if (ceiling === undefined) return null;
  await tx.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [`offline:${credentialId}`]);
  if (await offlineConfirmationsInLastDay(tx, credentialId) < ceiling) return null;
  await recordAuditEvent('offline_confirmation_limit_reached', { ...auditContext, nexusId: auth.nexus_id, clientId: auth.client_id },
    { authorizationId: auth.authorization_id, credentialId, limit: ceiling }, tx);
  return OFFLINE_LIMIT_REASON;
}

const OFFLINE_LIMIT_REASON = 'The device has reached its offline confirmation limit for 24 hours; confirm online';

/** Accepted offline codes of a credential in the last 24 hours, provisional
 * or not; rows confirmed before migration 022 count by verified_at. */
async function offlineConfirmationsInLastDay(tx: PoolClient, credentialId: string): Promise<number> {
  const used = await tx.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM authorization_requests
     WHERE credential_id = $1
       AND (offline_code_accepted_at > now() - interval '24 hours'
            OR (offline_code_accepted_at IS NULL AND confirmation_method = 'OFFLINE_CODE' AND verified_at > now() - interval '24 hours'))`,
    [credentialId]);
  return used.rows[0].n;
}

/** Consumes a locked authorization (PENDING_USER or OFFLINE_PROVISIONAL) as
 * VERIFIED, seals the evidence and queues the webhook. */
async function finalizeVerified(tx: PoolClient, auth: AuthorizationRow, verified: VerifiedDetails, auditContext: AuditContext): Promise<ChainPosition> {
  const id = auth.authorization_id;
  const context: AuditContext = { ...auditContext, nexusId: auth.nexus_id };
  // A code accepted now (v1, or v2 with the signature already received)
  // records the acceptance; from OFFLINE_PROVISIONAL it was recorded then.
  const recordCode = auth.state === 'PENDING_USER' && verified.offlineCodeTag !== undefined;
  const updated = await tx.query<AuthorizationRow>(
    `UPDATE authorization_requests
     SET state = 'VERIFIED', signature = $2, signature_format = $3, confirmation_method = $4, verified_at = now(), consumed_at = now(),
         offline_code_tag = CASE WHEN $5 THEN $6 ELSE offline_code_tag END,
         offline_code_accepted_at = CASE WHEN $5 THEN now() ELSE offline_code_accepted_at END
     WHERE authorization_id = $1 RETURNING *`,
    [id, verified.signature, verified.signatureFormat, verified.confirmationMethod, recordCode, verified.offlineCodeTag ?? null]);
  const row = updated.rows[0];
  await tx.query(`UPDATE credentials SET last_used_at = now() WHERE credential_id = $1`, [verified.credentialId]);
  await tx.query(`UPDATE nexus_identities SET last_used_at = now(), updated_at = now() WHERE nexus_id = $1`, [auth.nexus_id]);
  await tx.query(
    `INSERT INTO authorization_attempts (authorization_id, credential_id, attempt_number, result, source_ip, user_agent)
     VALUES ($1,$2,(SELECT COALESCE(MAX(attempt_number),0)+1 FROM authorization_attempts WHERE authorization_id=$1),'VERIFIED',$3,$4)`,
    [id, verified.credentialId, auditContext.ipAddress ?? null, auditContext.userAgent ?? null]);
  await recordAuditEvent('authorization_consumed', context, { authorizationId: id, transactionReference: auth.transaction_reference }, tx);
  const evidence = await recordEvidence(tx, { ...verified, offlineCodeAcceptedAt: verified.offlineCodeAcceptedAt ?? row.offline_code_accepted_at ?? undefined }, row, context);
  // The bank keeps the chain head it receives here; a verifier given that
  // head detects records removed from the end of the chain.
  await enqueueWebhook(auth.client_id, 'authorization.verified', {
    authorizationId: id,
    nexusId: auth.nexus_id,
    transactionReference: auth.transaction_reference,
    confirmationMethod: verified.confirmationMethod,
    confirmed: true,
    evidence,
    evidenceHead: await getChainHead(tx, auth.nexus_id),
  }, tx);
  return evidence;
}

// --- Offline confirmation v2: deferred device signature ---

type Acceptance = { ok: true; result: VerificationResult } | { ok: false; reason: string };

/**
 * v2: a correct code. If the device's signature over the same bytes was
 * already uploaded and still verifies, the authorization is VERIFIED
 * (OFFLINE_SIGNED); otherwise it becomes OFFLINE_PROVISIONAL until the
 * signature arrives or the deadline passes. Never VERIFIED on the code alone.
 */
async function acceptOfflineCode(id: string, clientId: string, auditContext: AuditContext, details: VerifiedDetails): Promise<Acceptance> {
  return withTransaction(async (tx) => {
    const planGap = await settlePlanForConfirmation(tx, id, clientId);
    const locked = await tx.query<AuthorizationRow>(
      `SELECT * FROM authorization_requests WHERE authorization_id = $1 AND client_id = $2 FOR UPDATE`, [id, clientId]);
    const auth = locked.rows[0];
    if (!auth || !OPEN_STATES.includes(auth.state)) return { ok: false, reason: 'Authorization was finalized concurrently' };
    if (planGap) return { ok: false, reason: planGap };
    const gap = await recheckUnderLock(tx, auth, details, auditContext);
    if (gap) return { ok: false, reason: gap };
    const limit = await offlineCeilingReached(tx, auth, details.credentialId, auditContext);
    if (limit) return { ok: false, reason: limit };

    const stored = await storedDeferredSignature(tx, id);
    if (stored && stored.credential_id === details.credentialId
        && await verifyDeviceSignature(details.hsmAdapter, details.publicKeyPem, details.signedBytes, stored.signature, stored.signature_format)) {
      const evidence = await finalizeVerified(tx, auth, {
        ...details, confirmationMethod: 'OFFLINE_SIGNED', signature: stored.signature, signatureFormat: stored.signature_format,
        deferredSignatureReceivedAt: stored.received_at,
      }, auditContext);
      return { ok: true, result: { status: 'VERIFIED', evidence } };
    }

    const deadlineHours = env.OFFLINE_SIGNATURE_DEADLINE_HOURS;
    const updated = await tx.query<{ offline_signature_deadline: Date; offline_code_accepted_at: Date }>(
      `UPDATE authorization_requests
       SET state = 'OFFLINE_PROVISIONAL', offline_code_tag = $2, offline_code_accepted_at = now(),
           offline_signature_deadline = now() + make_interval(hours => $3)
       WHERE authorization_id = $1 RETURNING offline_signature_deadline, offline_code_accepted_at`,
      [id, details.offlineCodeTag, deadlineHours]);
    const deadline = updated.rows[0].offline_signature_deadline.toISOString();
    await recordAuditEvent('offline_code_accepted_provisionally', { ...auditContext, nexusId: auth.nexus_id, clientId },
      { authorizationId: id, credentialId: details.credentialId, signatureDeadline: deadline }, tx);
    await enqueueWebhook(clientId, 'authorization.offline_provisional', {
      authorizationId: id,
      nexusId: auth.nexus_id,
      transactionReference: auth.transaction_reference,
      offlineCodeAcceptedAt: updated.rows[0].offline_code_accepted_at.toISOString(),
      signatureDeadline: deadline,
      confirmed: false,
    }, tx);
    return { ok: true, result: { status: 'PROVISIONAL', signatureDeadline: deadline } };
  });
}

interface StoredDeferredSignature { credential_id: string; signature: string; signature_format: 'der' | 'raw'; received_at: Date }

async function storedDeferredSignature(tx: PoolClient, id: string): Promise<StoredDeferredSignature | null> {
  const row = await tx.query<StoredDeferredSignature>(
    `SELECT credential_id, signature, signature_format, received_at FROM offline_deferred_signatures WHERE authorization_id = $1`, [id]);
  return row.rows[0] ?? null;
}

async function verifyDeviceSignature(hsm: HsmAdapter, publicKeyPem: string, bytes: Buffer, signatureB64: string, format: 'der' | 'raw'): Promise<boolean> {
  const signature = decodeBase64Strict(signatureB64);
  return signature !== null && hsm.verifySignature(publicKeyPem, bytes, signature, format);
}

export type DeferredSignatureResult =
  | { status: 'VERIFIED'; evidence: ChainPosition }
  | { status: 'RECEIVED' }
  | { status: 'ALREADY_RECORDED' };

type DeferredOutcome =
  | { kind: 'done'; result: DeferredSignatureResult }
  | { kind: 'conflict'; message: string; code: string }
  | { kind: 'invalid' };

/**
 * The device uploads its signature over the canonical bytes of an
 * authorization it confirmed offline (v2). Requests come from the device
 * itself (device-signed), and only from the credential the authorization
 * names. The signature alone never confirms an authorization: it finalizes
 * an OFFLINE_PROVISIONAL one, or is kept for a PENDING_USER one until the
 * code arrives. Everything is decided in one transaction on the locked row,
 * so parallel uploads and a parallel code serialize.
 */
export async function submitDeferredSignature(
  hsmAdapter: HsmAdapter,
  id: string,
  clientId: string,
  requestCredentialId: string,
  signatureB64: string,
  signatureFormat: 'der' | 'raw',
  auditContext: AuditContext = {},
): Promise<DeferredSignatureResult> {
  const auth = await getAuthorizationForClient(id, clientId);
  if (!auth.credentialId || auth.credentialId !== requestCredentialId) throw new ForbiddenError('The authorization is bound to another device');
  const credential = await getCredentialForClient(auth.credentialId, clientId);
  if (credential.state !== 'ACTIVE' || credential.nexusId !== auth.nexusId) throw new ConflictError('Credential is not valid for this authorization', NOT_AWAITING);
  let enrolmentEvidenceHash: string;
  try {
    enrolmentEvidenceHash = await assertCredentialIntegrity(credential);
  } catch (error) {
    if (error instanceof CredentialIntegrityError) throw new ConflictError('credential_integrity', 'CREDENTIAL_INTEGRITY');
    throw error;
  }
  const object = authorizationObjectOf(auth);
  const intact = hashCanonicalAuthorization(object) === auth.canonicalPayloadHash;
  const canonical = canonicalizeAuthorization(object);
  const valid = intact && await verifyDeviceSignature(hsmAdapter, credential.publicKeyPem, canonical, signatureB64, signatureFormat);

  const outcome = await withTransaction<DeferredOutcome>(async (tx) => {
    const locked = await tx.query<AuthorizationRow>(
      `SELECT * FROM authorization_requests WHERE authorization_id = $1 AND client_id = $2 FOR UPDATE`, [id, clientId]);
    const row = locked.rows[0];
    if (!row) throw new AuthorizationNotFoundError(id);
    const context: AuditContext = { ...auditContext, nexusId: row.nexus_id, clientId };
    const stored = await storedDeferredSignature(tx, id);
    if (stored) {
      if (stored.signature === signatureB64 && stored.signature_format === signatureFormat) return { kind: 'done', result: { status: 'ALREADY_RECORDED' } };
      return { kind: 'conflict', message: 'A different signature is already recorded for this authorization', code: NOT_AWAITING };
    }
    const awaiting = row.state === PROVISIONAL_STATE
      ? Date.now() < new Date(row.offline_signature_deadline as Date).getTime()
      : row.state === 'PENDING_USER' && deferredSignatureMode() && Date.now() < new Date(row.expires_at).getTime();
    if (!awaiting) {
      if (row.state === 'OFFLINE_UNSIGNED' || row.state === PROVISIONAL_STATE) {
        // Kept for investigation: a genuine device signature arriving late
        // shows the code was the customer's.
        await recordAuditEvent('deferred_signature_late', context, { authorizationId: id, credentialId: requestCredentialId, verified: valid }, tx);
      }
      return { kind: 'conflict', message: `Authorization is ${row.state}; no deferred signature is awaited`, code: NOT_AWAITING };
    }
    if (!intact) return { kind: 'conflict', message: 'Authorization integrity check failed', code: 'AUTHORIZATION_INTEGRITY' };
    if (!valid) {
      await recordAuditEvent('deferred_signature_invalid', context, { authorizationId: id, credentialId: requestCredentialId, state: row.state }, tx);
      return { kind: 'invalid' };
    }
    const details: VerifiedDetails = {
      signature: signatureB64, signatureFormat, credentialId: requestCredentialId, hsmAdapter, confirmationMethod: 'OFFLINE_SIGNED',
      signedBytes: canonical, publicKeyPem: credential.publicKeyPem, enrolmentEvidenceHash,
    };
    const gap = await recheckUnderLock(tx, row, details, auditContext, { ignoreExpiry: row.state === PROVISIONAL_STATE });
    if (gap) return { kind: 'conflict', message: gap, code: NOT_AWAITING };
    const inserted = await tx.query<{ received_at: Date }>(
      `INSERT INTO offline_deferred_signatures (authorization_id, credential_id, signature, signature_format) VALUES ($1,$2,$3,$4) RETURNING received_at`,
      [id, requestCredentialId, signatureB64, signatureFormat]);
    await recordAuditEvent('deferred_signature_received', context, { authorizationId: id, credentialId: requestCredentialId, state: row.state }, tx);
    if (row.state === 'PENDING_USER') return { kind: 'done', result: { status: 'RECEIVED' } };
    const evidence = await finalizeVerified(tx, row, {
      ...details, offlineCodeTag: row.offline_code_tag ?? undefined, offlineCodeAcceptedAt: row.offline_code_accepted_at ?? undefined,
      deferredSignatureReceivedAt: inserted.rows[0].received_at,
    }, auditContext);
    return { kind: 'done', result: { status: 'VERIFIED', evidence } };
  });
  if (outcome.kind === 'done') return outcome.result;
  if (outcome.kind === 'invalid') throw new UnprocessableError('The signature does not verify over this authorization with the enrolled key', 'INVALID_DEFERRED_SIGNATURE');
  throw new ConflictError(outcome.message, outcome.code);
}

const NOT_AWAITING = 'NOT_AWAITING_SIGNATURE';

/**
 * Moves OFFLINE_PROVISIONAL authorizations whose device signature can no
 * longer arrive to OFFLINE_UNSIGNED: the deadline passed, or the credential
 * or the identity is no longer ACTIVE (a revoked device cannot sign requests).
 * A security event: audited and reported to the bank.
 */
export async function expireUnsignedOfflineConfirmations(limit = 200): Promise<number> {
  return withTransaction(async (tx) => {
    const due = await tx.query<{ authorization_id: string; client_id: string; nexus_id: string; transaction_reference: string; credential_id: string; reason: string }>(
      `SELECT a.authorization_id, a.client_id, a.nexus_id, a.transaction_reference, a.credential_id,
              CASE WHEN a.offline_signature_deadline <= now() THEN 'deadline'
                   WHEN c.state <> 'ACTIVE' THEN 'credential_not_active'
                   ELSE 'identity_not_active' END AS reason
       FROM authorization_requests a
       JOIN credentials c ON c.credential_id = a.credential_id
       JOIN nexus_identities i ON i.nexus_id = a.nexus_id
       WHERE a.state = 'OFFLINE_PROVISIONAL'
         AND (a.offline_signature_deadline <= now() OR c.state <> 'ACTIVE' OR i.status <> 'ACTIVE')
       ORDER BY a.offline_signature_deadline
       LIMIT $1
       FOR UPDATE OF a SKIP LOCKED`, [limit]);
    for (const row of due.rows) {
      await tx.query(`UPDATE authorization_requests SET state = 'OFFLINE_UNSIGNED', offline_unsigned_reason = $2 WHERE authorization_id = $1 AND state = 'OFFLINE_PROVISIONAL'`,
        [row.authorization_id, row.reason]);
      await recordAuditEvent('offline_signature_missing', { nexusId: row.nexus_id, clientId: row.client_id, actor: 'system:expiry' },
        { authorizationId: row.authorization_id, credentialId: row.credential_id, reason: row.reason }, tx);
      await enqueueWebhook(row.client_id, 'authorization.offline_unsigned', {
        authorizationId: row.authorization_id, nexusId: row.nexus_id, transactionReference: row.transaction_reference, reason: row.reason, confirmed: false,
      }, tx);
    }
    return due.rows.length;
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
    offline: verified.confirmationMethod === 'OFFLINE_SIGNED' ? {
      offlineCodeTag: verified.offlineCodeTag ?? '',
      offlineCodeAcceptedAt: (verified.offlineCodeAcceptedAt ?? new Date()).toISOString(),
      deferredSignatureReceivedAt: (verified.deferredSignatureReceivedAt ?? new Date()).toISOString(),
    } : undefined,
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
