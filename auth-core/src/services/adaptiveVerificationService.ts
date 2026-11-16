import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { recordAuditEvent } from './auditService';
import { ConflictError, ForbiddenError, GoneError, NotFoundError, ValidationError } from './errors';
import { enqueueWebhook } from './webhookService';
import { verifyResultToken, VerificationResultError, type ProviderKey } from './verificationResult';

/**
 * Adaptive verification plan of one authorization.
 *
 * - `requiredStep` is the strongest factor that must be completed before the
 *   device signature is accepted. It starts at the bank's policy level and can
 *   only be raised (escalation), never lowered.
 * - `currentStep` is the factor to perform next. Factors run in order
 *   PUSH -> AUDIO -> VIDEO, skipping a factor the bank has not enabled.
 * - PUSH is a delivery channel, not a verification session: it is satisfied by
 *   the device signature itself when nothing stronger is required.
 * - A failed AUDIO check escalates to VIDEO when VIDEO is enabled; a failed
 *   final factor fails the plan permanently and rejects the authorization.
 */
export type VerificationStep = 'PUSH' | 'AUDIO' | 'VIDEO';
export type VerificationStatus = 'PENDING' | 'IN_PROGRESS' | 'VERIFIED' | 'FAILED' | 'EXPIRED' | 'CANCELLED';
export type EscalationReason = 'PUSH_NOT_DELIVERED' | 'PUSH_TIMEOUT' | 'HIGH_AMOUNT' | 'RISK_POLICY' | 'CLIENT_REQUEST' | 'CHANNEL_FAILURE';

export interface VerificationPlan {
  authorizationId: string;
  policyVersion: string;
  requiredStep: VerificationStep;
  currentStep: VerificationStep;
  allowedSteps: VerificationStep[];
  audioEnabled: boolean;
  videoEnabled: boolean;
  pushTimeoutSeconds: number;
  highAmountThresholdMinor: string | null;
  clientEscalationAllowed: boolean;
  status: VerificationStatus;
  lastEscalationReason: EscalationReason | null;
}

export interface VerificationPolicyInput {
  pushTimeoutSeconds?: number;
  highAmountThresholdMinor?: string;
  requireAudio?: boolean;
  requireVideo?: boolean;
  /** Whether the bank operates the channel at all; defaults to true. A
   * required channel is always enabled. */
  audioAvailable?: boolean;
  videoAvailable?: boolean;
  clientEscalationAllowed?: boolean;
}

export interface CreatePlanInput extends VerificationPolicyInput {
  authorizationId: string;
  nexusId: string;
  clientId: string;
  policyVersion: string;
  amountMinor: string;
}

const STEPS: VerificationStep[] = ['PUSH', 'AUDIO', 'VIDEO'];
const TERMINAL: VerificationStatus[] = ['FAILED', 'EXPIRED', 'CANCELLED'];
const SESSION_TTL_MS = 5 * 60_000;
/** Sessions (open, cancelled, expired or closed) per channel and authorization. */
export const MAX_SESSIONS_PER_CHANNEL = 3;

type Runner = Pick<PoolClient, 'query'>;

export async function createVerificationPlan(input: CreatePlanInput, runner: Runner = pool): Promise<VerificationPlan> {
  const pushTimeoutSeconds = Math.min(Math.max(input.pushTimeoutSeconds ?? 30, 10), 300);
  const threshold = input.highAmountThresholdMinor ?? null;
  if (threshold !== null && !/^\d{1,30}$/.test(threshold)) throw new ValidationError('highAmountThresholdMinor must be a decimal integer');

  const highAmount = threshold !== null && BigInt(input.amountMinor) >= BigInt(threshold);
  const requiredStep: VerificationStep = input.requireVideo ? 'VIDEO' : input.requireAudio || highAmount ? 'AUDIO' : 'PUSH';
  // A channel is offered only if the bank can verify it: a registered provider
  // key or operator verification for that channel. The request can
  // switch an available channel off, never on.
  const verifiable = await verifiableChannels(runner, input.clientId);
  const audioEnabled = verifiable.has('AUDIO') && input.audioAvailable !== false;
  const videoEnabled = verifiable.has('VIDEO') && input.videoAvailable !== false;
  const allowedSteps = STEPS.filter((s) => s === 'PUSH' || (s === 'AUDIO' && audioEnabled) || (s === 'VIDEO' && videoEnabled));
  if (!allowedSteps.some((s) => rank(s) >= rank(requiredStep))) {
    throw new ConflictError(`${requiredStep} verification is required but this bank has no verifier for it (register a verification provider or enable operator verification)`, 'VERIFICATION_CHANNEL_UNAVAILABLE');
  }
  const currentStep = requiredStep === 'PUSH' ? 'PUSH' : firstAbove('PUSH', allowedSteps) ?? requiredStep;

  const inserted = await runner.query<VerificationPlanRow>(
    `INSERT INTO authorization_verification_plans
      (authorization_id, nexus_id, client_id, policy_version, required_step, current_step, allowed_steps,
       audio_enabled, video_enabled, push_timeout_seconds, high_amount_threshold_minor, client_escalation_allowed,
       status, last_escalation_reason)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'PENDING',$13)
     ON CONFLICT (authorization_id) DO NOTHING
     RETURNING *`,
    [input.authorizationId, input.nexusId, input.clientId, input.policyVersion, requiredStep, currentStep, allowedSteps,
      audioEnabled, videoEnabled, pushTimeoutSeconds, threshold, input.clientEscalationAllowed !== false,
      highAmount ? 'HIGH_AMOUNT' : null],
  );
  if (inserted.rows[0]) return mapPlan(inserted.rows[0]);
  // The plan already exists (idempotent replay of POST /v1/authorizations).
  // It is immutable: a replay with a weaker policy must not downgrade it.
  const existing = await runner.query<VerificationPlanRow>(
    `SELECT * FROM authorization_verification_plans WHERE authorization_id=$1 AND client_id=$2`, [input.authorizationId, input.clientId]);
  if (!existing.rows[0]) throw new NotFoundError('Verification plan not found');
  return mapPlan(existing.rows[0]);
}

export async function getVerificationPlan(authorizationId: string, clientId: string): Promise<VerificationPlan> {
  const result = await pool.query<VerificationPlanRow>(
    `SELECT * FROM authorization_verification_plans WHERE authorization_id=$1 AND client_id=$2`, [authorizationId, clientId]);
  if (!result.rows[0]) throw new NotFoundError('Verification plan not found');
  return mapPlan(result.rows[0]);
}

/** Raises the required factor. Without `requestedStep` the next enabled
 * factor above the current requirement is used. */
export async function escalateVerification(authorizationId: string, clientId: string, reason: EscalationReason, requestedStep?: VerificationStep): Promise<VerificationPlan> {
  return withTransaction(async (tx) => {
    const plan = await lockPlan(tx, authorizationId, clientId);
    await assertAuthorizationPending(tx, authorizationId);
    if (TERMINAL.includes(plan.status)) throw new ConflictError(`Verification is ${plan.status}`);
    if (reason === 'CLIENT_REQUEST' && !plan.client_escalation_allowed) throw new ForbiddenError('Client escalation is not permitted by policy');

    const target = requestedStep ?? firstAbove(plan.required_step, plan.allowed_steps);
    if (!target) throw new ConflictError('No stronger verification step is enabled for this authorization');
    if (!plan.allowed_steps.includes(target)) throw new ConflictError(`${target} verification is not enabled for this authorization`);
    if (rank(target) <= rank(plan.required_step)) throw new ConflictError(`Verification already requires ${plan.required_step}; downgrade or repetition is not possible`);

    const verified = await highestVerified(tx, authorizationId);
    const current = firstAbove(maxStep(verified, 'PUSH'), plan.allowed_steps) ?? target;
    const updated = await tx.query<VerificationPlanRow>(
      `UPDATE authorization_verification_plans
       SET required_step=$2, current_step=$3, status='PENDING', last_escalation_reason=$4, updated_at=now()
       WHERE authorization_id=$1 RETURNING *`,
      [authorizationId, target, current, reason]);
    await recordAuditEvent('verification_escalated', { nexusId: plan.nexus_id },
      { authorizationId, from: plan.required_step, to: target, reason, policyVersion: plan.policy_version }, tx);
    return mapPlan(updated.rows[0]);
  });
}

export async function openVerificationSession(authorizationId: string, clientId: string, channel: VerificationStep): Promise<{ sessionId: string; nonce: string; expiresAt: Date; channel: VerificationStep }> {
  if (channel === 'PUSH') throw new ValidationError('PUSH has no verification session; it is completed by the device signature');
  return withTransaction(async (tx) => {
    const plan = await lockPlan(tx, authorizationId, clientId);
    await assertAuthorizationPending(tx, authorizationId);
    if (TERMINAL.includes(plan.status)) throw new ConflictError(`Verification is ${plan.status}`);
    if (plan.status === 'VERIFIED') throw new ConflictError('Verification is already complete');
    if (rank(plan.required_step) < rank(channel)) throw new ConflictError(`${channel} is not required; escalate first`);
    if (channel !== plan.current_step) throw new ConflictError(`The next verification step is ${plan.current_step}`);

    // A customer who declines or misses calls can retry, a limited number of
    // times per channel; then the bank escalates or cancels.
    const attempts = await tx.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM verification_sessions WHERE authorization_id=$1 AND channel=$2`, [authorizationId, channel]);
    if ((attempts.rows[0]?.n ?? 0) >= MAX_SESSIONS_PER_CHANNEL) {
      throw new ConflictError(`${channel} verification was attempted ${MAX_SESSIONS_PER_CHANNEL} times for this authorization`, 'VERIFICATION_ATTEMPTS_EXHAUSTED');
    }
    // Only one session per authorization can be open; a new one supersedes it.
    await tx.query(`UPDATE verification_sessions SET status='CANCELLED' WHERE authorization_id=$1 AND status='IN_PROGRESS'`, [authorizationId]);
    const sessionId = randomUUID();
    const nonce = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    await tx.query(
      `INSERT INTO verification_sessions (session_id, authorization_id, nexus_id, client_id, channel, nonce_hash, expires_at, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'IN_PROGRESS')`,
      [sessionId, authorizationId, plan.nexus_id, clientId, channel, sha256(nonce), expiresAt]);
    await tx.query(`UPDATE authorization_verification_plans SET status='IN_PROGRESS', updated_at=now() WHERE authorization_id=$1`, [authorizationId]);
    await recordAuditEvent('verification_session_opened', { nexusId: plan.nexus_id },
      { authorizationId, sessionId, channel, policyVersion: plan.policy_version }, tx);
    return { sessionId, nonce, expiresAt, channel };
  });
}

/**
 * Closes an audio or video session with a result token signed by a
 * verification provider registered for the bank. The bank gateway
 * only relays the token; Auth Core checks the signature, the binding to this
 * session, transaction and device, and freshness itself
 * (verificationResult.ts). An invalid token changes nothing.
 */
export async function completeVerificationSession(authorizationId: string, clientId: string, sessionId: string, resultToken: string): Promise<VerificationPlan> {
  return closeSession(authorizationId, clientId, sessionId, async (tx, session, auth) => {
    let verified;
    try {
      verified = await verifyResultToken(resultToken, {
        clientId,
        sessionId,
        authorizationId,
        canonicalPayloadHash: auth.canonical_payload_hash,
        credentialId: auth.credential_id ?? '',
        channel: session.channel as 'AUDIO' | 'VIDEO',
        sessionNonceSha256: session.nonce_hash,
        nowSeconds: Math.floor(Date.now() / 1000),
      }, (providerId, keyId) => providerKey(tx, clientId, providerId, keyId));
    } catch (error) {
      if (error instanceof VerificationResultError) {
        await recordAuditEvent('verification_result_rejected', { nexusId: session.nexus_id, clientId },
          { authorizationId, sessionId, channel: session.channel, reason: error.reason }, tx);
        return { rejected: error.reason };
      }
      throw error;
    }
    // One result per provider token: a token accepted for another session is
    // refused (the unique index is the backstop).
    const reused = await tx.query(
      `SELECT 1 FROM verification_sessions WHERE client_id = $1 AND result_issuer = $2 AND result_jti = $3`,
      [clientId, `${verified.providerId}/${verified.keyId}`, verified.jti]);
    if (reused.rows[0]) {
      await recordAuditEvent('verification_result_rejected', { nexusId: session.nexus_id, clientId },
        { authorizationId, sessionId, channel: session.channel, reason: 'jti already used' }, tx);
      return { rejected: 'jti already used' };
    }
    return {
      result: verified.result,
      method: 'PROVIDER',
      issuer: `${verified.providerId}/${verified.keyId}`,
      reference: verified.jti,
      jti: verified.jti,
      assertionHash: sha256(resultToken),
    };
  });
}

export interface OperatorIdentity {
  username: string;
  /** null for an operator of all banks. */
  clientId: string | null;
}

/**
 * Closes an audio or video session with the decision of a bank operator who
 * held the in-app call in the admin console (logged in with password and
 * TOTP). Allowed only for channels the bank enabled for operator
 * verification, and only for operators of that bank.
 */
export async function recordOperatorDecision(sessionId: string, operator: OperatorIdentity, result: 'VERIFIED' | 'FAILED'): Promise<VerificationPlan> {
  const located = await pool.query<{ authorization_id: string; client_id: string }>(
    `SELECT authorization_id, client_id FROM verification_sessions WHERE session_id = $1`, [sessionId]);
  const row = located.rows[0];
  if (!row || (operator.clientId !== null && operator.clientId !== row.client_id)) throw new NotFoundError('Verification session not found');
  return closeSession(row.authorization_id, row.client_id, sessionId, async (tx, session) => {
    const channels = await tx.query<{ operator_verification_channels: string[] }>(
      `SELECT operator_verification_channels FROM bank_clients WHERE client_id = $1`, [row.client_id]);
    if (!channels.rows[0]?.operator_verification_channels.includes(session.channel)) {
      throw new ForbiddenError(`Operator verification is not enabled for ${session.channel} at this bank`);
    }
    return { result, method: 'OPERATOR', issuer: operator.username, reference: `operator:${operator.username}`, jti: null, assertionHash: null };
  });
}

interface SessionResult {
  result: 'VERIFIED' | 'FAILED';
  method: 'PROVIDER' | 'OPERATOR';
  issuer: string;
  reference: string;
  jti: string | null;
  assertionHash: string | null;
}

type Decide = (tx: PoolClient, session: VerificationSessionRow, auth: { canonical_payload_hash: string; credential_id: string | null }) =>
  Promise<SessionResult | { rejected: string }>;

/** Locks plan and session (the lock order of openVerificationSession), checks
 * the session can still be closed, asks `decide` for the result and applies
 * it to the plan. A refused result is committed (its audit event) and then
 * raised as 403 without touching the session. */
async function closeSession(authorizationId: string, clientId: string, sessionId: string, decide: Decide): Promise<VerificationPlan> {
  const outcome = await withTransaction(async (tx): Promise<VerificationPlan | 'EXPIRED' | { rejected: string }> => {
    const plan = await lockPlan(tx, authorizationId, clientId);
    const sessions = await tx.query<VerificationSessionRow>(
      `SELECT * FROM verification_sessions WHERE session_id=$1 AND authorization_id=$2 AND client_id=$3 FOR UPDATE`,
      [sessionId, authorizationId, clientId]);
    const session = sessions.rows[0];
    if (!session) throw new NotFoundError('Verification session not found');
    if (session.status !== 'IN_PROGRESS') throw new ConflictError(`Verification session is ${session.status}`);
    if (Date.now() >= new Date(session.expires_at).getTime()) {
      // Committed before the error is raised, so the session stays EXPIRED.
      await tx.query(`UPDATE verification_sessions SET status='EXPIRED' WHERE session_id=$1`, [sessionId]);
      await tx.query(`UPDATE authorization_verification_plans SET status='PENDING', updated_at=now() WHERE authorization_id=$1 AND status='IN_PROGRESS'`, [authorizationId]);
      return 'EXPIRED';
    }
    const auth = await tx.query<{ state: string; expires_at: Date; canonical_payload_hash: string; credential_id: string | null }>(
      `SELECT state, expires_at, canonical_payload_hash, credential_id FROM authorization_requests WHERE authorization_id=$1`, [authorizationId]);
    const authorization = auth.rows[0];
    if (!authorization || authorization.state !== 'PENDING_USER') throw new ConflictError(`Authorization is ${authorization?.state ?? 'missing'}`);
    if (Date.now() >= new Date(authorization.expires_at).getTime()) throw new GoneError('Authorization expired');

    const decided = await decide(tx, session, authorization);
    if ('rejected' in decided) return decided;
    return applySessionResult(tx, plan, session, clientId, decided);
  });
  if (outcome === 'EXPIRED') throw new GoneError('Verification session expired');
  if ('rejected' in outcome) throw new ForbiddenError(`Verification result rejected: ${outcome.rejected}`);
  return outcome;
}

async function applySessionResult(tx: PoolClient, plan: VerificationPlanRow, session: VerificationSessionRow, clientId: string, r: SessionResult): Promise<VerificationPlan> {
  const authorizationId = plan.authorization_id;
  const sessionId = session.session_id;
  await tx.query(
    `UPDATE verification_sessions
     SET status=$1, provider_reference=$2, assertion_hash=$3, result_method=$4, result_issuer=$5, result_jti=$6, completed_at=now()
     WHERE session_id=$7`,
    [r.result, r.reference, r.assertionHash, r.method, r.issuer, r.jti, sessionId]);
  const factor = { authorizationId, sessionId, channel: session.channel, method: r.method, issuer: r.issuer, providerReference: r.reference };

  if (r.result === 'FAILED') {
    const fallback = firstAbove(session.channel, plan.allowed_steps);
    if (fallback) {
      const escalated = await tx.query<VerificationPlanRow>(
        `UPDATE authorization_verification_plans
         SET required_step=$2, current_step=$3, status='PENDING', last_escalation_reason='CHANNEL_FAILURE', updated_at=now()
         WHERE authorization_id=$1 RETURNING *`,
        [authorizationId, maxStep(plan.required_step, fallback), fallback]);
      await recordAuditEvent('verification_failed_escalated', { nexusId: plan.nexus_id }, { ...factor, nextStep: fallback }, tx);
      return mapPlan(escalated.rows[0]);
    }
    const failed = await tx.query<VerificationPlanRow>(
      `UPDATE authorization_verification_plans SET status='FAILED', updated_at=now() WHERE authorization_id=$1 RETURNING *`, [authorizationId]);
    const rejected = await tx.query<{ transaction_reference: string }>(
      `UPDATE authorization_requests SET state='REJECTED' WHERE authorization_id=$1 AND state='PENDING_USER' RETURNING transaction_reference`, [authorizationId]);
    if (rejected.rows[0]) {
      await enqueueWebhook(clientId, 'authorization.rejected', {
        authorizationId, nexusId: plan.nexus_id, transactionReference: rejected.rows[0].transaction_reference, reason: 'verification_failed' }, tx);
    }
    await recordAuditEvent('verification_failed', { nexusId: plan.nexus_id }, { ...factor, authorizationState: 'REJECTED' }, tx);
    return mapPlan(failed.rows[0]);
  }

  const satisfied = rank(session.channel) >= rank(plan.required_step);
  const next = satisfied ? session.channel : firstAbove(session.channel, plan.allowed_steps) ?? plan.required_step;
  const updated = await tx.query<VerificationPlanRow>(
    `UPDATE authorization_verification_plans SET status=$2, current_step=$3, updated_at=now() WHERE authorization_id=$1 RETURNING *`,
    [authorizationId, satisfied ? 'VERIFIED' : 'PENDING', next]);
  await recordAuditEvent('verification_completed', { nexusId: plan.nexus_id },
    { ...factor, result: r.result, planStatus: updated.rows[0].status }, tx);
  return mapPlan(updated.rows[0]);
}

/** Channels the bank can verify: registered provider keys and operator verification. */
async function verifiableChannels(runner: Runner, clientId: string): Promise<Set<string>> {
  const result = await runner.query<{ channel: string }>(
    `SELECT unnest(operator_verification_channels) AS channel FROM bank_clients WHERE client_id = $1
     UNION
     SELECT unnest(channels) FROM verification_providers WHERE client_id = $1 AND status = 'ACTIVE'`, [clientId]);
  return new Set(result.rows.map((r) => r.channel));
}

async function providerKey(tx: Runner, clientId: string, providerId: string, keyId: string): Promise<ProviderKey | null> {
  const result = await tx.query<{ provider_id: string; key_id: string; channels: string[]; public_key_pem: string }>(
    `SELECT provider_id, key_id, channels, public_key_pem FROM verification_providers
     WHERE client_id = $1 AND provider_id = $2 AND key_id = $3 AND status = 'ACTIVE'`, [clientId, providerId, keyId]);
  const row = result.rows[0];
  return row ? { providerId: row.provider_id, keyId: row.key_id, channels: row.channels, publicKeyPem: row.public_key_pem } : null;
}

/**
 * Settles the plan inside the transaction that consumes the authorization,
 * after the device signature or offline code has verified. The plan row is
 * locked first (the same order as escalation and session completion), so an
 * escalation that commits concurrently is either seen here or refused there.
 * For a PUSH-level plan the confirmation itself is the verification.
 * Returns null when the plan is satisfied, otherwise the reason it is not.
 */
export async function settlePlanForConfirmation(tx: PoolClient, authorizationId: string, clientId: string): Promise<string | null> {
  const plan = await lockPlan(tx, authorizationId, clientId);
  if (plan.required_step === 'PUSH' && plan.status === 'PENDING') {
    await tx.query(`UPDATE authorization_verification_plans SET status='VERIFIED', updated_at=now() WHERE authorization_id=$1`, [authorizationId]);
    await recordAuditEvent('push_verification_completed', { nexusId: plan.nexus_id }, { authorizationId, policyVersion: plan.policy_version }, tx);
    return null;
  }
  return plan.status === 'VERIFIED' ? null : `Required verification (${plan.required_step}) has not been completed`;
}

async function lockPlan(tx: Runner, authorizationId: string, clientId: string): Promise<VerificationPlanRow> {
  const result = await tx.query<VerificationPlanRow>(
    `SELECT * FROM authorization_verification_plans WHERE authorization_id=$1 AND client_id=$2 FOR UPDATE`, [authorizationId, clientId]);
  if (!result.rows[0]) throw new NotFoundError('Verification plan not found');
  return result.rows[0];
}

async function assertAuthorizationPending(tx: Runner, authorizationId: string): Promise<void> {
  const result = await tx.query<{ state: string; expires_at: Date }>(
    `SELECT state, expires_at FROM authorization_requests WHERE authorization_id=$1`, [authorizationId]);
  const auth = result.rows[0];
  if (!auth) throw new NotFoundError('Authorization not found');
  if (auth.state !== 'PENDING_USER') throw new ConflictError(`Authorization is ${auth.state}`);
  if (Date.now() >= new Date(auth.expires_at).getTime()) throw new GoneError('Authorization expired');
}

async function highestVerified(tx: Runner, authorizationId: string): Promise<VerificationStep | null> {
  const result = await tx.query<{ channel: VerificationStep }>(
    `SELECT channel FROM verification_sessions WHERE authorization_id=$1 AND status='VERIFIED'`, [authorizationId]);
  return result.rows.reduce<VerificationStep | null>((best, row) => (best && rank(best) >= rank(row.channel) ? best : row.channel), null);
}

function rank(step: VerificationStep): number { return STEPS.indexOf(step) + 1; }
function maxStep(a: VerificationStep | null, b: VerificationStep): VerificationStep { return a && rank(a) > rank(b) ? a : b; }
function firstAbove(step: VerificationStep, allowed: VerificationStep[]): VerificationStep | null {
  return STEPS.find((s) => rank(s) > rank(step) && allowed.includes(s)) ?? null;
}
function sha256(value: string): string { return createHash('sha256').update(value, 'utf8').digest('hex'); }

function mapPlan(row: VerificationPlanRow): VerificationPlan {
  return {
    authorizationId: row.authorization_id,
    policyVersion: row.policy_version,
    requiredStep: row.required_step,
    currentStep: row.current_step,
    allowedSteps: row.allowed_steps,
    audioEnabled: row.audio_enabled,
    videoEnabled: row.video_enabled,
    pushTimeoutSeconds: row.push_timeout_seconds,
    highAmountThresholdMinor: row.high_amount_threshold_minor,
    clientEscalationAllowed: row.client_escalation_allowed,
    status: row.status,
    lastEscalationReason: row.last_escalation_reason ?? null,
  };
}

type VerificationPlanRow = {
  authorization_id: string; nexus_id: string; client_id: string; policy_version: string;
  required_step: VerificationStep; current_step: VerificationStep; allowed_steps: VerificationStep[];
  audio_enabled: boolean; video_enabled: boolean; push_timeout_seconds: number; high_amount_threshold_minor: string | null;
  client_escalation_allowed: boolean; status: VerificationStatus; last_escalation_reason?: EscalationReason | null;
};
type VerificationSessionRow = {
  session_id: string; authorization_id: string; nexus_id: string; client_id: string; channel: VerificationStep;
  nonce_hash: string; expires_at: Date; status: string;
};
