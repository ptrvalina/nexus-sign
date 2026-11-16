import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { recordAuditEvent, type AuditContext } from './auditService';
import { enqueueWebhook } from './webhookService';
import type { AuthorizationRecord } from './authorizationRecord';

/**
 * Expiry of authorizations.
 *
 * An authorization stays PENDING_USER in the database until something moves
 * it on. Two things do: a confirmation attempt after expires_at, and the
 * sweep below. Read paths report EXPIRED as soon as expires_at has passed, so
 * the bank and the device never see a stale PENDING_USER between sweeps.
 */

/** The state to report: PENDING_USER past its expiry is EXPIRED. */
export function reportedState(auth: Pick<AuthorizationRecord, 'state' | 'expiresAt'>, now = Date.now()): string {
  return auth.state === 'PENDING_USER' && now >= auth.expiresAt.getTime() ? 'EXPIRED' : auth.state;
}

/**
 * Moves one locked, overdue PENDING_USER authorization to EXPIRED in the
 * caller's transaction: closes its verification plan and open sessions,
 * records the audit event and queues the `authorization.expired` webhook.
 */
export async function markExpired(
  tx: PoolClient,
  row: { authorization_id: string; client_id: string; nexus_id: string; transaction_reference: string; expires_at: Date },
  context: AuditContext = {},
): Promise<void> {
  await tx.query(`UPDATE authorization_requests SET state = 'EXPIRED' WHERE authorization_id = $1 AND state = 'PENDING_USER'`, [row.authorization_id]);
  await tx.query(
    `UPDATE authorization_verification_plans SET status = 'EXPIRED', updated_at = now()
     WHERE authorization_id = $1 AND status NOT IN ('VERIFIED','FAILED','EXPIRED','CANCELLED')`, [row.authorization_id]);
  await tx.query(`UPDATE verification_sessions SET status = 'EXPIRED' WHERE authorization_id = $1 AND status = 'IN_PROGRESS'`, [row.authorization_id]);
  await recordAuditEvent('authorization_expired', { ...context, nexusId: row.nexus_id, clientId: row.client_id },
    { authorizationId: row.authorization_id, reason: 'EXPIRED' }, tx);
  await enqueueWebhook(row.client_id, 'authorization.expired', {
    authorizationId: row.authorization_id,
    nexusId: row.nexus_id,
    transactionReference: row.transaction_reference,
    expiresAt: new Date(row.expires_at).toISOString(),
  }, tx);
}

/**
 * Expires up to `limit` overdue authorizations. Rows locked by a concurrent
 * confirmation are skipped and picked up by a later sweep (or finalized by
 * that confirmation). Returns how many were expired.
 */
export async function expireOverdueAuthorizations(limit = 200): Promise<number> {
  return withTransaction(async (tx) => {
    const overdue = await tx.query<{ authorization_id: string; client_id: string; nexus_id: string; transaction_reference: string; expires_at: Date }>(
      `SELECT authorization_id, client_id, nexus_id, transaction_reference, expires_at
       FROM authorization_requests
       WHERE state = 'PENDING_USER' AND expires_at <= now()
       ORDER BY expires_at
       LIMIT $1
       FOR UPDATE SKIP LOCKED`, [limit]);
    for (const row of overdue.rows) await markExpired(tx, row, { actor: 'system:expiry' });
    return overdue.rows.length;
  });
}

/**
 * Closes audio/video sessions whose five minutes passed without a result
 * (nobody answered, or the call dropped and was not resumed). The plan goes
 * back to PENDING: an unanswered call verifies nothing and fails nothing; the
 * customer may open another session, up to MAX_SESSIONS_PER_CHANNEL.
 */
export async function expireOverdueVerificationSessions(limit = 200): Promise<number> {
  return withTransaction(async (tx) => {
    const overdue = await tx.query<{ session_id: string; authorization_id: string; nexus_id: string; client_id: string; channel: string }>(
      `SELECT s.session_id, s.authorization_id, s.nexus_id, s.client_id, s.channel
       FROM verification_sessions s
       WHERE s.status = 'IN_PROGRESS' AND s.expires_at <= now()
       ORDER BY s.expires_at LIMIT $1
       FOR UPDATE SKIP LOCKED`, [limit]);
    for (const row of overdue.rows) {
      await tx.query(`UPDATE verification_sessions SET status = 'EXPIRED' WHERE session_id = $1`, [row.session_id]);
      await tx.query(`UPDATE authorization_verification_plans SET status = 'PENDING', updated_at = now() WHERE authorization_id = $1 AND status = 'IN_PROGRESS'`, [row.authorization_id]);
      await recordAuditEvent('verification_session_expired', { nexusId: row.nexus_id, clientId: row.client_id, actor: 'system:expiry' },
        { sessionId: row.session_id, authorizationId: row.authorization_id, channel: row.channel }, tx);
    }
    return overdue.rows.length;
  });
}

/**
 * Deletes device request nonces past their lifetime, at most
 * `limit` per call. A nonce is kept for twice the timestamp skew plus a
 * margin, after which the request's own timestamp is too old to be accepted.
 */
export async function purgeExpiredDeviceNonces(limit = 5000): Promise<number> {
  const result = await pool.query(
    `DELETE FROM device_request_nonces WHERE ctid IN (
       SELECT ctid FROM device_request_nonces WHERE expires_at < now() LIMIT $1)`, [limit]);
  return result.rowCount ?? 0;
}
