import type { PoolClient } from 'pg';
import { withTransaction } from '../db/pool';
import { recordAuditEvent, type AuditContext } from './auditService';
import { enqueueWebhook } from './webhookService';
import { ConflictError, NotFoundError } from './errors';

/**
 * Ending an authorization before anyone confirmed it (audit finding A1-03).
 *
 * - The customer declines on the enrolled device ("it wasn't me", wrong
 *   details): state REJECTED, webhook `authorization.declined` with the
 *   reason. `NOT_ME` is the strongest fraud signal the product gives the bank.
 * - The bank withdraws it (order changed, its fraud system fired): state
 *   CANCELLED, webhook `authorization.cancelled`.
 *
 * Both only from PENDING_USER, under the authorization's row lock, so a
 * confirmation and a decline cannot both succeed; a signature arriving later
 * fails because the authorization is no longer open. Open verification plans
 * and call sessions end with it.
 */

export type DeclineReason = 'NOT_ME' | 'WRONG_DETAILS' | 'OTHER';
export type BankCancelReason = 'ORDER_CHANGED' | 'FRAUD_SUSPECTED' | 'CUSTOMER_REQUEST' | 'OTHER';

interface OpenRow { authorization_id: string; client_id: string; nexus_id: string; credential_id: string; transaction_reference: string; state: string }

async function lockOpen(tx: PoolClient, authorizationId: string, clientId: string): Promise<OpenRow> {
  const locked = await tx.query<OpenRow>(
    `SELECT authorization_id, client_id, nexus_id, credential_id, transaction_reference, state
       FROM authorization_requests WHERE authorization_id = $1 AND client_id = $2 FOR UPDATE`, [authorizationId, clientId]);
  const row = locked.rows[0];
  if (!row) throw new NotFoundError(`Authorization ${authorizationId} was not found`);
  if (row.state !== 'PENDING_USER') throw new ConflictError(`Authorization is ${row.state}`, 'AUTHORIZATION_NOT_PENDING');
  return row;
}

async function close(tx: PoolClient, row: OpenRow, state: 'REJECTED' | 'CANCELLED'): Promise<void> {
  await tx.query(`UPDATE authorization_requests SET state = $2 WHERE authorization_id = $1 AND state = 'PENDING_USER'`, [row.authorization_id, state]);
  await tx.query(
    `UPDATE authorization_verification_plans SET status = 'CANCELLED', updated_at = now()
      WHERE authorization_id = $1 AND status NOT IN ('VERIFIED','FAILED','EXPIRED','CANCELLED')`, [row.authorization_id]);
  await tx.query(`UPDATE verification_sessions SET status = 'CANCELLED' WHERE authorization_id = $1 AND status = 'IN_PROGRESS'`, [row.authorization_id]);
}

/** The customer declines on the enrolled device the authorization is bound to. */
export async function declineAuthorization(authorizationId: string, clientId: string, credentialId: string, reason: DeclineReason, context: AuditContext = {}): Promise<{ authorizationId: string; state: 'REJECTED'; reason: DeclineReason }> {
  return withTransaction(async (tx) => {
    const row = await lockOpen(tx, authorizationId, clientId);
    if (row.credential_id !== credentialId) throw new ConflictError('The authorization is bound to another device', 'CREDENTIAL_MISMATCH');
    await close(tx, row, 'REJECTED');
    await recordAuditEvent('authorization_declined', { ...context, nexusId: row.nexus_id, clientId, actor: `credential:${credentialId}` },
      { authorizationId, reason }, tx);
    await enqueueWebhook(clientId, 'authorization.declined', {
      authorizationId, nexusId: row.nexus_id, transactionReference: row.transaction_reference, credentialId, reason,
    }, tx);
    return { authorizationId, state: 'REJECTED' as const, reason };
  });
}

/** The bank withdraws an authorization the customer has not confirmed. */
export async function cancelAuthorizationByBank(authorizationId: string, clientId: string, reason: BankCancelReason, context: AuditContext = {}): Promise<{ authorizationId: string; state: 'CANCELLED'; reason: BankCancelReason }> {
  return withTransaction(async (tx) => {
    const row = await lockOpen(tx, authorizationId, clientId);
    await close(tx, row, 'CANCELLED');
    await recordAuditEvent('authorization_cancelled', { ...context, nexusId: row.nexus_id, clientId, actor: context.actor ?? `bank:${clientId}` },
      { authorizationId, reason }, tx);
    await enqueueWebhook(clientId, 'authorization.cancelled', {
      authorizationId, nexusId: row.nexus_id, transactionReference: row.transaction_reference, reason,
    }, tx);
    return { authorizationId, state: 'CANCELLED' as const, reason };
  });
}
