import type { PoolClient } from 'pg';
import type { DeferredAudits } from './credentialIntegrity';
import { pool, withTransaction } from '../db/pool';
import { recordAuditEvent } from './auditService';
import { enqueueWebhook } from './webhookService';
import { AuthorizationNotFoundError, type AuthorizationRow } from './authorizationRecord';
import { authorizationEvidenceProblem } from './authorizationEvidenceCheck';
import { ConflictError } from './errors';
import { env } from '../config/env';

/**
 * Bank transaction lifecycle of a VERIFIED authorization:
 *
 *   PENDING -> COMMIT_REQUESTED -> COMMITTED | FAILED | CANCELLED
 *
 * (also enforced by the database, migration 017). A commit is requested only
 * while the identity and the confirming credential are ACTIVE and within
 * BANK_COMMIT_MAX_AGE_SECONDS of the confirmation.
 *
 * The bank remains the system of record; Auth Core records what the bank
 * reports and notifies the bank's webhook on every real state change. Replays
 * of an already-applied transition return the current state without a new
 * event. The notification is written in the same transaction as the state
 * change (transactional outbox), so neither can exist without the other.
 */
export type BankTransactionState = 'PENDING' | 'COMMIT_REQUESTED' | 'COMMITTED' | 'FAILED' | 'CANCELLED';

export interface BankTransactionView {
  authorizationId: string;
  authorizationState: string;
  bankTransactionState: BankTransactionState;
  bankTransactionReference: string | null;
  bankCommitAt: string | null;
  bankCommitError: string | null;
}

interface Row {
  authorization_id: string; nexus_id: string; credential_id: string | null; verified_at: Date | null; state: string; bank_transaction_state: BankTransactionState;
  bank_transaction_reference: string | null; bank_commit_at: Date | null; bank_commit_error: string | null;
}

/** Records the bank's commit request; idempotent for the same bankTransactionReference. */
export async function requestCommit(authorizationId: string, clientId: string, bankTransactionReference: string): Promise<BankTransactionView> {
  // Security events of a refusal are written after the transaction has ended
  // and released the row lock and its connection: written while holding the
  // lock, through another pool connection, parallel requests waiting on the
  // lock could hold the whole pool (phase 11).
  const deferred: DeferredAudits = [];
  try {
    return await commitInTransaction(authorizationId, clientId, bankTransactionReference, deferred);
  } finally {
    for (const audit of deferred) await audit();
  }
}

function commitInTransaction(authorizationId: string, clientId: string, bankTransactionReference: string, deferred: DeferredAudits): Promise<BankTransactionView> {
  return withTransaction(async (tx) => {
    const auth = await lock(tx, authorizationId, clientId);
    if (auth.state !== 'VERIFIED') throw new ConflictError(`Authorization is ${auth.state}; only a VERIFIED authorization can be committed`);
    if (auth.bank_transaction_state === 'COMMIT_REQUESTED' || auth.bank_transaction_state === 'COMMITTED') {
      if (auth.bank_transaction_reference !== bankTransactionReference) {
        throw new ConflictError('A commit was already requested with a different bankTransactionReference');
      }
      return view(auth);
    }
    if (auth.bank_transaction_state !== 'PENDING') throw new ConflictError(`Bank transaction is ${auth.bank_transaction_state}`);
    // An approval stops being usable when the customer or device it came
    // from is no longer in good standing, and after BANK_COMMIT_MAX_AGE_SECONDS
    // (NXS-030). The bank asks the customer again in both cases.
    const standing = await tx.query<{ identity: string; credential: string | null }>(
      `SELECT i.status AS identity, c.state AS credential
         FROM nexus_identities i LEFT JOIN credentials c ON c.credential_id = $2
        WHERE i.nexus_id = $1 FOR SHARE OF i`, [auth.nexus_id, auth.credential_id]);
    const { identity, credential } = standing.rows[0] ?? { identity: 'UNKNOWN', credential: null };
    if (identity !== 'ACTIVE') throw new ConflictError(`NEXUS ID is ${identity}; the authorization can no longer be committed`, 'IDENTITY_NOT_ACTIVE');
    if (credential !== 'ACTIVE') throw new ConflictError('The device credential that confirmed this authorization is no longer active', 'CREDENTIAL_NOT_ACTIVE');
    if (!auth.verified_at || Date.now() - auth.verified_at.getTime() > env.BANK_COMMIT_MAX_AGE_SECONDS * 1000) {
      throw new ConflictError(`The confirmation is older than ${env.BANK_COMMIT_MAX_AGE_SECONDS} s; request a new authorization`, 'CONFIRMATION_TOO_OLD');
    }
    // FI-004 (phase 9): the state column alone does not authorize a commit;
    // the sealed evidence must show a device signature over these terms.
    const problem = await authorizationEvidenceProblem(tx, auth as unknown as AuthorizationRow, deferred);
    if (problem) {
      // Outside the transaction, so the record survives the refusal.
      deferred.push(() => recordAuditEvent('integrity_violation', { nexusId: auth.nexus_id, clientId },
        { authorizationId, reason: `commit refused: ${problem}` }).catch(() => undefined));
      throw new ConflictError(`The authorization's evidence does not support a commit: ${problem}`, 'EVIDENCE_INVALID');
    }

    const updated = await tx.query<Row>(
      `UPDATE authorization_requests SET bank_transaction_state='COMMIT_REQUESTED', bank_transaction_reference=$3
       WHERE authorization_id=$1 AND client_id=$2 RETURNING *`, [authorizationId, clientId, bankTransactionReference]);
    await recordAuditEvent('bank_commit_requested', { nexusId: auth.nexus_id }, { authorizationId, bankTransactionReference }, tx);
    await enqueueWebhook(clientId, 'authorization.bank_transaction.commit_requested', { authorizationId, bankTransactionReference }, tx);
    return view(updated.rows[0]);
  });
}

export async function finalizeBankTransaction(authorizationId: string, clientId: string, resultState: Extract<BankTransactionState, 'COMMITTED' | 'FAILED' | 'CANCELLED'>, errorMessage?: string): Promise<BankTransactionView> {
  return withTransaction(async (tx) => {
    const auth = await lock(tx, authorizationId, clientId);
    if (auth.bank_transaction_state === resultState) return view(auth);
    if (auth.bank_transaction_state !== 'COMMIT_REQUESTED') {
      throw new ConflictError(`Bank transaction is ${auth.bank_transaction_state}; expected COMMIT_REQUESTED`);
    }
    const updated = await tx.query<Row>(
      `UPDATE authorization_requests SET bank_transaction_state=$3, bank_commit_at=now(), bank_commit_error=$4
       WHERE authorization_id=$1 AND client_id=$2 RETURNING *`, [authorizationId, clientId, resultState, errorMessage ?? null]);
    const suffix = resultState.toLowerCase() as 'committed' | 'failed' | 'cancelled';
    await recordAuditEvent(`bank_transaction_${suffix}`, { nexusId: auth.nexus_id }, { authorizationId, errorMessage: errorMessage ?? null }, tx);
    await enqueueWebhook(clientId, `authorization.bank_transaction.${suffix}`, { authorizationId, state: resultState, error: errorMessage ?? null }, tx);
    return view(updated.rows[0]);
  });
}

/** Current state, for reconciliation against the bank's own ledger. */
export async function getBankTransactionState(authorizationId: string, clientId: string): Promise<BankTransactionView> {
  const result = await pool.query<Row>(
    `SELECT authorization_id, nexus_id, state, bank_transaction_state, bank_transaction_reference, bank_commit_at, bank_commit_error
     FROM authorization_requests WHERE authorization_id=$1 AND client_id=$2`, [authorizationId, clientId]);
  if (!result.rows[0]) throw new AuthorizationNotFoundError(authorizationId);
  return view(result.rows[0]);
}

async function lock(tx: PoolClient, authorizationId: string, clientId: string): Promise<Row> {
  const result = await tx.query<Row>(
    `SELECT * FROM authorization_requests WHERE authorization_id=$1 AND client_id=$2 FOR UPDATE`, [authorizationId, clientId]);
  if (!result.rows[0]) throw new AuthorizationNotFoundError(authorizationId);
  return result.rows[0];
}

function view(row: Row): BankTransactionView {
  return {
    authorizationId: row.authorization_id,
    authorizationState: row.state,
    bankTransactionState: row.bank_transaction_state,
    bankTransactionReference: row.bank_transaction_reference,
    bankCommitAt: row.bank_commit_at?.toISOString() ?? null,
    bankCommitError: row.bank_commit_error,
  };
}
