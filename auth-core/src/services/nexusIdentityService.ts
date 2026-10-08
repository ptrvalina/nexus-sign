import { randomInt } from 'node:crypto';
import type { PoolClient } from 'pg';
import { withTransaction, pool } from '../db/pool';
import { recordAuditEvent } from './auditService';
import { forgetInactivePushRegistrations } from './pushRegistrationService';

export interface NexusIdentityRecord {
  nexusId: string;
  clientId: string;
  bankCustomerRef: string;
  status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
  createdAt: Date;
  updatedAt: Date;
  lastUsedAt: Date | null;
}

export class NexusIdentityNotFoundError extends Error {
  constructor(nexusId: string) {
    super(`NEXUS ID ${nexusId} was not found`);
    this.name = 'NexusIdentityNotFoundError';
  }
}

export class DuplicateBankCustomerError extends Error {
  constructor(bankCustomerRef: string) {
    super(`An active identity already exists for bank customer reference ${bankCustomerRef}`);
    this.name = 'DuplicateBankCustomerError';
  }
}

async function allocateNexusId(client: { query: Function }): Promise<string> {
  for (let i = 0; i < 10; i += 1) {
    const candidate = randomInt(100_000_000, 1_000_000_000).toString();
    const existing = await client.query('SELECT 1 FROM nexus_identities WHERE nexus_id = $1', [candidate]);
    if (existing.rowCount === 0) return candidate;
  }
  throw new Error('Unable to allocate a unique 9-digit NEXUS ID');
}

export async function createNexusIdentity(clientId: string, bankCustomerRef: string): Promise<NexusIdentityRecord> {
  try {
    return await withTransaction(async (client) => {
    const duplicate = await client.query(
      `SELECT nexus_id FROM nexus_identities WHERE client_id = $1 AND bank_customer_ref = $2 AND status <> 'REVOKED' FOR UPDATE`,
      [clientId, bankCustomerRef],
    );
    if (duplicate.rows[0]) throw new DuplicateBankCustomerError(bankCustomerRef);

    const nexusId = await allocateNexusId(client);
    const result = await client.query<IdentityRow>(
      `INSERT INTO nexus_identities (nexus_id, client_id, bank_customer_ref)
       VALUES ($1, $2, $3)
       RETURNING nexus_id, client_id, bank_customer_ref, status, created_at, updated_at, last_used_at`,
      [nexusId, clientId, bankCustomerRef],
    );
    const row = result.rows[0];
    if (!row) throw new Error('NEXUS identity insert returned no row');
    await recordAuditEvent('identity_created', { nexusId }, {}, client);
    return map(row);
    });
  } catch (error: unknown) {
    if (typeof error === 'object' && error !== null && 'code' in error && (error as { code?: string }).code === '23505') {
      throw new DuplicateBankCustomerError(bankCustomerRef);
    }
    throw error;
  }
}

export async function getNexusIdentityForClient(nexusId: string, clientId: string): Promise<NexusIdentityRecord> {
  const result = await pool.query<IdentityRow>(
    `SELECT nexus_id, client_id, bank_customer_ref, status, created_at, updated_at, last_used_at
     FROM nexus_identities WHERE nexus_id = $1 AND client_id = $2`,
    [nexusId, clientId],
  );
  const row = result.rows[0];
  if (!row) throw new NexusIdentityNotFoundError(nexusId);
  return map(row);
}

interface IdentityRow { nexus_id: string; client_id: string; bank_customer_ref: string; status: NexusIdentityRecord['status']; created_at: Date; updated_at: Date; last_used_at: Date | null; }
function map(row: IdentityRow): NexusIdentityRecord {
  return { nexusId: row.nexus_id, clientId: row.client_id, bankCustomerRef: row.bank_customer_ref, status: row.status, createdAt: row.created_at, updatedAt: row.updated_at, lastUsedAt: row.last_used_at };
}


/** Suspends an identity: open authorizations are cancelled, and signing,
 * mobile sessions and recovery are refused until it is reactivated. */
export async function suspendNexusIdentity(nexusId: string, reason: string, actor?: string): Promise<void> {
  await withTransaction(async (client) => {
    const result = await client.query(`UPDATE nexus_identities SET status='SUSPENDED', updated_at=now() WHERE nexus_id=$1 AND status='ACTIVE'`, [nexusId]);
    if (result.rowCount === 0) throw new NexusIdentityNotFoundError(nexusId);
    const cancelled = await client.query(`UPDATE authorization_requests SET state='CANCELLED' WHERE nexus_id=$1 AND state='PENDING_USER'`, [nexusId]);
    await recordAuditEvent('identity_suspended', { nexusId, actor }, { reason, cancelledAuthorizations: cancelled.rowCount ?? 0 }, client);
  });
}

/** Runs `work` in the caller's transaction, or in a new one. */
function inTransaction<T>(tx: PoolClient | undefined, work: (client: PoolClient) => Promise<T>): Promise<T> {
  return tx ? work(tx) : withTransaction(work);
}

export async function revokeNexusIdentity(nexusId: string, reason: string, actor?: string, tx?: PoolClient): Promise<void> {
  await inTransaction(tx, async (client) => {
    const result = await client.query(`UPDATE nexus_identities SET status='REVOKED', updated_at=now() WHERE nexus_id=$1 AND status IN ('ACTIVE','SUSPENDED')`, [nexusId]);
    if (result.rowCount === 0) throw new NexusIdentityNotFoundError(nexusId);
    await client.query(`UPDATE credentials SET state='REVOKED', revoked_at=now() WHERE nexus_id=$1 AND state = 'ACTIVE'`, [nexusId]);
    const cancelled = await client.query(`UPDATE authorization_requests SET state='CANCELLED' WHERE nexus_id=$1 AND state='PENDING_USER'`, [nexusId]);
    await recordAuditEvent('identity_revoked', { nexusId, actor }, { reason, cancelledAuthorizations: cancelled.rowCount ?? 0 }, client);
    await forgetInactivePushRegistrations(client, nexusId);
  });
}

export async function reactivateNexusIdentity(nexusId: string, reason: string, actor?: string, tx?: PoolClient): Promise<void> {
  await inTransaction(tx, async (client) => {
    const result = await client.query(`UPDATE nexus_identities SET status='ACTIVE', updated_at=now() WHERE nexus_id=$1 AND status='SUSPENDED'`, [nexusId]);
    if (result.rowCount === 0) throw new NexusIdentityNotFoundError(nexusId);
    await recordAuditEvent('identity_reactivated', { nexusId, actor }, { reason }, client);
  });
}

/** Current status of an identity, or null if it does not exist. */
export async function getNexusIdentityStatus(nexusId: string): Promise<NexusIdentityRecord['status'] | null> {
  const result = await pool.query<{ status: NexusIdentityRecord['status'] }>(`SELECT status FROM nexus_identities WHERE nexus_id=$1`, [nexusId]);
  return result.rows[0]?.status ?? null;
}

/** An identity by NEXUS ID regardless of bank client, for the admin interface. */
export async function getNexusIdentity(nexusId: string): Promise<NexusIdentityRecord> {
  const result = await pool.query<IdentityRow>(`SELECT nexus_id,client_id,bank_customer_ref,status,created_at,updated_at,last_used_at FROM nexus_identities WHERE nexus_id=$1`, [nexusId]);
  const row = result.rows[0];
  if (!row) throw new NexusIdentityNotFoundError(nexusId);
  return map(row);
}
