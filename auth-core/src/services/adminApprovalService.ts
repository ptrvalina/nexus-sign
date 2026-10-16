import { withTransaction, pool } from '../db/pool';
import { env } from '../config/env';
import { recordAuditEvent } from './auditService';
import type { AdminSession } from './adminAuthService';
import { ConflictError, ForbiddenError, GoneError, NotFoundError } from './errors';
import { NexusIdentityNotFoundError, reactivateNexusIdentity, revokeNexusIdentity, type NexusIdentityRecord, getNexusIdentity } from './nexusIdentityService';

/**
 * Four-eyes control for the admin actions that cannot be undone by the bank
 * on its own: revoking an identity (its device credential and recovery are
 * gone) and reactivating a suspended one (it can sign again). One admin
 * requests, a different admin with access to the same bank approves, and the
 * action runs in the approval's transaction. Suspension stays a one-person
 * action because it is the protective response to an incident.
 */
export type ApprovalAction = 'REVOKE' | 'REACTIVATE';

export interface AdminApproval {
  approvalId: string;
  action: ApprovalAction;
  nexusId: string;
  clientId: string;
  reason: string;
  requestedBy: string;
  requestedAt: Date;
  expiresAt: Date;
  status: 'PENDING' | 'EXECUTED' | 'REJECTED' | 'EXPIRED';
  decidedBy: string | null;
  decidedAt: Date | null;
}

interface ApprovalRow {
  approval_id: string; action: ApprovalAction; nexus_id: string; client_id: string; reason: string;
  requested_by: string; requested_at: Date; expires_at: Date; status: AdminApproval['status'];
  decided_by: string | null; decided_at: Date | null;
}

const COLUMNS = 'approval_id, action, nexus_id, client_id, reason, requested_by, requested_at, expires_at, status, decided_by, decided_at';

function map(row: ApprovalRow): AdminApproval {
  return {
    approvalId: row.approval_id, action: row.action, nexusId: row.nexus_id, clientId: row.client_id, reason: row.reason,
    requestedBy: row.requested_by, requestedAt: row.requested_at, expiresAt: row.expires_at, status: row.status,
    decidedBy: row.decided_by, decidedAt: row.decided_at,
  };
}

/** An identity the admin may see: platform operators see every bank's,
 * bank-scoped admins only their bank's. Others are reported as not found. */
export async function identityInScope(admin: AdminSession, nexusId: string): Promise<NexusIdentityRecord> {
  const identity = await getNexusIdentity(nexusId);
  if (admin.clientId !== null && identity.clientId !== admin.clientId) throw new NexusIdentityNotFoundError(nexusId);
  return identity;
}

export async function requestApproval(admin: AdminSession, action: ApprovalAction, nexusId: string, reason: string): Promise<AdminApproval> {
  const identity = await identityInScope(admin, nexusId);
  const allowed = action === 'REVOKE' ? ['ACTIVE', 'SUSPENDED'] : ['SUSPENDED'];
  if (!allowed.includes(identity.status)) throw new ConflictError(`NEXUS ID is ${identity.status}`);
  try {
    const result = await pool.query<ApprovalRow>(
      `INSERT INTO admin_approvals (action, nexus_id, client_id, reason, requested_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, now() + make_interval(hours => $6))
       RETURNING ${COLUMNS}`,
      [action, nexusId, identity.clientId, reason, admin.username, env.ADMIN_APPROVAL_TTL_HOURS],
    );
    const approval = map(result.rows[0]!);
    await recordAuditEvent('admin_approval_requested', { nexusId, actor: `admin:${admin.username}` }, { approvalId: approval.approvalId, action, reason });
    return approval;
  } catch (error) {
    if ((error as { code?: string }).code === '23505') throw new ConflictError(`A ${action} request for this NEXUS ID is already waiting for approval`, 'APPROVAL_PENDING');
    throw error;
  }
}

export async function listApprovals(admin: AdminSession, status: AdminApproval['status'] = 'PENDING'): Promise<AdminApproval[]> {
  await pool.query(`UPDATE admin_approvals SET status = 'EXPIRED', decided_at = now() WHERE status = 'PENDING' AND expires_at <= now()`);
  const result = await pool.query<ApprovalRow>(
    `SELECT ${COLUMNS} FROM admin_approvals
      WHERE status = $1 AND ($2::text IS NULL OR client_id = $2)
      ORDER BY requested_at DESC LIMIT 200`,
    [status, admin.clientId],
  );
  return result.rows.map(map);
}

/**
 * Approves (and executes) or rejects a pending request. The approver must be
 * a different admin with access to the identity's bank; the database also
 * refuses an EXECUTED request with `decided_by = requested_by`. The requester may withdraw (reject)
 * their own request.
 */
export async function decideApproval(admin: AdminSession, approvalId: string, decision: 'APPROVE' | 'REJECT'): Promise<AdminApproval> {
  return withTransaction(async (client) => {
    const result = await client.query<ApprovalRow>(`SELECT ${COLUMNS} FROM admin_approvals WHERE approval_id = $1 FOR UPDATE`, [approvalId]);
    const row = result.rows[0];
    if (!row || (admin.clientId !== null && row.client_id !== admin.clientId)) throw new NotFoundError('Approval request not found');
    if (row.status !== 'PENDING') throw new ConflictError(`Approval request is ${row.status}`);
    // Marked EXPIRED by the next listApprovals().
    if (row.expires_at.getTime() <= Date.now()) throw new GoneError('Approval request has expired');
    const actor = `admin:${admin.username}`;
    if (decision === 'APPROVE') {
      if (row.requested_by === admin.username) throw new ForbiddenError('A second admin must approve this request');
      const performedBy = `${actor} (requested by admin:${row.requested_by})`;
      if (row.action === 'REVOKE') await revokeNexusIdentity(row.nexus_id, row.reason, performedBy, client);
      else await reactivateNexusIdentity(row.nexus_id, row.reason, performedBy, client);
    }
    const updated = await client.query<ApprovalRow>(
      `UPDATE admin_approvals SET status = $2, decided_by = $3, decided_at = now() WHERE approval_id = $1 RETURNING ${COLUMNS}`,
      [approvalId, decision === 'APPROVE' ? 'EXECUTED' : 'REJECTED', admin.username],
    );
    await recordAuditEvent(decision === 'APPROVE' ? 'admin_approval_granted' : 'admin_approval_rejected',
      { nexusId: row.nexus_id, actor }, { approvalId, action: row.action, requestedBy: row.requested_by }, client);
    return map(updated.rows[0]!);
  });
}
