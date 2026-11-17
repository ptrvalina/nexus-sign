import { pool, withTransaction } from '../db/pool';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import type { AdminSession } from './adminAuthService';
import { identityInScope } from './adminApprovalService';
import { recordAuditEvent } from './auditService';
import { CredentialNotFoundError, revokeCredentialForClient } from './credentialService';
import { ConflictError, ForbiddenError, NotFoundError } from './errors';
import { mapEvidenceRow } from './evidenceService';
import {
  getMandateForClient, listMandateDebits, listMandatesForIdentity, placeBankHold, releaseBankHold, withdrawMandate, type Mandate,
} from './mandateService';
import { enqueueWebhook } from './webhookService';
import { authorizationHistory, type HistoryEntry, type HistoryFilter } from './customerAccountService';

/**
 * What the bank's staff see and do in the console for one customer's
 * mandates and devices (presentation pages 17 to 22). Reading follows the
 * identity scope of the admin (a bank's staff see their bank's customers;
 * a platform operator sees all, read-only). Changes are made only by the
 * bank's own staff with at least the operator role, are written to the
 * audit log with the staff member's name, and, where the state of a mandate
 * changes, sealed in the evidence chain.
 */

/** The bank the admin acts for. A platform operator is not the bank. */
function actingBank(admin: AdminSession): string {
  if (!admin.clientId) throw new ForbiddenError("Only the bank's own staff change its customers' mandates and devices");
  return admin.clientId;
}

async function mandateInScope(admin: AdminSession, mandateId: string): Promise<Mandate> {
  const row = await pool.query<{ client_id: string }>(`SELECT client_id FROM mandates WHERE mandate_id = $1`, [mandateId]);
  const clientId = row.rows[0]?.client_id;
  if (!clientId || (admin.clientId !== null && admin.clientId !== clientId)) throw new NotFoundError(`Mandate ${mandateId} was not found`);
  return getMandateForClient(clientId, mandateId);
}

/** The customer's authorizations (confirmed, declined, open) with how each ended and whether evidence is sealed. */
export async function consoleAuthorizations(admin: AdminSession, nexusId: string, options: { filter?: HistoryFilter; before?: string } = {}): Promise<HistoryEntry[]> {
  const identity = await identityInScope(admin, nexusId);
  await recordAuditEvent('admin_authorizations_viewed', { nexusId, actor: `admin:${admin.username}` }, { filter: options.filter ?? 'all' });
  return authorizationHistory(identity.nexusId, { filter: options.filter, before: options.before, limit: 100 });
}

export async function consoleMandates(admin: AdminSession, nexusId: string): Promise<Mandate[]> {
  const identity = await identityInScope(admin, nexusId);
  await recordAuditEvent('admin_mandates_viewed', { nexusId, actor: `admin:${admin.username}` }, {});
  return listMandatesForIdentity(identity.nexusId, admin.clientId ?? undefined);
}

export interface MandateEventEntry { at: string; event: string; from: string | null; to: string | null; reason: string | null; actor: string | null }

/** One mandate with its debits, sealed evidence records and event log. */
export async function consoleMandate(admin: AdminSession, mandateId: string) {
  const mandate = await mandateInScope(admin, mandateId);
  const [debits, evidence, events] = await Promise.all([
    listMandateDebits(mandateId),
    pool.query(`SELECT * FROM evidence_records WHERE mandate_id = $1 ORDER BY chain_sequence`, [mandateId]),
    pool.query<{ timestamp: Date; actor: string | null; event_type: string; details: Record<string, string | undefined> }>(
      `SELECT timestamp, actor, event_type, details FROM audit_logs
        WHERE nexus_id = $1 AND event_type IN ('mandate_created', 'mandate_changed', 'mandate_signature_invalid') AND details->>'mandateId' = $2
        ORDER BY timestamp`, [mandate.nexusId, mandateId]),
  ]);
  await recordAuditEvent('admin_mandates_viewed', { nexusId: mandate.nexusId, actor: `admin:${admin.username}` }, { mandateId });
  return {
    mandate,
    debits,
    evidence: evidence.rows.map((r) => mapEvidenceRow(r)),
    events: events.rows.map((r): MandateEventEntry => ({
      at: new Date(r.timestamp).toISOString(), event: r.details.event ?? r.event_type, from: r.details.from ?? null, to: r.details.to ?? null,
      reason: r.details.reason ?? null, actor: r.actor,
    })),
  };
}

export async function consoleMandateAction(hsm: HsmAdapter, admin: AdminSession, mandateId: string, action: 'HOLD' | 'RELEASE' | 'WITHDRAW', reason: string): Promise<Mandate> {
  const clientId = actingBank(admin);
  await mandateInScope(admin, mandateId);
  switch (action) {
    case 'HOLD': return placeBankHold(hsm, clientId, mandateId, admin.username, reason);
    case 'RELEASE': return releaseBankHold(hsm, clientId, mandateId, admin.username);
    default: return withdrawMandate(hsm, clientId, mandateId, `CONSOLE:${admin.username}:${reason}`.slice(0, 64));
  }
}

export interface ConsoleDevice {
  credentialId: string; platform: string; securityLevel: string; attestationStatus: string; state: 'ACTIVE' | 'REVOKED';
  enrolledAt: string; lastUsedAt: string | null; revokedAt: string | null; enrolmentReason: string | null;
}
export interface ConsoleDeviceRequest {
  requestId: string; kind: string; method: string; reference: string; state: string; requestedAt: string; notBefore: string;
  expiresAt: string; decidedAt: string | null; usedByCredentialId: string | null;
}

/** Devices, device requests (additions and replacements), the bank's device limit and the identity's security events. */
export async function consoleDevices(admin: AdminSession, nexusId: string) {
  const identity = await identityInScope(admin, nexusId);
  const [devices, requests, limit, events] = await Promise.all([
    pool.query(
      `SELECT c.credential_id, c.platform, c.security_level, c.attestation_status, c.state, c.created_at, c.last_used_at, c.revoked_at,
              e.sealed_payload->>'reason' AS enrolment_reason
         FROM credentials c LEFT JOIN evidence_records e ON e.evidence_id = c.enrolment_evidence_id
        WHERE c.nexus_id = $1 ORDER BY c.created_at DESC`, [nexusId]),
    pool.query(
      `SELECT replacement_id, kind, method, reference, state, requested_at, not_before, expires_at, decided_at, used_by_credential_id
         FROM device_replacements WHERE nexus_id = $1 ORDER BY requested_at DESC LIMIT 100`, [nexusId]),
    pool.query<{ max_devices_per_identity: number }>(`SELECT max_devices_per_identity FROM bank_clients WHERE client_id = $1`, [identity.clientId]),
    pool.query<{ event_type: string; timestamp: Date; actor: string | null; details: Record<string, unknown> }>(
      `SELECT event_type, timestamp, actor, details FROM audit_logs
        WHERE nexus_id = $1 AND (event_type LIKE 'credential_%' OR event_type LIKE 'device_%' OR event_type LIKE 'recovery_%'
              OR event_type LIKE 'identity_%' OR event_type LIKE 'nexus_identity_%')
        ORDER BY timestamp DESC LIMIT 100`, [nexusId]),
  ]);
  await recordAuditEvent('admin_devices_viewed', { nexusId, actor: `admin:${admin.username}` }, {});
  const iso = (d: Date | null) => (d ? new Date(d).toISOString() : null);
  return {
    nexusId,
    maxDevicesPerIdentity: limit.rows[0]?.max_devices_per_identity ?? 1,
    devices: devices.rows.map((r): ConsoleDevice => ({
      credentialId: r.credential_id, platform: r.platform, securityLevel: r.security_level, attestationStatus: r.attestation_status, state: r.state,
      enrolledAt: iso(r.created_at)!, lastUsedAt: iso(r.last_used_at), revokedAt: iso(r.revoked_at), enrolmentReason: r.enrolment_reason,
    })),
    requests: requests.rows.map((r): ConsoleDeviceRequest => ({
      requestId: r.replacement_id, kind: r.kind, method: r.method, reference: r.reference, state: r.state, requestedAt: iso(r.requested_at)!,
      notBefore: iso(r.not_before)!, expiresAt: iso(r.expires_at)!, decidedAt: iso(r.decided_at), usedByCredentialId: r.used_by_credential_id,
    })),
    securityEvents: events.rows.map((r) => ({ eventType: r.event_type, at: iso(r.timestamp)!, actor: r.actor, details: r.details ?? {} })),
  };
}

/** The bank's staff revoke one device (for example reported lost by phone). Open payments addressed to it are cancelled. */
export async function consoleRevokeDevice(admin: AdminSession, nexusId: string, credentialId: string, reason: string): Promise<void> {
  const clientId = actingBank(admin);
  await identityInScope(admin, nexusId);
  const owner = await pool.query(`SELECT 1 FROM credentials WHERE credential_id = $1 AND nexus_id = $2`, [credentialId, nexusId]);
  if (owner.rowCount === 0) throw new CredentialNotFoundError(credentialId);
  try {
    await revokeCredentialForClient(credentialId, clientId, `CONSOLE:${admin.username}:${reason}`.slice(0, 96));
  } catch (error) {
    if (error instanceof CredentialNotFoundError) throw new ConflictError('The device is already removed', 'CREDENTIAL_NOT_ACTIVE');
    throw error;
  }
}

/** The bank's staff stop an open device addition or replacement (the customer did not ask for it). */
export async function consoleCancelDeviceRequest(admin: AdminSession, nexusId: string, requestId: string): Promise<ConsoleDeviceRequest> {
  const clientId = actingBank(admin);
  await identityInScope(admin, nexusId);
  return withTransaction(async (tx) => {
    const row = (await tx.query(
      `UPDATE device_replacements SET state = 'CANCELLED', decided_at = now()
        WHERE replacement_id = $1 AND nexus_id = $2 AND state IN ('PENDING', 'APPROVED')
        RETURNING replacement_id, kind, method, reference, state, requested_at, not_before, expires_at, decided_at, used_by_credential_id`,
      [requestId, nexusId])).rows[0];
    if (!row) throw new ConflictError('No open device request with this ID for this NEXUS ID', 'REPLACEMENT_NOT_PENDING');
    await recordAuditEvent('credential_replacement_cancelled', { nexusId, actor: `admin:${admin.username}` }, { requestId, kind: row.kind, by: 'BANK_STAFF' }, tx);
    await enqueueWebhook(clientId, 'credential.replacement_cancelled', { nexusId, replacementId: requestId, kind: row.kind, by: 'BANK_STAFF' }, tx);
    const iso = (d: Date | null) => (d ? new Date(d).toISOString() : null);
    return {
      requestId: row.replacement_id, kind: row.kind, method: row.method, reference: row.reference, state: row.state, requestedAt: iso(row.requested_at)!,
      notBefore: iso(row.not_before)!, expiresAt: iso(row.expires_at)!, decidedAt: iso(row.decided_at), usedByCredentialId: row.used_by_credential_id,
    };
  });
}
