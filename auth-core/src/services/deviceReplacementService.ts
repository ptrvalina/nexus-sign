import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { env } from '../config/env';
import { recordAuditEvent } from './auditService';
import { enqueueWebhook } from './webhookService';
import { ConflictError, NotFoundError } from './errors';
import type { DeviceRequestKind } from './mobileSessionService';

/**
 * Device replacement hold (audit finding A2-01).
 *
 * Replacing an identity's enrolled device used to need one call by the bank
 * backend: the new device was enrolled and the old one revoked at once, with
 * nothing from the customer. Whoever holds the bank backend's credentials
 * could take over any NEXUS ID of that bank and sign payments.
 *
 * A replacement is now a request with a hold. The bank asks for it
 * (POST /v1/mobile/sessions with `replacement`); Auth Core records it,
 * tells the bank (`credential.replacement_requested`, which the bank shows on
 * the customer's current device), and issues a BOOTSTRAP token only when the
 * customer approved it from the enrolled device (device-signed), or after
 * DEVICE_REPLACEMENT_HOLD_SECONDS. The enrolled device can cancel it during
 * the hold. Enrolment uses the request exactly once, in the same transaction
 * that revokes the old device.
 */

export type ReplacementMethod = 'BRANCH_VISIT' | 'VIDEO_IDENTIFICATION' | 'IN_APP_STRONG_AUTHENTICATION' | 'OTHER';
export type ReplacementState = 'PENDING' | 'APPROVED' | 'CANCELLED' | 'USED' | 'EXPIRED';

export interface DeviceReplacement {
  replacementId: string;
  /** REPLACEMENT: the new device takes over. ADDITION: it joins the active ones. */
  kind: DeviceRequestKind;
  nexusId: string;
  method: ReplacementMethod;
  reference: string;
  state: ReplacementState;
  requestedAt: string;
  notBefore: string;
  expiresAt: string;
  /** True when a BOOTSTRAP token may be issued for it now. */
  usable: boolean;
}

/** How long an open request stays valid after its hold ends. */
const REQUEST_VALIDITY_AFTER_HOLD_SECONDS = 7 * 24 * 3600;

interface ReplacementRow {
  replacement_id: string; kind: DeviceRequestKind; nexus_id: string; method: ReplacementMethod; reference: string; state: ReplacementState;
  requested_at: Date; not_before: Date; expires_at: Date; usable: boolean;
}

const COLUMNS = `replacement_id, kind, nexus_id, method, reference, state, requested_at, not_before, expires_at,
  (state = 'APPROVED' OR (state = 'PENDING' AND not_before <= now())) AND expires_at > now() AS usable`;

const toReplacement = (r: ReplacementRow): DeviceReplacement => ({
  replacementId: r.replacement_id, kind: r.kind, nexusId: r.nexus_id, method: r.method, reference: r.reference, state: r.state,
  requestedAt: new Date(r.requested_at).toISOString(), notBefore: new Date(r.not_before).toISOString(),
  expiresAt: new Date(r.expires_at).toISOString(), usable: Boolean(r.usable),
});

/** Expired open requests no longer block a new one. */
async function expireOpenRequests(client: PoolClient, nexusId: string): Promise<void> {
  await client.query(`UPDATE device_replacements SET state = 'EXPIRED', decided_at = now()
    WHERE nexus_id = $1 AND state IN ('PENDING', 'APPROVED') AND expires_at <= now()`, [nexusId]);
}

/**
 * The bank asks to replace the enrolled device. Returns the open request for
 * this identity (creating it, with its hold, if there is none). The caller
 * issues a BOOTSTRAP token only when `usable` is true.
 */
export async function requestDeviceReplacement(clientId: string, nexusId: string, method: ReplacementMethod, reference: string, kind: DeviceRequestKind = 'REPLACEMENT'): Promise<{ replacement: DeviceReplacement; created: boolean }> {
  return withTransaction(async (client) => {
    // The identity row serializes requests, approvals and enrolments.
    const identity = await client.query<{ max_devices_per_identity: number }>(
      `SELECT b.max_devices_per_identity FROM nexus_identities n JOIN bank_clients b ON b.client_id = n.client_id
        WHERE n.nexus_id = $1 AND n.client_id = $2 FOR UPDATE OF n`, [nexusId, clientId]);
    if (identity.rowCount === 0) throw new NotFoundError(`NEXUS ID ${nexusId} was not found`);
    await expireOpenRequests(client, nexusId);
    const open = await client.query<ReplacementRow>(
      `SELECT ${COLUMNS} FROM device_replacements WHERE nexus_id = $1 AND state IN ('PENDING', 'APPROVED')`, [nexusId]);
    if (open.rows[0]) {
      if (open.rows[0].kind !== kind) {
        throw new ConflictError(`A device ${open.rows[0].kind.toLowerCase()} request is already open for this NEXUS ID`, 'DEVICE_REQUEST_OPEN');
      }
      return { replacement: toReplacement(open.rows[0]), created: false };
    }
    if (kind === 'ADDITION') {
      const active = await client.query<{ n: number }>(`SELECT count(*)::int AS n FROM credentials WHERE nexus_id = $1 AND state = 'ACTIVE'`, [nexusId]);
      if (active.rows[0].n === 0) throw new ConflictError('A device can be added only next to an active one; enrol or replace instead', 'NO_ACTIVE_DEVICE');
      if (active.rows[0].n >= identity.rows[0].max_devices_per_identity) {
        throw new ConflictError(`The NEXUS ID already has ${active.rows[0].n} active device(s), the bank's limit`, 'DEVICE_LIMIT_REACHED');
      }
    }
    const hold = env.DEVICE_REPLACEMENT_HOLD_SECONDS;
    const created = await client.query<ReplacementRow>(
      `INSERT INTO device_replacements (replacement_id, nexus_id, client_id, method, reference, state, not_before, expires_at, kind)
       VALUES ($1, $2, $3, $4, $5, 'PENDING', now() + $6::integer * interval '1 second', now() + ($6::integer + $7::integer) * interval '1 second', $8)
       RETURNING ${COLUMNS}`,
      [randomUUID(), nexusId, clientId, method, reference, hold, REQUEST_VALIDITY_AFTER_HOLD_SECONDS, kind]);
    const replacement = toReplacement(created.rows[0]);
    await recordAuditEvent('credential_replacement_requested', { nexusId, actor: `bank:${clientId}` },
      { replacementId: replacement.replacementId, kind, method, reference, notBefore: replacement.notBefore }, client);
    await enqueueWebhook(clientId, kind === 'ADDITION' ? 'credential.addition_requested' : 'credential.replacement_requested', {
      nexusId, replacementId: replacement.replacementId, kind, method, reference, notBefore: replacement.notBefore, expiresAt: replacement.expiresAt,
    }, client);
    return { replacement, created: true };
  });
}

/** Open requests for the identity of an enrolled device (what its app shows). */
export async function listOpenReplacements(nexusId: string): Promise<DeviceReplacement[]> {
  const rows = await pool.query<ReplacementRow>(
    `SELECT ${COLUMNS} FROM device_replacements WHERE nexus_id = $1 AND state IN ('PENDING', 'APPROVED') AND expires_at > now()
     ORDER BY requested_at`, [nexusId]);
  return rows.rows.map(toReplacement);
}

/**
 * The customer decides on the enrolled device (a device-signed request):
 * APPROVE ends the hold now, CANCEL ends the request. Only an ACTIVE
 * credential of the same identity decides, and only a PENDING request.
 */
export async function decideDeviceReplacement(credentialId: string, nexusId: string, replacementId: string, decision: 'APPROVE' | 'CANCEL'): Promise<DeviceReplacement> {
  return withTransaction(async (client) => {
    await client.query(`SELECT 1 FROM nexus_identities WHERE nexus_id = $1 FOR UPDATE`, [nexusId]);
    const credential = await client.query(`SELECT 1 FROM credentials WHERE credential_id = $1 AND nexus_id = $2 AND state = 'ACTIVE'`, [credentialId, nexusId]);
    if (credential.rowCount === 0) throw new ConflictError('Only the enrolled device of this NEXUS ID decides on a replacement', 'CREDENTIAL_NOT_ACTIVE');
    await expireOpenRequests(client, nexusId);
    const updated = await client.query<ReplacementRow>(
      `UPDATE device_replacements SET state = $3, decided_by_credential_id = $4, decided_at = now()
        WHERE replacement_id = $1 AND nexus_id = $2 AND state = 'PENDING'
        RETURNING ${COLUMNS}`,
      [replacementId, nexusId, decision === 'APPROVE' ? 'APPROVED' : 'CANCELLED', credentialId]);
    const row = updated.rows[0];
    if (!row) throw new ConflictError('No pending replacement request with this ID', 'REPLACEMENT_NOT_PENDING');
    const clientId = (await client.query<{ client_id: string }>(`SELECT client_id FROM device_replacements WHERE replacement_id = $1`, [replacementId])).rows[0].client_id;
    await recordAuditEvent(decision === 'APPROVE' ? 'credential_replacement_approved' : 'credential_replacement_cancelled',
      { nexusId, actor: `credential:${credentialId}` }, { replacementId }, client);
    await enqueueWebhook(clientId, decision === 'APPROVE' ? 'credential.replacement_approved' : 'credential.replacement_cancelled', { nexusId, replacementId }, client);
    return toReplacement(row);
  });
}

/**
 * Inside the enrolment transaction (identity row already locked): the
 * replacement must still be usable, and is used once. Throws otherwise, so
 * the old device is not revoked.
 */
export async function consumeDeviceReplacement(client: PoolClient, nexusId: string, replacementId: string | undefined, newCredentialId: string, kind: DeviceRequestKind = 'REPLACEMENT'): Promise<void> {
  if (!replacementId) throw new ConflictError('A device replacement needs an approved or matured replacement request', 'REPLACEMENT_REQUIRED');
  const used = await client.query(
    `UPDATE device_replacements SET state = 'USED', used_by_credential_id = $3, decided_at = coalesce(decided_at, now())
      WHERE replacement_id = $1 AND nexus_id = $2 AND kind = $4 AND expires_at > now()
        AND (state = 'APPROVED' OR (state = 'PENDING' AND not_before <= now()))`,
    [replacementId, nexusId, newCredentialId, kind]);
  if (used.rowCount !== 1) {
    throw new ConflictError('The replacement request was cancelled, has expired, was already used or is still on hold', 'REPLACEMENT_NOT_USABLE');
  }
}
