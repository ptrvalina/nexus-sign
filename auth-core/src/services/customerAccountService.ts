import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { env } from '../config/env';
import { recordAuditEvent } from './auditService';
import { enqueueWebhook } from './webhookService';
import { ConflictError, NotFoundError, ValidationError } from './errors';
import { mapEvidenceRow } from './evidenceService';
import { reportedState } from './authorizationExpiry';
import { suspendNexusIdentity } from './nexusIdentityService';

/**
 * What the customer sees and controls in the bank's app (presentation pages
 * 19 to 22). Every function takes the NEXUS ID of the signed device request;
 * nothing here reads another identity's data. The bank's app renders the
 * results; NEXUS-SIGN has no customer interface of its own.
 */

export interface DeviceSummary {
  credentialId: string; platform: string; securityLevel: string; attestationStatus: string;
  state: 'ACTIVE' | 'REVOKED'; enrolledAt: string; revokedAt: string | null; thisDevice: boolean;
}

/** All devices that ever held keys for this NEXUS ID, newest first. */
export async function listDevices(nexusId: string, requestingCredentialId: string): Promise<DeviceSummary[]> {
  const rows = await pool.query<{ credential_id: string; platform: string; security_level: string; attestation_status: string;
    state: 'ACTIVE' | 'REVOKED'; created_at: Date; revoked_at: Date | null }>(
    `SELECT credential_id, platform, security_level, attestation_status, state, created_at, revoked_at
       FROM credentials WHERE nexus_id = $1 ORDER BY created_at DESC`, [nexusId]);
  return rows.rows.map((r) => ({
    credentialId: r.credential_id, platform: r.platform, securityLevel: r.security_level, attestationStatus: r.attestation_status,
    state: r.state, enrolledAt: new Date(r.created_at).toISOString(), revokedAt: r.revoked_at ? new Date(r.revoked_at).toISOString() : null,
    thisDevice: r.credential_id === requestingCredentialId,
  }));
}

export interface HistoryEntry {
  authorizationId: string; transactionReference: string; operationType: string; amountMinor: string; currency: string;
  beneficiary: Record<string, string>; state: string; reason: string | null; createdAt: string; decidedAt: string | null;
  credentialId: string; evidence: boolean;
}

const HISTORY_FILTERS = { confirmed: ['VERIFIED'], declined: ['REJECTED', 'CANCELLED', 'EXPIRED', 'OFFLINE_UNSIGNED'], open: ['PENDING_USER', 'OFFLINE_PROVISIONAL'] } as const;
export type HistoryFilter = keyof typeof HISTORY_FILTERS | 'all';

/**
 * The identity's authorizations with how each ended, newest first, in pages
 * (`before`: the createdAt of the last entry of the previous page).
 */
export async function authorizationHistory(nexusId: string, options: { filter?: HistoryFilter; before?: string; limit?: number } = {}): Promise<HistoryEntry[]> {
  const limit = Math.min(Math.max(options.limit ?? 50, 1), 200);
  const states = options.filter && options.filter !== 'all' ? [...HISTORY_FILTERS[options.filter]] : null;
  const rows = await pool.query<{ authorization_id: string; transaction_reference: string; operation_type: string; amount_minor: string;
    currency: string; beneficiary: Record<string, string>; state: string; expires_at: Date; created_at: Date; verified_at: Date | null;
    credential_id: string; outcome_reason: string | null; occurred_at: Date | null; evidence_id: string | null }>(
    `SELECT a.authorization_id, a.transaction_reference, a.operation_type, a.amount_minor::text AS amount_minor, a.currency, a.beneficiary,
            a.state, a.expires_at, a.created_at, a.verified_at, a.credential_id, o.reason AS outcome_reason, o.occurred_at,
            coalesce(e.evidence_id, o.evidence_id) AS evidence_id
       FROM authorization_requests a
       LEFT JOIN evidence_outcomes o ON o.authorization_id = a.authorization_id AND o.subject = 'AUTHORIZATION'
       LEFT JOIN evidence_records e ON e.authorization_id = a.authorization_id AND e.record_type = 'AUTHORIZATION'
      WHERE a.nexus_id = $1 AND ($2::text[] IS NULL OR a.state = ANY($2::text[])) AND ($3::timestamptz IS NULL OR a.created_at < $3::timestamptz)
      ORDER BY a.created_at DESC LIMIT $4`,
    [nexusId, states, options.before ?? null, limit]);
  return rows.rows.map((r) => ({
    authorizationId: r.authorization_id, transactionReference: r.transaction_reference, operationType: r.operation_type,
    amountMinor: r.amount_minor, currency: r.currency, beneficiary: r.beneficiary,
    state: reportedState({ state: r.state as never, expiresAt: new Date(r.expires_at) }),
    reason: r.outcome_reason, createdAt: new Date(r.created_at).toISOString(),
    decidedAt: r.verified_at ? new Date(r.verified_at).toISOString() : r.occurred_at ? new Date(r.occurred_at).toISOString() : null,
    credentialId: r.credential_id, evidence: r.evidence_id !== null,
  }));
}

/**
 * The sealed evidence of one of the identity's authorizations (the
 * confirmation, or the outcome when it ended otherwise), with the
 * enrolment record of its credential, so the app can show it and an
 * auditor can verify it with the published evidence key.
 */
export async function evidenceForCustomer(nexusId: string, authorizationId: string): Promise<{ record: ReturnType<typeof mapEvidenceRow>; credentialEnrolment: ReturnType<typeof mapEvidenceRow> | null }> {
  const row = (await pool.query(
    `SELECT * FROM evidence_records WHERE authorization_id = $1 AND nexus_id = $2 AND record_type IN ('AUTHORIZATION', 'AUTHORIZATION_OUTCOME')`,
    [authorizationId, nexusId])).rows[0];
  if (!row) throw new NotFoundError('No sealed evidence for this authorization yet');
  const record = mapEvidenceRow(row);
  const hash = (record.sealedPayload as { enrolmentEvidenceHash?: string }).enrolmentEvidenceHash;
  const enrolment = hash ? (await pool.query(
    `SELECT * FROM evidence_records WHERE nexus_id = $1 AND evidence_hash = $2 AND record_type = 'CREDENTIAL_ENROLLED'`, [nexusId, hash])).rows[0] : undefined;
  return { record, credentialEnrolment: enrolment ? mapEvidenceRow(enrolment) : null };
}

/** Audit details a customer may see; operator names, IP addresses of other parties and secrets are not among them. */
const VISIBLE_DETAILS = ['authorizationId', 'credentialId', 'credentialIds', 'reason', 'replacementId', 'method', 'notBefore', 'version', 'effectiveAt'];

export interface SecurityEvent { eventType: string; at: string; actor: 'BANK' | 'DEVICE' | 'OPERATOR' | 'SYSTEM'; details: Record<string, unknown> }

/** The identity's security log: enrolments, revocations, replacements, recoveries, suspensions, settings, declines. */
export async function securityEvents(nexusId: string, options: { before?: string; limit?: number } = {}): Promise<SecurityEvent[]> {
  const limit = Math.min(Math.max(options.limit ?? 50, 1), 200);
  const rows = await pool.query<{ event_type: string; timestamp: Date; actor: string | null; details: Record<string, unknown> }>(
    `SELECT event_type, timestamp, actor, details FROM audit_logs
      WHERE nexus_id = $1 AND ($2::timestamptz IS NULL OR timestamp < $2::timestamptz)
      ORDER BY timestamp DESC LIMIT $3`, [nexusId, options.before ?? null, limit]);
  return rows.rows.map((r) => ({
    eventType: r.event_type,
    at: new Date(r.timestamp).toISOString(),
    actor: r.actor?.startsWith('credential:') ? 'DEVICE' : r.actor?.startsWith('bank:') ? 'BANK' : r.actor && !r.actor.startsWith('system') ? 'OPERATOR' : 'SYSTEM',
    details: Object.fromEntries(Object.entries(r.details ?? {}).filter(([k]) => VISIBLE_DETAILS.includes(k))),
  }));
}

export interface NotificationEntry { messageId: string; category: string; authorizationId: string | null; status: string; createdAt: string; deliveredAt: string | null }

/**
 * Past push messages of the identity (the event feed). Contents stay sealed
 * per device; the app opens one with GET /v1/mobile/push-messages/{id}.
 */
export async function notificationHistory(nexusId: string, options: { before?: string; limit?: number } = {}): Promise<NotificationEntry[]> {
  const limit = Math.min(Math.max(options.limit ?? 50, 1), 200);
  const rows = await pool.query<{ message_id: string; category: string; authorization_id: string | null; status: string; created_at: Date; delivered_at: Date | null }>(
    `SELECT message_id, category, authorization_id, status, created_at, delivered_at FROM push_messages
      WHERE nexus_id = $1 AND ($2::timestamptz IS NULL OR created_at < $2::timestamptz)
      ORDER BY created_at DESC LIMIT $3`, [nexusId, options.before ?? null, limit]);
  return rows.rows.map((r) => ({
    messageId: r.message_id, category: r.category, authorizationId: r.authorization_id, status: r.status,
    createdAt: new Date(r.created_at).toISOString(), deliveredAt: r.delivered_at ? new Date(r.delivered_at).toISOString() : null,
  }));
}

// --- Settings and limits ---

export interface CustomerSettings {
  version: number;
  currency: string | null;
  perPaymentLimitMinor: string | null;
  dailyLimitMinor: string | null;
  videoCheckAboveMinor: string | null;
  channels: { push: boolean; audio: boolean; video: boolean };
  effectiveAt: string;
}
export type SettingsInput = Omit<CustomerSettings, 'version' | 'effectiveAt'>;

const DEFAULT_SETTINGS: CustomerSettings = {
  version: 0, currency: null, perPaymentLimitMinor: null, dailyLimitMinor: null, videoCheckAboveMinor: null,
  channels: { push: true, audio: true, video: true }, effectiveAt: new Date(0).toISOString(),
};

interface SettingsRow { version: number; currency: string | null; per_payment_limit_minor: string | null; daily_limit_minor: string | null;
  video_check_above_minor: string | null; channels: CustomerSettings['channels']; effective_at: Date }
const SETTINGS_COLUMNS = `version, currency, per_payment_limit_minor::text AS per_payment_limit_minor, daily_limit_minor::text AS daily_limit_minor,
  video_check_above_minor::text AS video_check_above_minor, channels, effective_at`;
const toSettings = (r: SettingsRow): CustomerSettings => ({
  version: Number(r.version), currency: r.currency, perPaymentLimitMinor: r.per_payment_limit_minor, dailyLimitMinor: r.daily_limit_minor,
  videoCheckAboveMinor: r.video_check_above_minor, channels: r.channels, effectiveAt: new Date(r.effective_at).toISOString(),
});

/** The settings in force now, and a relaxing change still on hold. */
export async function getSettings(nexusId: string, runner: Pick<PoolClient, 'query'> = pool): Promise<{ current: CustomerSettings; pending: CustomerSettings | null }> {
  const current = (await runner.query<SettingsRow>(
    `SELECT ${SETTINGS_COLUMNS} FROM customer_settings_versions WHERE nexus_id = $1 AND effective_at <= now() ORDER BY version DESC LIMIT 1`, [nexusId])).rows[0];
  const pending = (await runner.query<SettingsRow>(
    `SELECT ${SETTINGS_COLUMNS} FROM customer_settings_versions WHERE nexus_id = $1 AND effective_at > now() ORDER BY version DESC LIMIT 1`, [nexusId])).rows[0];
  return { current: current ? toSettings(current) : DEFAULT_SETTINGS, pending: pending ? toSettings(pending) : null };
}

const big = (v: string | null): bigint | null => (v === null ? null : BigInt(v));
/** True when `next` allows something `current` did not (a higher or removed limit or threshold, another currency). */
export function relaxes(current: CustomerSettings, next: SettingsInput): boolean {
  const looser = (a: string | null, b: string | null): boolean => { const x = big(a); const y = big(b); return x !== null && (y === null || y > x); };
  if (current.currency !== null && next.currency !== current.currency) return true;
  return looser(current.perPaymentLimitMinor, next.perPaymentLimitMinor) || looser(current.dailyLimitMinor, next.dailyLimitMinor)
    || looser(current.videoCheckAboveMinor, next.videoCheckAboveMinor);
}

const AMOUNT = /^(0|[1-9]\d{0,29})$/;

/**
 * Saves new settings from the enrolled device. Tightening applies now;
 * relaxing applies after CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS, and the bank
 * is told either way (`customer.settings_changed`), so it can warn the
 * customer on their other channels.
 */
export async function updateSettings(clientId: string, nexusId: string, credentialId: string, input: SettingsInput): Promise<CustomerSettings> {
  for (const v of [input.perPaymentLimitMinor, input.dailyLimitMinor, input.videoCheckAboveMinor]) {
    if (v !== null && !AMOUNT.test(v)) throw new ValidationError('Limits are non-negative integer amounts in minor units');
  }
  if (input.currency !== null && !/^[A-Z]{3}$/.test(input.currency)) throw new ValidationError('currency must be an ISO 4217 code');
  if (input.currency === null && (input.perPaymentLimitMinor ?? input.dailyLimitMinor ?? input.videoCheckAboveMinor) !== null) {
    throw new ValidationError('Limits need a currency');
  }
  if (!input.channels.push) throw new ValidationError('Push cannot be switched off: it delivers the confirmation requests');
  if (input.videoCheckAboveMinor !== null && !input.channels.video) throw new ValidationError('A video check threshold needs the video channel');
  return withTransaction(async (tx) => {
    await tx.query(`SELECT 1 FROM nexus_identities WHERE nexus_id = $1 FOR UPDATE`, [nexusId]);
    const { current, pending } = await getSettings(nexusId, tx);
    // A pending relaxation is replaced by the new version; compared with what is in force.
    const relaxing = relaxes(current, input);
    const hold = relaxing ? env.CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS : 0;
    const version = Math.max(current.version, pending?.version ?? 0) + 1;
    const saved = (await tx.query<SettingsRow>(
      `INSERT INTO customer_settings_versions (nexus_id, version, currency, per_payment_limit_minor, daily_limit_minor, video_check_above_minor,
         channels, changed_by_credential_id, relaxes, effective_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, clock_timestamp() + $10::integer * interval '1 second')
       RETURNING ${SETTINGS_COLUMNS}`,
      [nexusId, version, input.currency, input.perPaymentLimitMinor, input.dailyLimitMinor, input.videoCheckAboveMinor,
        JSON.stringify(input.channels), credentialId, relaxing, hold])).rows[0];
    const settings = toSettings(saved);
    await recordAuditEvent('customer_settings_changed', { nexusId, actor: `credential:${credentialId}` },
      { version, relaxes: relaxing, effectiveAt: settings.effectiveAt }, tx);
    await enqueueWebhook(clientId, 'customer.settings_changed', { nexusId, credentialId, relaxes: relaxing, settings }, tx);
    return settings;
  });
}

/**
 * Checked in the transaction that creates an authorization, with the
 * identity row locked: refuses an amount above the customer's limits and
 * reports whether the customer asked for a video check at this amount.
 * Other currencies are not limited (the bank's own limits apply).
 */
export async function applyCustomerLimits(tx: PoolClient, nexusId: string, amountMinor: string, currency: string): Promise<{ requireVideo: boolean }> {
  await tx.query(`SELECT 1 FROM nexus_identities WHERE nexus_id = $1 FOR UPDATE`, [nexusId]);
  const { current } = await getSettings(nexusId, tx);
  if (current.currency !== currency) return { requireVideo: false };
  const amount = BigInt(amountMinor);
  if (current.perPaymentLimitMinor !== null && amount > BigInt(current.perPaymentLimitMinor)) {
    throw new ConflictError('The amount is above the limit per payment the customer set', 'CUSTOMER_LIMIT_EXCEEDED');
  }
  if (current.dailyLimitMinor !== null) {
    const used = (await tx.query<{ total: string }>(
      `SELECT coalesce(sum(amount_minor), 0)::text AS total FROM authorization_requests
        WHERE nexus_id = $1 AND currency = $2 AND created_at > now() - interval '24 hours'
          AND (state IN ('VERIFIED', 'OFFLINE_PROVISIONAL') OR (state = 'PENDING_USER' AND expires_at > now()))`, [nexusId, currency])).rows[0].total;
    if (BigInt(used) + amount > BigInt(current.dailyLimitMinor)) {
      throw new ConflictError('The amount would exceed the daily limit the customer set', 'CUSTOMER_LIMIT_EXCEEDED');
    }
  }
  return { requireVideo: current.videoCheckAboveMinor !== null && amount > BigInt(current.videoCheckAboveMinor) };
}

/** The customer suspends their NEXUS ID from an enrolled device (lost or stolen phone, suspected fraud). */
export async function suspendByCustomer(clientId: string, nexusId: string, credentialId: string, reason: 'LOST_DEVICE' | 'SUSPECTED_FRAUD' | 'OTHER'): Promise<void> {
  await withTransaction(async (tx) => {
    await suspendNexusIdentity(nexusId, `CUSTOMER:${reason}`, `credential:${credentialId}`, tx);
    await enqueueWebhook(clientId, 'identity.suspended', { nexusId, by: 'CUSTOMER', credentialId, reason }, tx);
  });
}
