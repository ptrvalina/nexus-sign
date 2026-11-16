/**
 * Audit log export for a SIEM (security information and event management).
 * Reads audit_logs in (timestamp, id) order after a cursor and formats each
 * event as a JSON line with Elastic Common Schema field names, or as an
 * ArcSight CEF line, the two formats SIEM collectors accept from a file or
 * stdin. Read-only; runs with the nexus_audit_reader role
 * (scripts/db/roles.sql).
 *
 * audit_logs.timestamp is the time of the writing transaction's start, so a
 * transaction that commits later can insert an event older than the cursor.
 * The export therefore leaves out events younger than `lagSeconds`; set it
 * above the longest transaction (statement_timeout), or events can be missed.
 * The table is append-only (trigger audit_logs_no_update), so an exported
 * event never changes.
 */

export interface AuditEvent {
  id: string; eventId: string; micros: string; timestamp: string; eventType: string; nexusId: string | null; clientId: string | null;
  actor: string | null; ipAddress: string | null; userAgent: string | null; bankCustomerRef: string | null; details: Record<string, unknown>;
}

export interface Runner { query: (text: string, values?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }> }

/** Opaque position after the last exported event: `<microseconds since 1970>|<id>`. */
export type AuditCursor = string;

const CURSOR = /^(\d{1,17})\|([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;

export function parseCursor(cursor: string | undefined): { micros: string; id: string } | null {
  if (!cursor) return null;
  const m = CURSOR.exec(cursor.trim());
  if (!m) throw new Error('cursor must be <microseconds>|<uuid>, as printed by the previous export');
  return { micros: m[1], id: m[2] };
}

/** ISO 8601 with microseconds from microseconds since the epoch (exact, no Date rounding). */
function isoMicros(micros: string): string {
  const us = BigInt(micros);
  return `${new Date(Number(us / 1000n)).toISOString().slice(0, 19)}.${String(us % 1_000_000n).padStart(6, '0')}Z`;
}

export async function exportAuditEvents(db: Runner, options: { after?: AuditCursor; limit?: number; lagSeconds?: number; clientId?: string } = {}):
  Promise<{ events: AuditEvent[]; next: AuditCursor | null }> {
  const after = parseCursor(options.after);
  const limit = Math.min(Math.max(options.limit ?? 1000, 1), 10_000);
  const lag = Math.max(options.lagSeconds ?? 60, 0);
  // Integer microseconds since the epoch, so the cursor compares exactly
  // whatever the driver does with timestamps.
  const rows = await db.query(
    `SELECT id::text, event_id::text, (extract(epoch FROM timestamp) * 1000000)::bigint::text AS us, event_type, nexus_id, client_id, actor,
            host(ip_address) AS ip, user_agent, bank_customer_id, details
       FROM audit_logs
      WHERE timestamp <= now() - make_interval(secs => $1)
        AND ($2::bigint IS NULL OR (timestamp, id) > (to_timestamp($2::bigint / 1000000.0), $3::uuid))
        AND ($4::text IS NULL OR client_id = $4)
      ORDER BY timestamp, id
      LIMIT $5`,
    [lag, after?.micros ?? null, after?.id ?? null, options.clientId ?? null, limit]);
  const events = rows.rows.map((r): AuditEvent => ({
    id: String(r.id), eventId: String(r.event_id), micros: String(r.us), timestamp: isoMicros(String(r.us)), eventType: String(r.event_type),
    nexusId: (r.nexus_id as string | null) ?? null, clientId: (r.client_id as string | null) ?? null, actor: (r.actor as string | null) ?? null,
    ipAddress: (r.ip as string | null) ?? null, userAgent: (r.user_agent as string | null) ?? null, bankCustomerRef: (r.bank_customer_id as string | null) ?? null,
    details: (r.details as Record<string, unknown>) ?? {},
  }));
  const last = events.at(-1);
  return { events, next: last ? `${last.micros}|${last.id}` : (options.after ?? null) };
}

/** Events a security team looks at first. Everything else is informational. */
const HIGH = /(_failed|_invalid|_locked|_rejected|_revoked|_suspended|integrity|forg|replay|signature_invalid|admin_login_failed|limit_exceeded)/;

export function severity(eventType: string): number {
  return HIGH.test(eventType) ? 7 : 3;
}

/** One JSON line with Elastic Common Schema names. */
export function toJsonLine(e: AuditEvent, product = { vendor: 'NEXIS', name: 'NEXUS-SIGN', version: '' }): string {
  return JSON.stringify({
    '@timestamp': e.timestamp,
    event: { id: e.eventId, action: e.eventType, kind: 'event', category: ['iam'], severity: severity(e.eventType), dataset: 'nexus_sign.audit' },
    observer: { vendor: product.vendor, product: product.name, version: product.version || undefined },
    user: e.actor ? { name: e.actor } : undefined,
    source: e.ipAddress ? { ip: e.ipAddress } : undefined,
    user_agent: e.userAgent ? { original: e.userAgent } : undefined,
    nexus_sign: { audit_id: e.id, nexus_id: e.nexusId, client_id: e.clientId, bank_customer_ref: e.bankCustomerRef, details: e.details },
  });
}

const cefHeader = (v: string) => v.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]/g, ' ');
const cefValue = (v: string) => v.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r\n|\r|\n/g, '\\n');

/** One ArcSight CEF line (CEF:0). Header fields escape \ and |, extension values \ and = and line breaks. */
export function toCef(e: AuditEvent, product = { vendor: 'NEXIS', name: 'NEXUS-SIGN', version: '' }): string {
  const ext: Array<[string, string | null]> = [
    ['rt', String(Date.parse(e.timestamp))],
    ['act', e.eventType],
    ['suser', e.actor],
    ['src', e.ipAddress],
    ['requestClientApplication', e.userAgent],
    ['externalId', e.eventId],
    ['cs1Label', 'nexusId'], ['cs1', e.nexusId],
    ['cs2Label', 'clientId'], ['cs2', e.clientId],
    ['cs3Label', 'auditId'], ['cs3', e.id],
    ['msg', JSON.stringify(e.details)],
  ];
  const extension = ext.filter(([, v]) => v !== null && v !== '').map(([k, v]) => `${k}=${cefValue(v as string)}`).join(' ');
  return `CEF:0|${cefHeader(product.vendor)}|${cefHeader(product.name)}|${cefHeader(product.version)}|${cefHeader(e.eventType)}|${cefHeader(e.eventType)}|${severity(e.eventType)}|${extension}`;
}
