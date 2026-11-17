import { pool } from '../db/pool';
import { NotFoundError } from './errors';

export interface AuditLogFilter {
  nexusId?: string;
  eventType?: string;
  limit: number;
  before?: Date;
  /** Bank scope of the admin; null for a platform operator. */
  clientId?: string | null;
}

export interface AuditLogRow {
  id: string;
  eventId: string;
  timestamp: Date;
  eventType: string;
  nexusId: string | null;
  bankCustomerRef: string | null;
  details: Record<string, unknown>;
  ipAddress: string | null;
  clientId: string | null;
  actor: string | null;
}

export async function listAuditLogs(filter: AuditLogFilter): Promise<AuditLogRow[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (filter.nexusId) {
    params.push(filter.nexusId);
    conditions.push(`nexus_id = $${params.length}`);
  }
  if (filter.eventType) {
    params.push(filter.eventType);
    conditions.push(`event_type = $${params.length}`);
  }
  if (filter.before) {
    params.push(filter.before);
    conditions.push(`"timestamp" < $${params.length}`);
  }
  if (filter.clientId) {
    params.push(filter.clientId);
    conditions.push(`client_id = $${params.length}`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  params.push(filter.limit);

  const result = await pool.query<{
    id: string;
    event_id: string;
    timestamp: Date;
    event_type: string;
    nexus_id: string | null;
    bank_customer_id: string | null;
    details: Record<string, unknown>;
    ip_address: string | null;
    client_id: string | null;
    actor: string | null;
  }>(
    `SELECT id, event_id, "timestamp", event_type, nexus_id, bank_customer_id, details, ip_address, client_id, actor
     FROM audit_logs
     ${whereClause}
     ORDER BY "timestamp" DESC
     LIMIT $${params.length}`,
    params,
  );

  return result.rows.map((row) => ({
    id: row.id,
    eventId: row.event_id,
    timestamp: row.timestamp,
    eventType: row.event_type,
    nexusId: row.nexus_id,
    bankCustomerRef: row.bank_customer_id,
    details: row.details,
    ipAddress: row.ip_address,
    clientId: row.client_id,
    actor: row.actor,
  }));
}

export interface WebhookDeliveryRow {
  id: string;
  eventId: string;
  clientId: string;
  eventType: string;
  status: string;
  retryCount: number;
  lastError: string | null;
  createdAt: Date;
  deliveredAt: Date | null;
}

export async function listWebhookDeliveries(limit: number, statusFilter?: string, clientId?: string | null): Promise<WebhookDeliveryRow[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];
  if (clientId) {
    params.push(clientId);
    conditions.push(`client_id = $${params.length}`);
  }
  if (statusFilter) {
    params.push(statusFilter);
    conditions.push(`status = $${params.length}`);
  }
  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  params.push(limit);

  const result = await pool.query<{
    id: string;
    event_id: string;
    client_id: string;
    event_type: string;
    status: string;
    retry_count: number;
    last_error: string | null;
    created_at: Date;
    delivered_at: Date | null;
  }>(
    `SELECT id, event_id, client_id, event_type, status, retry_count, last_error, created_at, delivered_at
     FROM webhook_deliveries
     ${whereClause}
     ORDER BY created_at DESC
     LIMIT $${params.length}`,
    params,
  );

  return result.rows.map((row) => ({
    id: row.id,
    eventId: row.event_id,
    clientId: row.client_id,
    eventType: row.event_type,
    status: row.status,
    retryCount: row.retry_count,
    lastError: row.last_error,
    createdAt: row.created_at,
    deliveredAt: row.delivered_at,
  }));
}

export interface DashboardStats {
  identitiesByStatus: Record<string, number>;
  authorizationsLast24hByStatus: Record<string, number>;
  webhookDeliveriesLast24hByStatus: Record<string, number>;
}

/** Counts for the dashboard; `clientId` limits them to one bank. */
export async function getDashboardStats(clientId: string | null = null): Promise<DashboardStats> {
  const scope = [clientId];
  const [identityRows, authorizationRows, webhookRows] = await Promise.all([
    pool.query<{ status: string; count: string }>(`SELECT status, count(*) FROM nexus_identities WHERE ($1::text IS NULL OR client_id = $1) GROUP BY status`, scope),
    pool.query<{ status: string; count: string }>(
      `SELECT state AS status, count(*) FROM authorization_requests WHERE created_at > now() - interval '24 hours' AND ($1::text IS NULL OR client_id = $1) GROUP BY state`, scope,
    ),
    pool.query<{ status: string; count: string }>(
      `SELECT status, count(*) FROM webhook_deliveries WHERE created_at > now() - interval '24 hours' AND ($1::text IS NULL OR client_id = $1) GROUP BY status`, scope,
    ),
  ]);

  const toRecord = (rows: { status: string; count: string }[]): Record<string, number> =>
    Object.fromEntries(rows.map((row) => [row.status, Number(row.count)]));

  return {
    identitiesByStatus: toRecord(identityRows.rows),
    authorizationsLast24hByStatus: toRecord(authorizationRows.rows),
    webhookDeliveriesLast24hByStatus: toRecord(webhookRows.rows),
  };
}

/**
 * Sends a FAILED webhook delivery again (finding A2-08): the row returns to
 * PENDING with its retry budget reset, keeping its event ID, so the bank's
 * deduplication still applies. A bank-scoped admin reaches only that bank's
 * deliveries.
 */
export async function redeliverWebhook(id: string, clientId: string | null): Promise<{ eventId: string; clientId: string; eventType: string }> {
  const result = await pool.query<{ event_id: string; client_id: string; event_type: string }>(
    `UPDATE webhook_deliveries SET status = 'PENDING', retry_count = 0, next_attempt_at = now(), last_error = NULL, last_http_status = NULL
     WHERE id = $1 AND status = 'FAILED' AND ($2::text IS NULL OR client_id = $2)
     RETURNING event_id, client_id, event_type`, [id, clientId]);
  const row = result.rows[0];
  if (!row) throw new NotFoundError('No failed webhook delivery with this ID');
  return { eventId: row.event_id, clientId: row.client_id, eventType: row.event_type };
}
