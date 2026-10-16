import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { pool } from '../db/pool';
import type { AuditEventType } from '../types';
import { currentRequestContext } from './requestContext';

export interface AuditContext {
  nexusId?: string;
  bankCustomerRef?: string;
  /** Bank the event belongs to; derived from `nexusId` when omitted. */
  clientId?: string;
  ipAddress?: string;
  userAgent?: string;
  /** Operator or system that performed the action (admin username, bank client). */
  actor?: string;
}

/**
 * Records a single audit event. Every security-relevant state change must
 * have a matching call here; a missing audit call is a defect.
 *
 * Source address, user agent, actor and bank default to the current HTTP
 * request's (requestContext.ts). The audit table is append-only (database
 * trigger). Pass `client` when running inside a transaction so the state
 * change and its audit record commit or roll back together.
 */
export async function recordAuditEvent(
  eventType: AuditEventType,
  context: AuditContext,
  details: Record<string, unknown> = {},
  client?: PoolClient,
): Promise<void> {
  const request = currentRequestContext();
  const actor = context.actor ?? request?.actor ?? null;
  const runner = client ?? pool;
  await runner.query(
    `INSERT INTO audit_logs (event_id, event_type, nexus_id, bank_customer_id, details, ip_address, user_agent, actor, client_id)
     VALUES ($1, $2, $3::varchar, $4, $5, $6, $7, $8,
             COALESCE($9::text, (SELECT client_id FROM nexus_identities WHERE nexus_id = $3::varchar)))`,
    [
      randomUUID(),
      eventType,
      context.nexusId ?? null,
      context.bankCustomerRef ?? null,
      JSON.stringify({ ...details, ...(context.nexusId ? { nexusId: context.nexusId } : {}), ...(actor ? { actor } : {}) }),
      context.ipAddress ?? request?.ipAddress ?? null,
      context.userAgent ?? request?.userAgent ?? null,
      actor,
      context.clientId ?? request?.clientId ?? null,
    ],
  );
}
