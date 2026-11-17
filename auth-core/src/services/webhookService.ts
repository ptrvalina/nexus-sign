import { createHmac, randomUUID } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { LookupAddress } from 'node:dns';
import type { LookupFunction } from 'node:net';
import type { PoolClient } from 'pg';
import { pool } from '../db/pool';
import { getWebhookDestination, hasWebhookDestination } from './clientService';
import { webhookDeliveryOutcomes } from '../observability/metrics';
import { assertWebhookUrlAllowed, type AllowedWebhookTarget } from './webhookUrlPolicy';

/**
 * Outbound notifications to the bank's webhook endpoint.
 *
 * Events are queued in PostgreSQL (`webhook_deliveries`) in the same
 * transaction as the state change they describe, and delivered by a polling
 * worker with retries. The queue is durable across restarts and each event
 * has a unique `eventId` the receiver uses for deduplication.
 *
 * Request format:
 *   X-NEXUS-SIGN-Event-Id:  <eventId>
 *   X-NEXUS-SIGN-Timestamp: <unix seconds>
 *   X-NEXUS-SIGN-Signature: v1=<hex HMAC-SHA256(webhookSecret, "<timestamp>.<raw body>")>
 * During the overlap after a rotation of the webhook secret (finding A2-08)
 * the header carries one entry per secret, the previous one first:
 *   X-NEXUS-SIGN-Signature: v1=<HMAC with the previous secret>,v1=<HMAC with the new secret>
 * The receiver accepts the request when any v1 entry matches its secret.
 * The receiver recomputes the HMAC over the exact bytes received, compares in
 * constant time and rejects timestamps outside its tolerance window.
 */
const RETRY_DELAYS_SECONDS = [1, 5, 30, 300, 1800];
const BATCH_SIZE = 20;
const DELIVERY_TIMEOUT_MS = 10_000;
const CLAIM_LEASE_SECONDS = 30; // must exceed DELIVERY_TIMEOUT_MS

type Runner = Pick<PoolClient, 'query'>;

export async function enqueueWebhook(clientId: string, eventType: string, payload: Record<string, unknown>, runner: Runner = pool): Promise<void> {
  if (!(await hasWebhookDestination(clientId, runner))) return; // no webhook configured for this bank client
  await runner.query(
    `INSERT INTO webhook_deliveries (event_id, client_id, event_type, payload) VALUES ($1, $2, $3, $4)`,
    [randomUUID(), clientId, eventType, JSON.stringify(payload)],
  );
}

function webhookSignature(timestamp: string, rawBody: string, secret: string): string {
  return `v1=${createHmac('sha256', secret).update(`${timestamp}.${rawBody}`, 'utf8').digest('hex')}`;
}

/** The X-NEXUS-SIGN-Signature value: the previous secret's entry first while it overlaps. */
export function webhookSignatureHeader(timestamp: string, rawBody: string, secret: string, previousSecret?: string): string {
  const current = webhookSignature(timestamp, rawBody, secret);
  return previousSecret ? `${webhookSignature(timestamp, rawBody, previousSecret)},${current}` : current;
}

interface PendingDelivery {
  id: string;
  event_id: string;
  client_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  retry_count: number;
}

/**
 * Claims due rows by moving next_attempt_at into a short lease, in a
 * transaction held only for that UPDATE and never across the network call.
 * If the process dies mid-delivery the lease expires and the row is retried.
 */
async function claimBatch(): Promise<PendingDelivery[]> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query<PendingDelivery>(
      `SELECT id, event_id, client_id, event_type, payload, retry_count
       FROM webhook_deliveries
       WHERE status = 'PENDING' AND next_attempt_at <= now()
       ORDER BY next_attempt_at
       LIMIT $1
       FOR UPDATE SKIP LOCKED`,
      [BATCH_SIZE],
    );
    if (result.rows.length > 0) {
      await client.query(
        `UPDATE webhook_deliveries SET next_attempt_at = now() + ($2 || ' seconds')::interval WHERE id = ANY($1::uuid[])`,
        [result.rows.map((row) => row.id), CLAIM_LEASE_SECONDS],
      );
    }
    await client.query('COMMIT');
    return result.rows;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/** Delivers one batch of due webhooks; called periodically by src/workers/webhookWorker.ts. */
export async function deliverPendingWebhooks(): Promise<void> {
  const batch = await claimBatch();
  await Promise.all(batch.map((row) => attemptDelivery(row)));
}

async function attemptDelivery(row: PendingDelivery): Promise<void> {
  let destination: Awaited<ReturnType<typeof getWebhookDestination>>;
  try {
    destination = await getWebhookDestination(row.client_id);
  } catch {
    // Most often a changed WEBHOOK_SECRET_ENCRYPTION_KEY. Counted as a failed
    // attempt so the row reaches FAILED instead of being re-claimed forever.
    await scheduleRetry(row, 'Webhook secret could not be decrypted', null);
    return;
  }
  if (!destination) {
    await pool.query(`UPDATE webhook_deliveries SET status = 'FAILED', last_error = $2 WHERE id = $1`,
      [row.id, 'No webhook destination configured at delivery time']);
    webhookDeliveryOutcomes.inc({ outcome: 'failed' });
    return;
  }

  const body = JSON.stringify({ eventId: row.event_id, eventType: row.event_type, ...row.payload });
  const timestamp = Math.floor(Date.now() / 1000).toString();
  let status: number | null = null;
  try {
    const target = await assertWebhookUrlAllowed(destination.webhookUrl);
    status = await post(target, body, {
      'Content-Type': 'application/json',
      'X-NEXUS-SIGN-Event-Id': row.event_id,
      'X-NEXUS-SIGN-Timestamp': timestamp,
      'X-NEXUS-SIGN-Signature': webhookSignatureHeader(timestamp, body, destination.webhookSecret, destination.previousWebhookSecret),
    });
    if (status >= 200 && status < 300) {
      await pool.query(`UPDATE webhook_deliveries SET status = 'DELIVERED', delivered_at = now(), last_http_status = $2 WHERE id = $1`, [row.id, status]);
      webhookDeliveryOutcomes.inc({ outcome: 'delivered' });
      return;
    }
    await scheduleRetry(row, `HTTP ${status}`, status);
  } catch (error) {
    await scheduleRetry(row, error instanceof Error ? error.message : 'Unknown delivery error', status);
  }
}

/** A DNS lookup that always answers with the address vetted by the URL
 * policy, so the connection cannot be redirected by a second resolution. */
export function pinnedLookup(target: Pick<AllowedWebhookTarget, 'address' | 'family'>): LookupFunction {
  // Node 20+ connects with autoSelectFamily and then asks for every address
  // ({ all: true }); answering with a single address fails the connection.
  return (_hostname, options, callback) => {
    if (options.all) {
      (callback as unknown as (error: null, addresses: LookupAddress[]) => void)(null, [{ address: target.address, family: target.family }]);
      return;
    }
    callback(null, target.address, target.family);
  };
}

/** POSTs to the vetted address only (no DNS lookup at connect time, no redirects). */
function post(target: AllowedWebhookTarget, body: string, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const client = target.url.protocol === 'https:' ? https : http;
    const request = client.request(target.url, {
      method: 'POST',
      headers: { ...headers, 'Content-Length': Buffer.byteLength(body) },
      timeout: DELIVERY_TIMEOUT_MS,
      lookup: pinnedLookup(target),
    }, (response) => {
      response.resume(); // the response body is not used
      resolve(response.statusCode ?? 0);
    });
    request.on('timeout', () => request.destroy(new Error('Webhook delivery timed out')));
    request.on('error', reject);
    request.end(body);
  });
}

async function scheduleRetry(row: PendingDelivery, errorMessage: string, httpStatus: number | null): Promise<void> {
  const retryCount = row.retry_count + 1;
  if (retryCount > RETRY_DELAYS_SECONDS.length) {
    await pool.query(
      `UPDATE webhook_deliveries SET status = 'FAILED', retry_count = $2, last_error = $3, last_http_status = $4 WHERE id = $1`,
      [row.id, retryCount, errorMessage, httpStatus]);
    webhookDeliveryOutcomes.inc({ outcome: 'failed' });
    return;
  }
  // Retry n waits RETRY_DELAYS_SECONDS[n-1]: 1 s, 5 s, 30 s, 5 min, 30 min.
  await pool.query(
    `UPDATE webhook_deliveries
     SET retry_count = $2, next_attempt_at = now() + ($3 || ' seconds')::interval, last_error = $4, last_http_status = $5
     WHERE id = $1`,
    [row.id, retryCount, RETRY_DELAYS_SECONDS[retryCount - 1], errorMessage, httpStatus]);
  webhookDeliveryOutcomes.inc({ outcome: 'retried' });
}
