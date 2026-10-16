import { randomBytes, randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { env } from '../config/env';
import { pool, withTransaction } from '../db/pool';
import { pushDeliveryOutcomes } from '../observability/metrics';
import { recordAuditEvent } from './auditService';
import { getClientPushMode } from './clientService';
import { getNexusIdentityForClient } from './nexusIdentityService';
import { isValidPushReceipt, sealPushMessage, type PushCategory, type PushContent, type PushEnvelope } from './pushProtocol';
import { decryptPushKey } from './pushRegistrationService';
import type { ApnsEnvironment, PushProvider, PushSender, PushSendOutcome } from './pushProviders';
import { enqueueWebhook } from './webhookService';
import { ConflictError, ForbiddenError, NotFoundError, ValidationError } from './errors';

/**
 * Secure push messages: queued sealed for one device, delivered through APNs
 * or FCM by the push worker, confirmed by a receipt the device signs.
 *
 * Status: QUEUED (waiting for the provider) -> SENT (accepted by the
 * provider) -> DELIVERED (the device decrypted it and sent its receipt).
 * FAILED and EXPIRED are final. The bank learns the outcome through the
 * webhooks push.delivered, push.failed and, for authorization requests not
 * received within the plan's pushTimeoutSeconds, push.timeout.
 */

export type PushStatus = 'QUEUED' | 'SENT' | 'DELIVERED' | 'FAILED' | 'EXPIRED';
export type BankPushCategory = Exclude<PushCategory, 'AUTHORIZATION_REQUEST'>;

export interface PushMessageRecord {
  messageId: string;
  nexusId: string;
  credentialId: string | null;
  category: PushCategory;
  authorizationId: string | null;
  messageReference: string | null;
  status: PushStatus;
  provider: PushProvider | null;
  retryCount: number;
  lastError: string | null;
  createdAt: Date;
  sentAt: Date | null;
  deliveredAt: Date | null;
  expiresAt: Date;
}

export interface SendPushMessageInput {
  nexusId: string;
  category: BankPushCategory;
  title: string;
  body?: string;
  data?: Record<string, string>;
  ttlSeconds?: number;
  /** The bank's own ID for the message; a retry with the same reference returns the original message. */
  messageReference?: string;
}

type Runner = Pick<PoolClient, 'query'>;

const RETRY_DELAYS_SECONDS = [5, 30, 120, 600, 1800];
const BATCH_SIZE = 50;
const CLAIM_LEASE_SECONDS = 30;

const MESSAGE_COLUMNS = `message_id, nexus_id, credential_id, category, authorization_id, message_reference, status, provider,
  retry_count, last_error, created_at, sent_at, delivered_at, expires_at`;

interface MessageRow {
  message_id: string; nexus_id: string; credential_id: string | null; category: PushCategory; authorization_id: string | null;
  message_reference: string | null; status: PushStatus; provider: PushProvider | null; retry_count: number; last_error: string | null;
  created_at: Date; sent_at: Date | null; delivered_at: Date | null; expires_at: Date;
}

function mapMessage(row: MessageRow): PushMessageRecord {
  return {
    messageId: row.message_id, nexusId: row.nexus_id, credentialId: row.credential_id, category: row.category,
    authorizationId: row.authorization_id, messageReference: row.message_reference, status: row.status, provider: row.provider,
    retryCount: row.retry_count, lastError: row.last_error, createdAt: row.created_at, sentAt: row.sent_at,
    deliveredAt: row.delivered_at, expiresAt: row.expires_at,
  };
}

function assertPushDeliveryEnabled(): void {
  if (!env.PUSH_DELIVERY_ENABLED) throw new ConflictError('Secure push delivery is not enabled on this Auth Core deployment');
}

interface ActiveRegistration { credentialId: string; provider: PushProvider; pushKeyEncrypted: string }

/** The registration of the identity's active credential, or of `credentialId` if given. */
async function activeRegistration(runner: Runner, nexusId: string, credentialId?: string): Promise<ActiveRegistration | null> {
  const result = await runner.query<{ credential_id: string; provider: PushProvider; push_key_encrypted: string }>(
    `SELECT r.credential_id, r.provider, r.push_key_encrypted
     FROM push_registrations r JOIN credentials c ON c.credential_id = r.credential_id
     WHERE c.nexus_id = $1 AND c.state = 'ACTIVE' AND r.status = 'ACTIVE' AND ($2::uuid IS NULL OR c.credential_id = $2::uuid)
     ORDER BY c.activated_at DESC NULLS LAST LIMIT 1`,
    [nexusId, credentialId ?? null]);
  const row = result.rows[0];
  return row ? { credentialId: row.credential_id, provider: row.provider, pushKeyEncrypted: row.push_key_encrypted } : null;
}

interface QueueRequest {
  clientId: string;
  nexusId: string;
  category: PushCategory;
  authorizationId: string | null;
  messageReference: string | null;
  content: Omit<PushContent, 'v' | 'category' | 'authorizationId' | 'sentAt'>;
  expiresAt: Date;
  registration: ActiveRegistration;
  /** Delivered even though the credential is revoked (device replacement). */
  replacementNotice?: boolean;
}

/** The device's push key cannot be read (DEVICE_SECRET_ENCRYPTION_KEY changed or missing). */
class PushKeyUnavailableError extends Error {
  constructor() { super('PUSH_KEY_UNAVAILABLE'); this.name = 'PushKeyUnavailableError'; }
}

async function insertSealedMessage(runner: Runner, request: QueueRequest): Promise<PushMessageRecord> {
  const messageId = randomUUID();
  const content: PushContent = {
    v: 1,
    category: request.category,
    title: request.content.title,
    body: request.content.body,
    authorizationId: request.authorizationId,
    data: request.content.data,
    sentAt: new Date().toISOString(),
  };
  let pushKey: Buffer;
  try {
    pushKey = decryptPushKey(request.registration.pushKeyEncrypted, request.registration.credentialId);
  } catch {
    throw new PushKeyUnavailableError();
  }
  let envelope: PushEnvelope;
  try {
    envelope = sealPushMessage(pushKey, messageId, request.registration.credentialId, content);
  } catch (error) {
    throw new ValidationError(error instanceof Error ? error.message : 'Push message is not valid');
  } finally {
    pushKey.fill(0);
  }
  const inserted = await runner.query<MessageRow>(
    `INSERT INTO push_messages (message_id, client_id, nexus_id, credential_id, category, authorization_id, message_reference,
       envelope, status, provider, expires_at, replacement_notice)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'QUEUED', $9, $10, $11)
     RETURNING ${MESSAGE_COLUMNS}`,
    [messageId, request.clientId, request.nexusId, request.registration.credentialId, request.category, request.authorizationId,
      request.messageReference, JSON.stringify(envelope), request.registration.provider, request.expiresAt, request.replacementNotice ?? false]);
  return mapMessage(inserted.rows[0]);
}

/**
 * Seals a security notice for a device that is about to be replaced, in the
 * transaction that replaces it: the customer learns on the old phone that
 * their account was set up on another device. Delivered although the
 * credential is then revoked; the old registration is removed once it is
 * sent. Nothing is queued when the bank does not use secure push or the
 * device never registered for it (the bank is told by webhook either way).
 */
export async function queueReplacementNotice(tx: PoolClient, clientId: string, nexusId: string, credentialId: string): Promise<string | null> {
  if (!env.PUSH_DELIVERY_ENABLED) return null;
  const mode = await tx.query<{ push_mode: string }>(`SELECT push_mode FROM bank_clients WHERE client_id = $1`, [clientId]);
  if (mode.rows[0]?.push_mode !== 'NEXUS') return null;
  const registration = await activeRegistration(tx, nexusId, credentialId);
  if (!registration) return null;
  try {
    const message = await insertSealedMessage(tx, {
      clientId,
      nexusId,
      category: 'SECURITY',
      authorizationId: null,
      messageReference: null,
      content: { title: env.PUSH_REPLACEMENT_TITLE, body: env.PUSH_REPLACEMENT_BODY, data: { event: 'DEVICE_REPLACED' } },
      expiresAt: new Date(Date.now() + REPLACEMENT_NOTICE_TTL_SECONDS * 1000),
      registration,
      replacementNotice: true,
    });
    await recordAuditEvent('push_message_queued', { nexusId }, { messageId: message.messageId, category: 'SECURITY', credentialId, reason: 'DEVICE_REPLACED' }, tx);
    return message.messageId;
  } catch (error) {
    if (error instanceof PushKeyUnavailableError) return null;
    throw error;
  }
}

const REPLACEMENT_NOTICE_TTL_SECONDS = 24 * 60 * 60;

/** A message the bank sends to its customer (POST /v1/push-messages). */
export async function sendPushMessage(clientId: string, input: SendPushMessageInput): Promise<{ message: PushMessageRecord; replayed: boolean }> {
  assertPushDeliveryEnabled();
  if ((await getClientPushMode(clientId)) !== 'NEXUS') {
    throw new ForbiddenError('Push messages are available to bank clients in push mode NEXUS');
  }
  if (input.messageReference) {
    const replay = await findByReference(clientId, input.messageReference);
    if (replay) {
      if (replay.nexusId !== input.nexusId || replay.category !== input.category) {
        throw new ConflictError('messageReference is already used for a different message');
      }
      return { message: replay, replayed: true };
    }
  }
  const identity = await getNexusIdentityForClient(input.nexusId, clientId);
  if (identity.status !== 'ACTIVE') throw new ConflictError(`NEXUS ID is ${identity.status}`);
  const ttl = Math.min(input.ttlSeconds ?? env.PUSH_MESSAGE_TTL_SECONDS, env.PUSH_MESSAGE_TTL_SECONDS);

  try {
    return await withTransaction(async (tx) => {
      const registration = await activeRegistration(tx, input.nexusId);
      if (!registration) throw new ConflictError('No active push registration for this NEXUS ID; the app has not registered for push');
      const message = await insertSealedMessage(tx, {
        clientId,
        nexusId: input.nexusId,
        category: input.category,
        authorizationId: null,
        messageReference: input.messageReference ?? null,
        content: { title: input.title, body: input.body ?? '', data: input.data ?? {} },
        expiresAt: new Date(Date.now() + ttl * 1000),
        registration,
      });
      await recordAuditEvent('push_message_queued', { nexusId: input.nexusId },
        { messageId: message.messageId, category: input.category, credentialId: registration.credentialId }, tx);
      return { message, replayed: false };
    });
  } catch (error) {
    if (error instanceof PushKeyUnavailableError) {
      throw new ConflictError('The push key of this device cannot be read; the app must register for push again');
    }
    // A concurrent request with the same messageReference won the race.
    if (input.messageReference && isUniqueViolation(error)) {
      const replay = await findByReference(clientId, input.messageReference);
      if (replay && replay.nexusId === input.nexusId && replay.category === input.category) return { message: replay, replayed: true };
      throw new ConflictError('messageReference is already used for a different message');
    }
    throw error;
  }
}

export interface AuthorizationPushInput {
  clientId: string;
  nexusId: string;
  credentialId: string;
  authorizationId: string;
  expiresAt: Date;
  title?: string;
  body?: string;
}

/**
 * Queues the push for a new authorization, inside the transaction that
 * creates it, when the bank client is in push mode NEXUS. The text only
 * invites the customer to open the app: what is approved is always shown
 * from the signed bytes. Without a push registration the message is recorded
 * as FAILED and push.failed tells the bank to use another channel.
 */
export async function queueAuthorizationPush(tx: PoolClient, input: AuthorizationPushInput): Promise<PushMessageRecord | null> {
  if ((await getClientPushMode(input.clientId)) !== 'NEXUS') return null;
  // A push that cannot be sent never blocks the authorization: it is
  // recorded as FAILED and the bank uses another channel.
  if (!env.PUSH_DELIVERY_ENABLED) return recordUnsentAuthorizationPush(tx, input, 'PUSH_DELIVERY_DISABLED');
  const registration = await activeRegistration(tx, input.nexusId, input.credentialId);
  if (!registration) return recordUnsentAuthorizationPush(tx, input, 'NO_PUSH_REGISTRATION');
  try {
    return await insertSealedMessage(tx, {
      clientId: input.clientId,
      nexusId: input.nexusId,
      category: 'AUTHORIZATION_REQUEST',
      authorizationId: input.authorizationId,
      messageReference: null,
      content: { title: input.title ?? env.PUSH_AUTHORIZATION_TITLE, body: input.body ?? env.PUSH_AUTHORIZATION_BODY, data: {} },
      expiresAt: input.expiresAt,
      registration,
    });
  } catch (error) {
    if (error instanceof PushKeyUnavailableError) return recordUnsentAuthorizationPush(tx, input, 'PUSH_KEY_UNAVAILABLE');
    throw error;
  }
}

async function recordUnsentAuthorizationPush(tx: PoolClient, input: AuthorizationPushInput, reason: string): Promise<PushMessageRecord> {
  const messageId = randomUUID();
  const inserted = await tx.query<MessageRow>(
    `INSERT INTO push_messages (message_id, client_id, nexus_id, credential_id, category, authorization_id, status, expires_at, last_error)
     VALUES ($1, $2, $3, $4, 'AUTHORIZATION_REQUEST', $5, 'FAILED', $6, $7)
     RETURNING ${MESSAGE_COLUMNS}`,
    [messageId, input.clientId, input.nexusId, input.credentialId, input.authorizationId, input.expiresAt, reason]);
  await enqueueWebhook(input.clientId, 'push.failed',
    { messageId, nexusId: input.nexusId, category: 'AUTHORIZATION_REQUEST', authorizationId: input.authorizationId, reason }, tx);
  pushDeliveryOutcomes.inc({ provider: 'none', outcome: 'failed' });
  return mapMessage(inserted.rows[0]);
}

async function findByReference(clientId: string, messageReference: string): Promise<PushMessageRecord | null> {
  const result = await pool.query<MessageRow>(
    `SELECT ${MESSAGE_COLUMNS} FROM push_messages WHERE client_id = $1 AND message_reference = $2`, [clientId, messageReference]);
  return result.rows[0] ? mapMessage(result.rows[0]) : null;
}

export async function getPushMessageForClient(messageId: string, clientId: string): Promise<PushMessageRecord> {
  const result = await pool.query<MessageRow>(
    `SELECT ${MESSAGE_COLUMNS} FROM push_messages WHERE message_id = $1 AND client_id = $2`, [messageId, clientId]);
  if (!result.rows[0]) throw new NotFoundError(`Push message ${messageId} was not found`);
  return mapMessage(result.rows[0]);
}

/** The sealed envelope, for a device that opens the app before (or without) the push arriving. */
export async function getPushEnvelopeForDevice(messageId: string, credentialId: string): Promise<{ messageId: string; status: PushStatus; envelope: PushEnvelope }> {
  const result = await pool.query<{ message_id: string; status: PushStatus; envelope: string | null }>(
    `SELECT message_id, status, envelope FROM push_messages
     WHERE message_id = $1 AND credential_id = $2 AND envelope IS NOT NULL AND expires_at > now()`, [messageId, credentialId]);
  const row = result.rows[0];
  if (!row?.envelope) throw new NotFoundError(`Push message ${messageId} was not found`);
  return { messageId: row.message_id, status: row.status, envelope: JSON.parse(row.envelope) as PushEnvelope };
}

/**
 * The device decrypted the message and proves it with a receipt keyed by the
 * push key (pushProtocol.pushReceipt). Idempotent; the bank gets
 * push.delivered once. An unknown message and a wrong receipt get the same
 * answer.
 */
export async function recordPushReceipt(messageId: string, credentialId: string, receipt: string): Promise<void> {
  const registration = await pool.query<{ push_key_encrypted: string }>(
    `SELECT r.push_key_encrypted FROM push_registrations r JOIN credentials c ON c.credential_id = r.credential_id
     WHERE r.credential_id = $1 AND c.state = 'ACTIVE'`, [credentialId]);
  const stored = registration.rows[0]?.push_key_encrypted;
  // The same work with or without a registration, so the answer time does
  // not tell whether a credential has one.
  let pushKey: Buffer;
  try {
    pushKey = stored ? decryptPushKey(stored, credentialId) : randomBytes(32);
  } catch {
    pushKey = randomBytes(32);
  }
  let valid: boolean;
  try {
    valid = isValidPushReceipt(pushKey, messageId, credentialId, receipt) && Boolean(stored);
  } finally {
    pushKey.fill(0);
  }
  if (!valid) throw new NotFoundError(`Push message ${messageId} was not found`);

  await withTransaction(async (tx) => {
    const updated = await tx.query<{ client_id: string; nexus_id: string; category: PushCategory; authorization_id: string | null; delivered_at: Date; provider: PushProvider | null }>(
      `UPDATE push_messages SET status = 'DELIVERED', delivered_at = now()
       WHERE message_id = $1 AND credential_id = $2 AND status IN ('QUEUED', 'SENT')
       RETURNING client_id, nexus_id, category, authorization_id, delivered_at, provider`, [messageId, credentialId]);
    const row = updated.rows[0];
    if (row) {
      pushDeliveryOutcomes.inc({ provider: row.provider ?? 'none', outcome: 'delivered' });
      await enqueueWebhook(row.client_id, 'push.delivered', {
        messageId, nexusId: row.nexus_id, category: row.category, authorizationId: row.authorization_id, deliveredAt: row.delivered_at.toISOString(),
      }, tx);
      return;
    }
    const existing = await tx.query(`SELECT 1 FROM push_messages WHERE message_id = $1 AND credential_id = $2`, [messageId, credentialId]);
    if (!existing.rows[0]) throw new NotFoundError(`Push message ${messageId} was not found`);
  });
}

// --- Delivery (called by src/workers/pushWorker.ts) ---

interface PendingMessage {
  message_id: string; client_id: string; nexus_id: string; credential_id: string; category: PushCategory;
  authorization_id: string | null; envelope: string; retry_count: number; expires_at: Date;
  provider: PushProvider | null; device_token: string | null; apns_environment: ApnsEnvironment | null;
  registration_status: string | null; credential_state: string | null; replacement_notice: boolean;
}

async function claimBatch(): Promise<PendingMessage[]> {
  return withTransaction(async (tx) => {
    const result = await tx.query<PendingMessage>(
      `SELECT m.message_id, m.client_id, m.nexus_id, m.credential_id, m.category, m.authorization_id, m.envelope, m.retry_count, m.expires_at,
              r.provider, r.device_token, r.apns_environment, r.status AS registration_status, c.state AS credential_state,
              m.replacement_notice
       FROM push_messages m
       LEFT JOIN push_registrations r ON r.credential_id = m.credential_id
       LEFT JOIN credentials c ON c.credential_id = m.credential_id
       WHERE m.status = 'QUEUED' AND m.next_attempt_at <= now()
       ORDER BY m.next_attempt_at
       LIMIT $1
       FOR UPDATE OF m SKIP LOCKED`,
      [BATCH_SIZE]);
    if (result.rows.length > 0) {
      await tx.query(`UPDATE push_messages SET next_attempt_at = now() + ($2 || ' seconds')::interval WHERE message_id = ANY($1::uuid[])`,
        [result.rows.map((row) => row.message_id), CLAIM_LEASE_SECONDS]);
    }
    return result.rows;
  });
}

export type PushSenders = Partial<Record<PushProvider, PushSender>>;

/** Hands one batch of due messages to the providers. */
export async function deliverPendingPushMessages(senders: PushSenders): Promise<void> {
  const batch = await claimBatch();
  await Promise.all(batch.map((row) => attempt(row, senders)));
}

async function attempt(row: PendingMessage, senders: PushSenders): Promise<void> {
  if (row.expires_at.getTime() <= Date.now()) {
    await finish(row, 'EXPIRED', 'EXPIRED', null);
    return;
  }
  const reachable = row.credential_state === 'ACTIVE' || row.replacement_notice;
  if (!reachable || row.registration_status !== 'ACTIVE' || !row.provider || !row.device_token) {
    await finish(row, 'FAILED', 'NO_ACTIVE_REGISTRATION', null);
    return;
  }
  const sender = senders[row.provider];
  if (!sender) {
    await finish(row, 'FAILED', `PROVIDER_NOT_CONFIGURED ${row.provider}`, null);
    return;
  }
  let outcome: PushSendOutcome;
  try {
    outcome = await sender.send(
      { provider: row.provider, deviceToken: row.device_token, apnsEnvironment: row.apns_environment },
      {
        messageId: row.message_id,
        envelope: JSON.parse(row.envelope) as PushEnvelope,
        expiresAt: row.expires_at,
        // A newer authorization request replaces an older one on the device.
        collapseId: row.category === 'AUTHORIZATION_REQUEST' ? 'nexus-authorization' : null,
      });
  } catch (error) {
    outcome = { kind: 'retry', error: error instanceof Error ? error.message : 'Push send failed', httpStatus: null };
  }

  switch (outcome.kind) {
    case 'sent':
      await pool.query(
        `UPDATE push_messages SET status = 'SENT', sent_at = now(), provider_message_id = $2, last_http_status = $3, last_error = NULL
         WHERE message_id = $1 AND status = 'QUEUED'`,
        [row.message_id, outcome.providerMessageId, outcome.httpStatus]);
      pushDeliveryOutcomes.inc({ provider: row.provider, outcome: 'sent' });
      if (row.replacement_notice) await forgetReplacedRegistration(row.credential_id);
      return;
    case 'unregistered':
      await pool.query(
        `UPDATE push_registrations SET status = 'INVALID', invalidated_at = now(), last_error = $2, updated_at = now()
         WHERE credential_id = $1 AND device_token = $3`,
        [row.credential_id, outcome.error.slice(0, 256), row.device_token]);
      await finish(row, 'FAILED', `DEVICE_TOKEN_INVALID ${outcome.error}`, outcome.httpStatus);
      return;
    case 'rejected':
      await finish(row, 'FAILED', `REJECTED ${outcome.error}`, outcome.httpStatus);
      return;
    case 'retry':
      await scheduleRetry(row, outcome.error, outcome.httpStatus);
      return;
  }
}

async function scheduleRetry(row: PendingMessage, error: string, httpStatus: number | null): Promise<void> {
  const retryCount = row.retry_count + 1;
  const delay = RETRY_DELAYS_SECONDS[retryCount - 1];
  if (delay === undefined) {
    await finish(row, 'FAILED', `RETRIES_EXHAUSTED ${error}`, httpStatus, retryCount);
    return;
  }
  if (Date.now() + delay * 1000 >= row.expires_at.getTime()) {
    // The next attempt would come after the message expired.
    await finish(row, 'EXPIRED', `EXPIRED ${error}`, httpStatus, retryCount);
    return;
  }
  await pool.query(
    `UPDATE push_messages SET retry_count = $2, next_attempt_at = now() + ($3 || ' seconds')::interval, last_error = $4, last_http_status = $5
     WHERE message_id = $1 AND status = 'QUEUED'`,
    [row.message_id, retryCount, delay, error.slice(0, 256), httpStatus]);
  pushDeliveryOutcomes.inc({ provider: row.provider ?? 'none', outcome: 'retried' });
}

/** Final failure or expiry, reported to the bank in the same transaction. */
async function finish(row: PendingMessage, status: 'FAILED' | 'EXPIRED', reason: string, httpStatus: number | null, retryCount = row.retry_count): Promise<void> {
  await withTransaction(async (tx) => {
    const updated = await tx.query(
      `UPDATE push_messages SET status = $2, last_error = $3, last_http_status = $4, retry_count = $5
       WHERE message_id = $1 AND status = 'QUEUED'`,
      [row.message_id, status, reason.slice(0, 256), httpStatus, retryCount]);
    if (updated.rowCount !== 1) return; // a receipt or another worker finished it first
    await enqueueWebhook(row.client_id, 'push.failed', {
      messageId: row.message_id, nexusId: row.nexus_id, category: row.category, authorizationId: row.authorization_id,
      reason: status === 'EXPIRED' ? 'EXPIRED' : reason.split(' ')[0],
    }, tx);
  });
  pushDeliveryOutcomes.inc({ provider: row.provider ?? 'none', outcome: status === 'EXPIRED' ? 'expired' : 'failed' });
  if (row.replacement_notice) await forgetReplacedRegistration(row.credential_id);
}

/** A replaced device keeps its registration only until its notice is done. */
async function forgetReplacedRegistration(credentialId: string): Promise<void> {
  await pool.query(
    `DELETE FROM push_registrations r USING credentials c
     WHERE r.credential_id = $1 AND c.credential_id = r.credential_id AND c.state <> 'ACTIVE'`, [credentialId]);
}

/**
 * Authorization requests the provider accepted but the device has not
 * confirmed within the plan's pushTimeoutSeconds, while the customer could
 * still approve them. The bank decides what follows: escalate, offer the
 * offline code, or cancel.
 */
export async function reportPushTimeouts(): Promise<number> {
  return withTransaction(async (tx) => {
    const timedOut = await tx.query<{ message_id: string; client_id: string; nexus_id: string; authorization_id: string; sent_at: Date }>(
      `UPDATE push_messages m SET timeout_reported_at = now()
       FROM authorization_verification_plans p, authorization_requests a
       WHERE m.status = 'SENT' AND m.authorization_id IS NOT NULL AND m.timeout_reported_at IS NULL
         AND p.authorization_id = m.authorization_id AND a.authorization_id = m.authorization_id
         AND a.state = 'PENDING_USER' AND a.expires_at > now()
         AND p.current_step = 'PUSH' AND p.status = 'PENDING'
         AND m.sent_at + (p.push_timeout_seconds || ' seconds')::interval < now()
       RETURNING m.message_id, m.client_id, m.nexus_id, m.authorization_id, m.sent_at`);
    for (const row of timedOut.rows) {
      await enqueueWebhook(row.client_id, 'push.timeout',
        { messageId: row.message_id, nexusId: row.nexus_id, authorizationId: row.authorization_id, sentAt: row.sent_at.toISOString() }, tx);
    }
    return timedOut.rows.length;
  });
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && (error as { code?: string }).code === '23505';
}
