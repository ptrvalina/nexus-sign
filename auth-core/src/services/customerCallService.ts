import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { redis } from '../db/redis';
import { env } from '../config/env';
import { recordAuditEvent } from './auditService';
import { enqueueWebhook } from './webhookService';
import { displayTextViolation } from './canonicalAuthorization';
import { ConflictError, ForbiddenError, NotFoundError, ValidationError } from './errors';
import {
  appendSignal, callKeys, iceServersFor, readSignals, validateSignal, type CallRole, type IceServer, type Signal,
} from './verificationCall';

/**
 * Calls the customer starts from the bank's app to talk to the bank
 * (presentation page 12), outside a payment check. Lifecycle (migration 030,
 * enforced by the database):
 *
 *   WAITING ──answer──▶ CONNECTED ──end / max duration / revocation──▶ ENDED
 *      ├─ customer cancels ─▶ CANCELLED
 *      └─ no operator within CUSTOMER_CALL_WAIT_SECONDS, or the device or
 *         identity is no longer active ─▶ MISSED
 *
 * Who may do what:
 *   - an ACTIVE device of an ACTIVE NEXUS ID asks for a call on a channel the
 *     bank enabled (bank_clients.customer_call_channels); one open call per
 *     NEXUS ID;
 *   - an operator of the same bank answers it from the console queue; the
 *     first to answer holds it (row update, not a race on Redis);
 *   - only the device that asked and the operator who answered exchange
 *     signals; either ends the call.
 *
 * The bank is told by webhook at each step (customer_call.requested,
 * .answered, .ended). Signalling is the WebRTC relay of verification calls
 * (keys `ccall:{callId}`); Auth Core never receives media and records
 * nothing of it. The row is the record of the call: who, which device, who
 * answered, when, how it ended.
 */

export type CustomerCallState = 'WAITING' | 'CONNECTED' | 'ENDED' | 'CANCELLED' | 'MISSED';
export type CallChannel = 'AUDIO' | 'VIDEO';

export interface CustomerCall {
  callId: string; nexusId: string; credentialId: string; channel: CallChannel; topic: string; conversationId: string | null;
  state: CustomerCallState; operator: string | null; createdAt: string; expiresAt: string; answeredAt: string | null;
  endedAt: string | null; endedBy: string | null; endReason: string | null;
}

interface CallRow {
  call_id: string; client_id: string; nexus_id: string; credential_id: string; channel: CallChannel; topic: string; conversation_id: string | null;
  state: CustomerCallState; operator: string | null; expires_at: Date; created_at: Date; answered_at: Date | null; ended_at: Date | null;
  ended_by: string | null; end_reason: string | null;
}

const iso = (d: Date | null) => (d ? new Date(d).toISOString() : null);
const toCall = (r: CallRow): CustomerCall => ({
  callId: r.call_id, nexusId: r.nexus_id, credentialId: r.credential_id, channel: r.channel, topic: r.topic, conversationId: r.conversation_id,
  state: r.state, operator: r.operator, createdAt: iso(r.created_at)!, expiresAt: iso(r.expires_at)!, answeredAt: iso(r.answered_at),
  endedAt: iso(r.ended_at), endedBy: r.ended_by, endReason: r.end_reason,
});

export interface CallDevice { clientId: string; nexusId: string; credentialId: string }
export interface CallOperator { username: string; clientId: string | null }

const OPEN: ReadonlySet<CustomerCallState> = new Set(['WAITING', 'CONNECTED']);

/** What the bank is told; never the topic text beyond what the customer typed, never media. */
function webhookPayload(r: CallRow): Record<string, unknown> {
  return {
    callId: r.call_id, nexusId: r.nexus_id, credentialId: r.credential_id, channel: r.channel, topic: r.topic, conversationId: r.conversation_id,
    state: r.state, operator: r.operator, createdAt: iso(r.created_at), answeredAt: iso(r.answered_at), endedAt: iso(r.ended_at),
    endedBy: r.ended_by, endReason: r.end_reason,
    durationSeconds: r.answered_at && r.ended_at ? Math.round((new Date(r.ended_at).getTime() - new Date(r.answered_at).getTime()) / 1000) : null,
  };
}

/** Ends an open call in the transaction `tx` (row locked by the caller). */
async function finish(tx: PoolClient, r: CallRow, by: string, reason: string): Promise<CallRow> {
  const to: CustomerCallState = r.state === 'CONNECTED' ? 'ENDED' : by.startsWith('credential:') && reason === 'cancelled' ? 'CANCELLED' : 'MISSED';
  const updated = (await tx.query<CallRow>(
    `UPDATE customer_calls SET state = $2, ended_at = now(), ended_by = $3, end_reason = $4 WHERE call_id = $1 RETURNING *`,
    [r.call_id, to, by, reason.slice(0, 64)])).rows[0];
  await recordAuditEvent('customer_call_ended', { nexusId: r.nexus_id, clientId: r.client_id, actor: by },
    { callId: r.call_id, from: r.state, to, reason }, tx);
  await enqueueWebhook(r.client_id, 'customer_call.ended', webhookPayload(updated), tx);
  return updated;
}

/** Why an open call can no longer go on, or null. */
async function closedReason(tx: Pick<PoolClient, 'query'>, r: CallRow): Promise<string | null> {
  if (Date.now() >= new Date(r.expires_at).getTime()) return r.state === 'WAITING' ? 'no_operator_answered' : 'max_duration';
  const live = await tx.query<{ credential: string; identity: string }>(
    `SELECT c.state AS credential, n.status AS identity FROM credentials c JOIN nexus_identities n ON n.nexus_id = c.nexus_id WHERE c.credential_id = $1`,
    [r.credential_id]);
  if (live.rows[0]?.credential !== 'ACTIVE') return 'credential_revoked';
  if (live.rows[0]?.identity !== 'ACTIVE') return 'identity_not_active';
  return null;
}

/** Closes the call in the database if its time is up or its device or identity is no longer active; relays one bye. */
async function settle(callId: string): Promise<CallRow> {
  const result = await withTransaction(async (tx) => {
    const r = (await tx.query<CallRow>(`SELECT * FROM customer_calls WHERE call_id = $1 FOR UPDATE`, [callId])).rows[0];
    if (!r) throw new NotFoundError('Call not found');
    if (!OPEN.has(r.state)) return { row: r, closedNow: null as string | null };
    const reason = await closedReason(tx, r);
    if (reason === null) return { row: r, closedNow: null };
    return { row: await finish(tx, r, 'system', reason), closedNow: reason };
  });
  if (result.closedNow) await serverBye(result.row, result.closedNow);
  return result.row;
}

async function serverBye(r: CallRow, reason: string): Promise<void> {
  if ((await redis.hsetnx(callKeys(r.call_id, 'ccall').state, 'closed', reason)) !== 1) return;
  await appendSignal('ccall', r.call_id, new Date(Math.max(Date.now(), new Date(r.expires_at).getTime())), 'server', 'bye', { reason }).catch(() => undefined);
}

function checkTopic(topic: string): string {
  const t = topic.normalize('NFC').trim();
  if (t.length === 0 || t.length > 200 || /[\r\n]/.test(t)) throw new ValidationError('A topic is one line of 1 to 200 characters');
  const violation = displayTextViolation(t);
  if (violation) throw new ValidationError(`The topic contains characters that are not shown safely (${violation})`);
  return t;
}

// --- The customer (device-signed requests) ---

export async function requestCustomerCall(device: CallDevice, input: { channel: CallChannel; topic: string; conversationId?: string | null }):
  Promise<{ call: CustomerCall; iceServers: IceServer[] }> {
  const topic = checkTopic(input.topic);
  const row = await withTransaction(async (tx) => {
    const ok = await tx.query<{ channels: string[]; identity: string; credential: string }>(
      `SELECT b.customer_call_channels AS channels, n.status AS identity, c.state AS credential
         FROM credentials c JOIN nexus_identities n ON n.nexus_id = c.nexus_id JOIN bank_clients b ON b.client_id = n.client_id
        WHERE c.credential_id = $1 AND c.nexus_id = $2 AND n.client_id = $3 FOR SHARE OF n`,
      [device.credentialId, device.nexusId, device.clientId]);
    const s = ok.rows[0];
    if (!s || s.credential !== 'ACTIVE' || s.identity !== 'ACTIVE') throw new ForbiddenError('An active device of an active NEXUS ID is required');
    if (!s.channels.includes(input.channel)) throw new ConflictError(`The bank does not take ${input.channel} calls from the app`, 'CALL_CHANNEL_NOT_ENABLED');
    if (input.conversationId) {
      const own = await tx.query(`SELECT 1 FROM conversations WHERE conversation_id = $1 AND nexus_id = $2 AND client_id = $3`, [input.conversationId, device.nexusId, device.clientId]);
      if (own.rowCount === 0) throw new NotFoundError('Conversation not found');
    }
    // An earlier call that ran out of time does not block a new one.
    const open = (await tx.query<CallRow>(`SELECT * FROM customer_calls WHERE nexus_id = $1 AND state IN ('WAITING','CONNECTED') FOR UPDATE`, [device.nexusId])).rows[0];
    if (open) {
      const reason = await closedReason(tx, open);
      if (reason === null) throw new ConflictError('A call with the bank is already open', 'CALL_ALREADY_OPEN');
      await finish(tx, open, 'system', reason);
    }
    const inserted = (await tx.query<CallRow>(
      `INSERT INTO customer_calls (call_id, client_id, nexus_id, credential_id, channel, topic, conversation_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8)) RETURNING *`,
      [randomUUID(), device.clientId, device.nexusId, device.credentialId, input.channel, topic, input.conversationId ?? null, env.CUSTOMER_CALL_WAIT_SECONDS])).rows[0];
    await recordAuditEvent('customer_call_requested', { nexusId: device.nexusId, clientId: device.clientId, actor: `credential:${device.credentialId}` },
      { callId: inserted.call_id, channel: input.channel }, tx);
    await enqueueWebhook(device.clientId, 'customer_call.requested', webhookPayload(inserted), tx);
    return inserted;
  });
  return { call: toCall(row), iceServers: iceServersFor(row.call_id, row.expires_at) };
}

async function ownCall(callId: string, device: CallDevice): Promise<CallRow> {
  const r = (await pool.query<CallRow>(`SELECT * FROM customer_calls WHERE call_id = $1`, [callId])).rows[0];
  // Only the device that asked; any other caller is told the call does not exist.
  if (!r || r.client_id !== device.clientId || r.nexus_id !== device.nexusId || r.credential_id !== device.credentialId) throw new NotFoundError('Call not found');
  return r;
}

export async function deviceCallState(callId: string, device: CallDevice): Promise<{ call: CustomerCall; iceServers: IceServer[] }> {
  await ownCall(callId, device);
  const r = await settle(callId);
  return { call: toCall(r), iceServers: OPEN.has(r.state) ? iceServersFor(r.call_id, r.expires_at) : [] };
}

export async function listDeviceCalls(device: CallDevice): Promise<CustomerCall[]> {
  const rows = await pool.query<CallRow>(`SELECT * FROM customer_calls WHERE nexus_id = $1 AND client_id = $2 ORDER BY created_at DESC LIMIT 50`, [device.nexusId, device.clientId]);
  return rows.rows.map(toCall);
}

function assertSignalling(r: CallRow, role: CallRole): void {
  if (!OPEN.has(r.state)) throw new ConflictError(`The call is ${r.state}`, 'CALL_NOT_OPEN');
  // The device may prepare its offer while it waits; the operator only after answering.
  if (role === 'operator' && r.state !== 'CONNECTED') throw new ConflictError('Answer the call first', 'CALL_NOT_WAITING');
}

export async function deviceSignal(callId: string, device: CallDevice, type: string, payload: unknown, messageId?: string) {
  await ownCall(callId, device);
  const r = await settle(callId);
  assertSignalling(r, 'device');
  return appendSignal('ccall', callId, r.expires_at, 'device', validateSignal(type, payload), payload, messageId);
}

export async function deviceSignals(callId: string, device: CallDevice, after: number, waitMs: number): Promise<{ signals: Signal[]; next: number }> {
  await ownCall(callId, device);
  return readSignals('ccall', callId, 'device', after, waitMs, async () => { await settle(callId); });
}

export async function deviceEnd(callId: string, device: CallDevice): Promise<CustomerCall> {
  await ownCall(callId, device);
  return endCall(callId, `credential:${device.credentialId}`, 'cancelled', 'device');
}

async function endCall(callId: string, by: string, reason: string, from: CallRole): Promise<CustomerCall> {
  const r = await withTransaction(async (tx) => {
    const row = (await tx.query<CallRow>(`SELECT * FROM customer_calls WHERE call_id = $1 FOR UPDATE`, [callId])).rows[0];
    if (!row) throw new NotFoundError('Call not found');
    if (!OPEN.has(row.state)) throw new ConflictError(`The call is ${row.state}`, 'CALL_NOT_OPEN');
    return finish(tx, row, by, row.state === 'CONNECTED' && reason === 'cancelled' ? 'hung_up' : reason);
  });
  await appendSignal('ccall', callId, new Date(Math.max(Date.now(), new Date(r.expires_at).getTime())), from, 'bye', { reason: r.end_reason })
    .catch((error: unknown) => { if (!(error instanceof ConflictError)) throw error; });
  return toCall(r);
}

// --- The bank's operators (console) ---

function operatorBank(operator: CallOperator): string {
  // A platform operator (no bank) is not the bank and does not talk to its customers.
  if (!operator.clientId) throw new NotFoundError('Call not found');
  return operator.clientId;
}

/** Calls waiting for an operator of this bank, and the calls this operator holds. Closes the ones that ran out of time. */
export async function operatorCallQueue(operator: CallOperator): Promise<CustomerCall[]> {
  const clientId = operatorBank(operator);
  const rows = await pool.query<CallRow>(
    `SELECT * FROM customer_calls WHERE client_id = $1 AND (state = 'WAITING' OR (state = 'CONNECTED' AND operator = $2)) ORDER BY created_at LIMIT 200`,
    [clientId, operator.username]);
  const calls: CustomerCall[] = [];
  for (const row of rows.rows) {
    const r = await settle(row.call_id);
    if (OPEN.has(r.state)) calls.push(toCall(r));
  }
  return calls;
}

export async function operatorAnswer(operator: CallOperator, callId: string): Promise<{ call: CustomerCall; iceServers: IceServer[] }> {
  const clientId = operatorBank(operator);
  const settled = await settle(callId);
  if (settled.client_id !== clientId) throw new NotFoundError('Call not found');
  const r = await withTransaction(async (tx) => {
    const answered = (await tx.query<CallRow>(
      `UPDATE customer_calls SET state = 'CONNECTED', operator = $3, answered_at = now(), expires_at = now() + make_interval(secs => $4)
        WHERE call_id = $1 AND client_id = $2 AND state = 'WAITING' AND expires_at > now() RETURNING *`,
      [callId, clientId, operator.username, env.CUSTOMER_CALL_MAX_SECONDS])).rows[0];
    if (!answered) {
      const current = (await tx.query<CallRow>(`SELECT * FROM customer_calls WHERE call_id = $1`, [callId])).rows[0];
      if (current?.state === 'CONNECTED' && current.operator === operator.username) return current; // a retry
      throw new ConflictError(current?.state === 'CONNECTED' ? 'Another operator answered the call' : `The call is ${current?.state ?? 'gone'}`, 'CALL_NOT_WAITING');
    }
    await recordAuditEvent('customer_call_answered', { nexusId: answered.nexus_id, clientId, actor: `admin:${operator.username}` }, { callId, channel: answered.channel }, tx);
    await enqueueWebhook(clientId, 'customer_call.answered', webhookPayload(answered), tx);
    return answered;
  });
  return { call: toCall(r), iceServers: iceServersFor(r.call_id, r.expires_at) };
}

async function heldCall(operator: CallOperator, callId: string): Promise<CallRow> {
  const clientId = operatorBank(operator);
  const r = await settle(callId);
  if (r.client_id !== clientId) throw new NotFoundError('Call not found');
  if (r.operator !== operator.username) throw new ForbiddenError('Answer the call before taking part in it');
  return r;
}

export async function operatorSignal(operator: CallOperator, callId: string, type: string, payload: unknown, messageId?: string) {
  const r = await heldCall(operator, callId);
  assertSignalling(r, 'operator');
  return appendSignal('ccall', callId, r.expires_at, 'operator', validateSignal(type, payload), payload, messageId);
}

export async function operatorSignals(operator: CallOperator, callId: string, after: number, waitMs: number): Promise<{ signals: Signal[]; next: number }> {
  await heldCall(operator, callId);
  return readSignals('ccall', callId, 'operator', after, waitMs, async () => { await settle(callId); });
}

export async function operatorEnd(operator: CallOperator, callId: string): Promise<CustomerCall> {
  await heldCall(operator, callId);
  return endCall(callId, `admin:${operator.username}`, 'operator_ended', 'operator');
}

// --- The bank (API) and housekeeping ---

export async function bankCall(clientId: string, callId: string): Promise<CustomerCall> {
  const r = (await pool.query<CallRow>(`SELECT client_id FROM customer_calls WHERE call_id = $1`, [callId])).rows[0];
  if (!r || r.client_id !== clientId) throw new NotFoundError('Call not found');
  return toCall(await settle(callId));
}

/** Closes open calls whose time is up or whose device or identity is no longer active (run by the expiry worker); returns how many. */
export async function expireCustomerCalls(limit = 100): Promise<number> {
  const due = await pool.query<{ call_id: string }>(
    `SELECT k.call_id FROM customer_calls k JOIN credentials c ON c.credential_id = k.credential_id JOIN nexus_identities n ON n.nexus_id = k.nexus_id
      WHERE k.state IN ('WAITING','CONNECTED') AND (k.expires_at <= now() OR c.state <> 'ACTIVE' OR n.status <> 'ACTIVE')
      ORDER BY k.expires_at LIMIT $1`, [limit]);
  let closed = 0;
  for (const { call_id } of due.rows) if (!OPEN.has((await settle(call_id)).state)) closed += 1;
  return closed;
}
