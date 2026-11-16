import { createHmac } from 'node:crypto';
import { pool, withTransaction } from '../db/pool';
import { redis } from '../db/redis';
import { env } from '../config/env';
import { recordAuditEvent } from './auditService';
import { ConflictError, ForbiddenError, GoneError, NotFoundError, ValidationError } from './errors';
import { getAuthorizationForClient } from './authorizationRecord';
import type { OperatorIdentity } from './adaptiveVerificationService';

/**
 * In-app audio and video calls between the customer's device and a bank
 * operator (ADR 0017). Auth Core relays the WebRTC signalling (SDP offer and
 * answer, ICE candidates) between the two parties of one open verification
 * session; media flows directly between them, or through the bank's TURN
 * server, encrypted with DTLS-SRTP by the WebRTC stacks. Auth Core never
 * receives media and records nothing of it.
 *
 * Who may take part:
 *   device    the enrolled device of the authorization (signed requests),
 *   operator  one admin-console operator of the same bank who claimed the
 *             session (password + TOTP login, role operator or higher).
 *
 * Signals live in Redis only for the life of the session.
 *
 * Signalling rules, enforced atomically in Redis (signal state machine):
 *   - only the device sends offers, only the operator answers; the device
 *     may send a new offer (ICE restart) only once its previous offer has
 *     been answered, so there is never more than one outstanding offer;
 *   - candidates follow the sender's own description (device: an offer,
 *     operator: an answer);
 *   - after a party's bye it sends nothing more;
 *   - a message may carry a client-chosen messageId; a repeated messageId
 *     (a retry after a lost response) returns the original seq and is not
 *     relayed twice. Replayed HTTP requests are refused before this point by
 *     the device request signature (one-time nonce) and the admin session.
 * When the session or its authorization is closed by anything (decision,
 * cancel, expiry, confirmation, credential revocation), the next read
 * relays one `bye` from `server` with the reason, so both parties end the
 * call even if the other side is gone.
 */
export type CallRole = 'device' | 'operator';
export type SignalSender = CallRole | 'server';
export const SIGNAL_TYPES = ['offer', 'answer', 'candidate', 'bye'] as const;
export type SignalType = typeof SIGNAL_TYPES[number];

const MAX_SDP_LENGTH = 16_384;
const MAX_CANDIDATE_LENGTH = 2_048;
const MAX_SIGNALS_PER_DIRECTION = 400;
const MAX_WAIT_MS = 20_000;
const POLL_STEP_MS = 250;

export interface Signal { seq: number; from: SignalSender; type: SignalType; payload: unknown; at: string }

export interface IceServer { urls: string[]; username?: string; credential?: string }

interface CallRow {
  session_id: string; authorization_id: string; client_id: string; nexus_id: string; channel: string; status: string;
  expires_at: Date; credential_id: string | null; auth_state: string; auth_expires_at: Date; credential_state: string | null;
}

// One hash tag per call: the keys of a call are in one Redis Cluster slot,
// as the append script needs.
const keys = (sessionId: string) => ({
  seq: `vcall:{${sessionId}}:seq`,
  operator: `vcall:{${sessionId}}:operator`,
  state: `vcall:{${sessionId}}:state`,
  inbox: (role: CallRole) => `vcall:{${sessionId}}:to:${role}`,
});

async function loadCall(sessionId: string): Promise<CallRow> {
  const result = await pool.query<CallRow>(
    `SELECT s.session_id, s.authorization_id, s.client_id, s.nexus_id, s.channel, s.status, s.expires_at,
            a.credential_id, a.state AS auth_state, a.expires_at AS auth_expires_at, c.state AS credential_state
     FROM verification_sessions s JOIN authorization_requests a ON a.authorization_id = s.authorization_id
     LEFT JOIN credentials c ON c.credential_id = a.credential_id
     WHERE s.session_id = $1`, [sessionId]);
  const row = result.rows[0];
  if (!row || (row.channel !== 'AUDIO' && row.channel !== 'VIDEO')) throw new NotFoundError('Verification session not found');
  return row;
}

/** Why the call can no longer go on, or null while it is open. */
function closedReason(row: CallRow, now = Date.now()): string | null {
  if (row.status !== 'IN_PROGRESS') return `session_${row.status.toLowerCase()}`;
  if (now >= row.expires_at.getTime()) return 'session_expired';
  if (row.auth_state !== 'PENDING_USER' || now >= row.auth_expires_at.getTime()) return 'authorization_closed';
  if (row.credential_state !== 'ACTIVE') return 'credential_revoked';
  return null;
}

function assertOpen(row: CallRow): void {
  const reason = closedReason(row);
  if (reason === null) return;
  // As before: a closed session is 409, an open one past its time 410.
  if (row.status !== 'IN_PROGRESS') throw new ConflictError(`Verification session is ${row.status}`);
  if (reason === 'session_expired') throw new GoneError('Verification session expired');
  if (reason === 'credential_revoked') throw new ConflictError('The device credential is revoked');
  throw new ConflictError('Authorization is no longer pending');
}

/** Milliseconds the call keys live: until the session expires, plus a minute
 * so the last signals (bye) can still be read. */
function keyLifetimeMs(row: CallRow): number {
  return Math.max(1_000, row.expires_at.getTime() - Date.now() + 60_000);
}

/**
 * STUN and TURN servers for one session. TURN credentials follow the TURN
 * REST convention supported by coturn (`use-auth-secret`): username
 * `<expiry>:<sessionId>`, password base64(HMAC-SHA1(secret, username)), so
 * they are valid only for this session's lifetime and nothing is stored.
 */
export function iceServersFor(sessionId: string, expiresAt: Date): IceServer[] {
  const servers: IceServer[] = [];
  if (env.WEBRTC_STUN_URLS.length > 0) servers.push({ urls: env.WEBRTC_STUN_URLS });
  if (env.WEBRTC_TURN_URLS.length > 0 && env.WEBRTC_TURN_SECRET) {
    const expiry = Math.floor(Math.min(expiresAt.getTime(), Date.now() + env.WEBRTC_TURN_CREDENTIAL_TTL_SECONDS * 1000) / 1000);
    const username = `${expiry}:${sessionId}`;
    servers.push({ urls: env.WEBRTC_TURN_URLS, username, credential: createHmac('sha1', env.WEBRTC_TURN_SECRET).update(username).digest('base64') });
  }
  return servers;
}

export interface DeviceContextForCall { clientId: string; nexusId: string; credentialId: string }

/** The device may join only the calls of its own authorizations. */
async function deviceCall(sessionId: string, device: DeviceContextForCall): Promise<CallRow> {
  const row = await loadCall(sessionId);
  if (row.client_id !== device.clientId || row.nexus_id !== device.nexusId || row.credential_id !== device.credentialId) {
    throw new NotFoundError('Verification session not found');
  }
  return row;
}

/** The operator may join only after claiming the call; one operator per call. */
async function operatorCall(sessionId: string, operator: OperatorIdentity): Promise<CallRow> {
  const row = await loadCall(sessionId);
  // Only operators of the customer's bank (audit finding A2-03): a platform
  // operator (clientId null) is not the bank and cannot verify its customers.
  if (operator.clientId === null || operator.clientId !== row.client_id) throw new NotFoundError('Verification session not found');
  return row;
}

export async function assertClaimedBy(sessionId: string, operator: OperatorIdentity): Promise<void> {
  const row = await operatorCall(sessionId, operator);
  const holder = await redis.get(keys(row.session_id).operator);
  if (holder !== operator.username) throw new ForbiddenError('Claim the call before taking part in it');
}

export async function deviceJoin(sessionId: string, device: DeviceContextForCall): Promise<Record<string, unknown>> {
  const row = await deviceCall(sessionId, device);
  assertOpen(row);
  const operator = await redis.get(keys(sessionId).operator);
  return { sessionId, channel: row.channel, expiresAt: row.expires_at.toISOString(), operatorJoined: operator !== null, iceServers: iceServersFor(sessionId, row.expires_at) };
}

/** Calls waiting for an operator, and the calls this operator holds. */
export async function listCalls(operator: OperatorIdentity): Promise<Record<string, unknown>[]> {
  const result = await pool.query<CallRow & { amount_minor: string; currency: string; beneficiary: Record<string, string>; transaction_reference: string; operation_type: string }>(
    `SELECT s.session_id, s.authorization_id, s.client_id, s.nexus_id, s.channel, s.status, s.expires_at,
            a.credential_id, a.state AS auth_state, a.expires_at AS auth_expires_at,
            a.amount_minor, a.currency, a.beneficiary, a.transaction_reference, a.operation_type
     FROM verification_sessions s
     JOIN authorization_requests a ON a.authorization_id = s.authorization_id
     JOIN bank_clients c ON c.client_id = s.client_id
     WHERE s.status = 'IN_PROGRESS' AND s.expires_at > now() AND a.state = 'PENDING_USER'
       AND s.channel = ANY(c.operator_verification_channels)
       AND s.client_id = $1
     ORDER BY s.created_at
     LIMIT 100`, [operator.clientId]);
  const calls: Record<string, unknown>[] = [];
  for (const row of result.rows) {
    const holder = await redis.get(keys(row.session_id).operator);
    if (holder !== null && holder !== operator.username) continue;
    calls.push({
      sessionId: row.session_id, authorizationId: row.authorization_id, clientId: row.client_id, nexusId: row.nexus_id,
      channel: row.channel, expiresAt: row.expires_at.toISOString(), claimedByMe: holder === operator.username,
      transaction: { operationType: row.operation_type, amountMinor: String(row.amount_minor), currency: row.currency, beneficiary: row.beneficiary, transactionReference: row.transaction_reference },
    });
  }
  return calls;
}

/** Claims a waiting call for this operator. Returns what the operator needs
 * to verify with the customer: the transaction terms (as stored, the bytes
 * the device will sign) and the ICE servers. */
export async function claimCall(sessionId: string, operator: OperatorIdentity): Promise<Record<string, unknown>> {
  const row = await operatorCall(sessionId, operator);
  assertOpen(row);
  const channels = await pool.query<{ operator_verification_channels: string[] }>(`SELECT operator_verification_channels FROM bank_clients WHERE client_id = $1`, [row.client_id]);
  if (!channels.rows[0]?.operator_verification_channels.includes(row.channel)) throw new ForbiddenError(`Operator verification is not enabled for ${row.channel} at this bank`);
  const k = keys(sessionId);
  const claimed = await redis.set(k.operator, operator.username, 'PX', keyLifetimeMs(row), 'NX');
  if (claimed !== 'OK' && (await redis.get(k.operator)) !== operator.username) throw new ConflictError('The call is answered by another operator');
  if (claimed === 'OK') {
    await recordAuditEvent('verification_call_claimed', { nexusId: row.nexus_id, clientId: row.client_id, actor: `admin:${operator.username}` },
      { sessionId, authorizationId: row.authorization_id, channel: row.channel });
  }
  const auth = await getAuthorizationForClient(row.authorization_id, row.client_id);
  return {
    sessionId, channel: row.channel, expiresAt: row.expires_at.toISOString(), iceServers: iceServersFor(sessionId, row.expires_at),
    transaction: { operationType: auth.operationType, amountMinor: auth.amountMinor, currency: auth.currency, beneficiary: auth.beneficiary, transactionReference: auth.transactionReference },
  };
}

function validateSignal(type: string, payload: unknown): SignalType {
  if (!(SIGNAL_TYPES as readonly string[]).includes(type)) throw new ValidationError('type must be offer, answer, candidate or bye');
  const size = JSON.stringify(payload ?? null).length;
  if ((type === 'offer' || type === 'answer')) {
    const sdp = (payload as { sdp?: unknown } | null)?.sdp;
    if (typeof sdp !== 'string' || sdp.length === 0 || sdp.length > MAX_SDP_LENGTH) throw new ValidationError(`payload.sdp must be a session description of at most ${MAX_SDP_LENGTH} characters`);
  } else if (type === 'candidate') {
    if (size > MAX_CANDIDATE_LENGTH) throw new ValidationError(`a candidate is at most ${MAX_CANDIDATE_LENGTH} characters`);
  } else if (size > 256) {
    throw new ValidationError('bye carries at most a short reason');
  }
  return type as SignalType;
}

/**
 * Appends one signal atomically, applying the signalling rules above.
 * KEYS: seq, state, inbox of the recipient(s): to:device, to:operator
 * ARGV: from, type, messageId ('' if none), signal JSON without seq, ttl ms, max per inbox
 * Returns {seq, duplicate} or an error code string.
 */
const APPEND_SCRIPT = `
local from, kind, mid, body, ttl, max = ARGV[1], ARGV[2], ARGV[3], ARGV[4], tonumber(ARGV[5]), tonumber(ARGV[6])
if mid ~= '' then
  local seen = redis.call('HGET', KEYS[2], 'id:' .. from .. ':' .. mid)
  if seen then return {tonumber(seen), 1} end
end
if redis.call('HGET', KEYS[2], 'bye:' .. from) then return 'ERR_CLOSED' end
local offers = tonumber(redis.call('HGET', KEYS[2], 'offers') or '0')
local answers = tonumber(redis.call('HGET', KEYS[2], 'answers') or '0')
if from == 'device' then
  if kind == 'answer' then return 'ERR_ROLE' end
  if kind == 'offer' and offers > answers then return 'ERR_OFFER_PENDING' end
  if kind == 'candidate' and offers == 0 then return 'ERR_NO_DESCRIPTION' end
elseif from == 'operator' then
  if kind == 'offer' then return 'ERR_ROLE' end
  if kind == 'answer' and answers >= offers then return 'ERR_NO_OFFER' end
  if kind == 'candidate' and answers == 0 then return 'ERR_NO_DESCRIPTION' end
elseif kind ~= 'bye' then
  return 'ERR_ROLE'
end
local targets = {}
if from ~= 'device' then table.insert(targets, KEYS[3]) end
if from ~= 'operator' then table.insert(targets, KEYS[4]) end
for _, inbox in ipairs(targets) do
  if redis.call('LLEN', inbox) >= max then return 'ERR_LIMIT' end
end
local seq = redis.call('INCR', KEYS[1])
local signal = '{"seq":' .. seq .. ',' .. string.sub(body, 2)
for _, inbox in ipairs(targets) do
  redis.call('RPUSH', inbox, signal)
  redis.call('PEXPIRE', inbox, ttl)
end
if kind == 'offer' then redis.call('HINCRBY', KEYS[2], 'offers', 1) end
if kind == 'answer' then redis.call('HINCRBY', KEYS[2], 'answers', 1) end
if kind == 'bye' then redis.call('HSET', KEYS[2], 'bye:' .. from, seq) end
if mid ~= '' then redis.call('HSET', KEYS[2], 'id:' .. from .. ':' .. mid, seq) end
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('PEXPIRE', KEYS[2], ttl)
return {seq, 0}
`;

const APPEND_ERRORS: Record<string, () => Error> = {
  ERR_CLOSED: () => new ConflictError('This party has left the call'),
  ERR_ROLE: () => new ValidationError('This party may not send this signal type'),
  ERR_OFFER_PENDING: () => new ConflictError('The previous offer has not been answered yet'),
  ERR_NO_OFFER: () => new ConflictError('There is no offer to answer'),
  ERR_NO_DESCRIPTION: () => new ConflictError('Send the session description before candidates'),
  ERR_LIMIT: () => new ConflictError('Too many signalling messages for this call'),
};

async function append(row: CallRow, from: SignalSender, type: SignalType, payload: unknown, messageId?: string): Promise<{ seq: number; duplicate: boolean }> {
  const k = keys(row.session_id);
  const body = JSON.stringify({ from, type, payload, at: new Date().toISOString() });
  const result = await redis.eval(APPEND_SCRIPT, 4, k.seq, k.state, k.inbox('device'), k.inbox('operator'),
    from, type, messageId ?? '', body, String(keyLifetimeMs(row)), String(MAX_SIGNALS_PER_DIRECTION)) as [number, number] | string;
  if (typeof result === 'string') throw (APPEND_ERRORS[result] ?? (() => new ConflictError(result)))();
  return { seq: Number(result[0]), duplicate: Number(result[1]) === 1 };
}

/** Relays one bye from `server` when the session or authorization has been
 * closed, at most once per call. */
async function relayClosure(sessionId: string): Promise<void> {
  const row = await loadCall(sessionId);
  const reason = closedReason(row);
  if (reason === null) return;
  if ((await redis.hsetnx(keys(sessionId).state, 'closed', reason)) !== 1) return;
  await append(row, 'server', 'bye', { reason }).catch(() => undefined);
}

const CLOSURE_CHECK_MS = 2_000;

/** Reads signals addressed to `role` with seq > after, waiting up to waitMs
 * for the first one (long poll). Checks every few seconds whether the call
 * has been closed elsewhere, and relays that as a bye. */
async function read(sessionId: string, role: CallRole, after: number, waitMs: number): Promise<{ signals: Signal[]; next: number }> {
  const deadline = Date.now() + Math.min(Math.max(waitMs, 0), MAX_WAIT_MS);
  let nextClosureCheck = 0;
  for (;;) {
    if (Date.now() >= nextClosureCheck) {
      await relayClosure(sessionId);
      nextClosureCheck = Date.now() + CLOSURE_CHECK_MS;
    }
    const raw = await redis.lrange(keys(sessionId).inbox(role), 0, -1);
    const signals = raw.map((s) => JSON.parse(s) as Signal).filter((s) => s.seq > after);
    if (signals.length > 0 || Date.now() >= deadline) return { signals, next: signals.at(-1)?.seq ?? after };
    await new Promise((resolve) => setTimeout(resolve, POLL_STEP_MS));
  }
}

export async function deviceSignal(sessionId: string, device: DeviceContextForCall, type: string, payload: unknown, messageId?: string): Promise<{ seq: number; duplicate: boolean }> {
  const row = await deviceCall(sessionId, device);
  assertOpen(row);
  return append(row, 'device', validateSignal(type, payload), payload, messageId);
}

export async function deviceSignals(sessionId: string, device: DeviceContextForCall, after: number, waitMs: number): Promise<{ signals: Signal[]; next: number }> {
  await deviceCall(sessionId, device);
  return read(sessionId, 'device', after, waitMs);
}

export async function operatorSignal(sessionId: string, operator: OperatorIdentity, type: string, payload: unknown, messageId?: string): Promise<{ seq: number; duplicate: boolean }> {
  await assertClaimedBy(sessionId, operator);
  const row = await loadCall(sessionId);
  assertOpen(row);
  return append(row, 'operator', validateSignal(type, payload), payload, messageId);
}

export async function operatorSignals(sessionId: string, operator: OperatorIdentity, after: number, waitMs: number): Promise<{ signals: Signal[]; next: number }> {
  await assertClaimedBy(sessionId, operator);
  return read(sessionId, 'operator', after, waitMs);
}

/**
 * The customer ends or declines the call. The session is CANCELLED and the
 * plan returns to PENDING, so the customer can try again (up to the attempt
 * limit of openVerificationSession) or the bank decides otherwise. Declining
 * is not a failed check: nothing was verified either way.
 */
export async function deviceCancel(sessionId: string, device: DeviceContextForCall): Promise<void> {
  const row = await deviceCall(sessionId, device);
  await cancelSession(row, 'device');
  await sendBye(sessionId, 'device', 'cancelled');
}

/**
 * The operator who holds the call leaves without a result (hang up). Like a
 * customer's cancel, nothing is verified or failed; the session is closed so
 * the customer is not left waiting, and the customer may open a new one.
 */
export async function operatorRelease(sessionId: string, operator: OperatorIdentity): Promise<void> {
  await assertClaimedBy(sessionId, operator);
  const row = await loadCall(sessionId);
  await cancelSession(row, `admin:${operator.username}`);
  await sendBye(sessionId, 'operator', 'operator_left');
}

async function cancelSession(row: CallRow, by: string): Promise<void> {
  const sessionId = row.session_id;
  await withTransaction(async (tx) => {
    const plan = await tx.query(`SELECT 1 FROM authorization_verification_plans WHERE authorization_id = $1 FOR UPDATE`, [row.authorization_id]);
    if (!plan.rows[0]) throw new NotFoundError('Verification plan not found');
    const cancelled = await tx.query(`UPDATE verification_sessions SET status = 'CANCELLED' WHERE session_id = $1 AND status = 'IN_PROGRESS'`, [sessionId]);
    if (cancelled.rowCount !== 1) throw new ConflictError(`Verification session is ${row.status}`);
    await tx.query(`UPDATE authorization_verification_plans SET status = 'PENDING', updated_at = now() WHERE authorization_id = $1 AND status = 'IN_PROGRESS'`, [row.authorization_id]);
    await recordAuditEvent('verification_session_cancelled', { nexusId: row.nexus_id, clientId: row.client_id },
      { sessionId, authorizationId: row.authorization_id, channel: row.channel, by }, tx);
  });
}

/** Tells the other party the call is over (after a decision or a cancel). */
export async function sendBye(sessionId: string, from: CallRole, reason: string): Promise<void> {
  const row = await loadCall(sessionId);
  await append(row, from, 'bye', { reason }).catch((error: unknown) => {
    // The party already said bye (for example a cancel after hanging up).
    if (!(error instanceof ConflictError)) throw error;
  });
}
