import { createHash, randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { canonicalJson } from './canonicalAuthorization';
import { ConflictError, NotFoundError, ValidationError } from './errors';
import { recordAuditEvent } from './auditService';
import { enqueueWebhook } from './webhookService';

/**
 * Conversations between a customer and the bank inside the bank's app
 * (presentation pages 11 and 12). Not a messenger: every conversation
 * belongs to one NEXUS ID of one bank, and only that customer's devices,
 * that bank's backend (its bot) and that bank's operators take part.
 *
 * - The customer writes from an enrolled device (device-signed requests).
 * - The bank's bot runs at the bank. It receives each customer message as the
 *   `conversation.message` webhook and answers through the bank API; it can
 *   hand the conversation over to a person.
 * - The customer can ask for a person at any time. The conversation then
 *   waits in the operator queue of that bank; an operator of the bank claims
 *   it in the console and answers there.
 * - Messages are append-only and hash-chained per conversation (each
 *   message's hash covers the previous one), so a removed or changed message
 *   is detectable; delivery and read marks are set once.
 *
 * Attachments are stored by the bank; a message carries the bank's reference,
 * the SHA-256 of the content and its media type, so the app can check what it
 * downloads from the bank.
 */

export type ConversationState = 'WITH_BOT' | 'WAITING_FOR_AGENT' | 'WITH_AGENT' | 'CLOSED';
export type SenderType = 'CUSTOMER' | 'BOT' | 'AGENT' | 'SYSTEM';

export interface Attachment { reference: string; sha256: string; mediaType: string; fileName: string; sizeBytes: number }

export interface Conversation {
  conversationId: string;
  nexusId: string;
  topic: string;
  authorizationId: string | null;
  state: ConversationState;
  assignedOperator: string | null;
  handoverReason: string | null;
  lastSequence: number;
  lastMessageHash: string | null;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
}

export interface Message {
  messageId: string;
  conversationId: string;
  sequence: number;
  senderType: SenderType;
  /** The operator's username is not shown to the customer: AGENT messages carry "agent". */
  sender: string;
  body: string;
  attachment: Attachment | null;
  clientMessageId: string | null;
  previousHash: string | null;
  messageHash: string;
  createdAt: string;
  deliveredAt: string | null;
  readAt: string | null;
}

interface ConversationRow {
  conversation_id: string; client_id: string; nexus_id: string; topic: string; authorization_id: string | null; state: ConversationState;
  assigned_operator: string | null; handover_reason: string | null; last_sequence: number; last_message_hash: string | null;
  created_at: Date; updated_at: Date; closed_at: Date | null;
}
interface MessageRow {
  message_id: string; conversation_id: string; sequence: number; sender_type: SenderType; sender_ref: string; body: string;
  attachment: Attachment | null; client_message_id: string | null; previous_hash: string | null; message_hash: string;
  created_at: Date; delivered_at: Date | null; read_at: Date | null;
}

const iso = (d: Date | null) => (d ? new Date(d).toISOString() : null);
const toConversation = (r: ConversationRow): Conversation => ({
  conversationId: r.conversation_id, nexusId: r.nexus_id, topic: r.topic, authorizationId: r.authorization_id, state: r.state,
  assignedOperator: r.assigned_operator, handoverReason: r.handover_reason, lastSequence: r.last_sequence, lastMessageHash: r.last_message_hash,
  createdAt: iso(r.created_at)!, updatedAt: iso(r.updated_at)!, closedAt: iso(r.closed_at),
});
/** For the customer the operator stays anonymous; the bank sees the username. */
const toMessage = (r: MessageRow, audience: 'customer' | 'bank'): Message => ({
  messageId: r.message_id, conversationId: r.conversation_id, sequence: r.sequence, senderType: r.sender_type,
  sender: audience === 'customer' && r.sender_type === 'AGENT' ? 'agent' : r.sender_ref, body: r.body, attachment: r.attachment,
  clientMessageId: r.client_message_id, previousHash: r.previous_hash, messageHash: r.message_hash, createdAt: iso(r.created_at)!,
  deliveredAt: iso(r.delivered_at), readAt: iso(r.read_at),
});

/**
 * The hash of a message: SHA-256 over the canonical JSON of its content and
 * the previous message's hash. Exported so the bank and tests can recompute it.
 */
export function messageHash(m: { conversationId: string; sequence: number; senderType: SenderType; sender: string; body: string; attachment: Attachment | null; createdAt: string; previousHash: string | null }): string {
  return createHash('sha256').update(canonicalJson({
    conversation_id: m.conversationId, sequence: m.sequence, sender_type: m.senderType, sender: m.sender, body: m.body,
    attachment: m.attachment, created_at: m.createdAt, previous_hash: m.previousHash,
  })).digest('hex');
}

/** Message text: no control or invisible characters except line breaks and tabs, no bidi overrides. */
function checkBody(body: string): string {
  const text = body.normalize('NFC');
  if (text.trim().length === 0 || text.length > 4000) throw new ValidationError('A message has 1 to 4000 characters');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F​-‏‪-‮⁠-⁩﻿￹-￻]/u.test(text)) {
    throw new ValidationError('A message must not contain control, invisible or direction-override characters');
  }
  return text;
}

function checkAttachment(a: Attachment | null | undefined): Attachment | null {
  if (!a) return null;
  if (!/^[A-Za-z0-9._:/-]{1,256}$/.test(a.reference) || !/^[0-9a-f]{64}$/.test(a.sha256) || !/^[a-z]+\/[a-z0-9.+-]{1,64}$/.test(a.mediaType)
      || typeof a.fileName !== 'string' || a.fileName.length < 1 || a.fileName.length > 200 || /[\\/\u0000-\u001F]/.test(a.fileName)
      || !Number.isInteger(a.sizeBytes) || a.sizeBytes < 1 || a.sizeBytes > 50 * 1024 * 1024) {
    throw new ValidationError('An attachment has a bank reference, a SHA-256, a media type, a plain file name and a size up to 50 MB');
  }
  return { reference: a.reference, sha256: a.sha256, mediaType: a.mediaType, fileName: a.fileName, sizeBytes: a.sizeBytes };
}

async function lockConversation(tx: PoolClient, conversationId: string, scope: { nexusId?: string; clientId?: string }): Promise<ConversationRow> {
  const row = (await tx.query<ConversationRow>(
    `SELECT * FROM conversations WHERE conversation_id = $1 AND ($2::text IS NULL OR nexus_id = $2) AND ($3::text IS NULL OR client_id = $3) FOR UPDATE`,
    [conversationId, scope.nexusId ?? null, scope.clientId ?? null])).rows[0];
  if (!row) throw new NotFoundError('Conversation not found');
  return row;
}

/** Appends one message under the conversation lock; idempotent per sender and clientMessageId. */
async function append(tx: PoolClient, c: ConversationRow, senderType: SenderType, senderRef: string, body: string, attachment: Attachment | null, clientMessageId: string | null): Promise<{ row: MessageRow; replayed: boolean }> {
  if (clientMessageId) {
    const previous = (await tx.query<MessageRow>(`SELECT * FROM conversation_messages WHERE conversation_id = $1 AND sender_ref = $2 AND client_message_id = $3`,
      [c.conversation_id, senderRef, clientMessageId])).rows[0];
    if (previous) {
      if (previous.body !== body) throw new ConflictError('This clientMessageId was used for another message', 'MESSAGE_ID_REUSED');
      return { row: previous, replayed: true };
    }
  }
  const sequence = c.last_sequence + 1;
  const createdAt = new Date();
  const hash = messageHash({ conversationId: c.conversation_id, sequence, senderType, sender: senderRef, body, attachment, createdAt: createdAt.toISOString(), previousHash: c.last_message_hash });
  const row = (await tx.query<MessageRow>(
    `INSERT INTO conversation_messages (message_id, conversation_id, sequence, sender_type, sender_ref, body, attachment, client_message_id, previous_hash, message_hash, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
    [randomUUID(), c.conversation_id, sequence, senderType, senderRef, body, attachment ? JSON.stringify(attachment) : null, clientMessageId, c.last_message_hash, hash, createdAt])).rows[0];
  await tx.query(`UPDATE conversations SET last_sequence = $2, last_message_hash = $3, updated_at = now() WHERE conversation_id = $1`, [c.conversation_id, sequence, hash]);
  c.last_sequence = sequence; c.last_message_hash = hash;
  return { row, replayed: false };
}

async function notifyBank(tx: PoolClient, c: ConversationRow, m: MessageRow): Promise<void> {
  await enqueueWebhook(c.client_id, 'conversation.message', {
    conversationId: c.conversation_id, nexusId: c.nexus_id, state: c.state, messageId: m.message_id, sequence: m.sequence,
    senderType: m.sender_type, body: m.body, attachment: m.attachment, messageHash: m.message_hash,
  }, tx);
}

// --- The customer (device-signed requests) ---

export interface DeviceScope { clientId: string; nexusId: string; credentialId: string }

/** The customer opens a conversation, optionally about one of their payments. */
export async function openConversation(device: DeviceScope, input: { topic: string; body: string; authorizationId?: string | null; clientMessageId?: string | null; attachment?: Attachment | null }): Promise<{ conversation: Conversation; message: Message }> {
  const topic = checkBody(input.topic);
  if (topic.length > 200 || /\n/.test(topic)) throw new ValidationError('A topic is one line of up to 200 characters');
  const body = checkBody(input.body);
  const attachment = checkAttachment(input.attachment);
  return withTransaction(async (tx) => {
    if (input.authorizationId) {
      const own = await tx.query(`SELECT 1 FROM authorization_requests WHERE authorization_id = $1 AND nexus_id = $2 AND client_id = $3`, [input.authorizationId, device.nexusId, device.clientId]);
      if (own.rowCount === 0) throw new NotFoundError('Authorization not found');
    }
    const conversationId = randomUUID();
    await tx.query(`INSERT INTO conversations (conversation_id, client_id, nexus_id, topic, authorization_id) VALUES ($1,$2,$3,$4,$5)`,
      [conversationId, device.clientId, device.nexusId, topic, input.authorizationId ?? null]);
    const c = await lockConversation(tx, conversationId, {});
    const { row } = await append(tx, c, 'CUSTOMER', `credential:${device.credentialId}`, body, attachment, input.clientMessageId ?? null);
    await recordAuditEvent('conversation_opened', { nexusId: device.nexusId, clientId: device.clientId, actor: `credential:${device.credentialId}` },
      { conversationId, authorizationId: input.authorizationId ?? null }, tx);
    await notifyBank(tx, c, row);
    return { conversation: toConversation(c), message: toMessage(row, 'customer') };
  });
}

export async function listCustomerConversations(nexusId: string): Promise<Conversation[]> {
  const rows = await pool.query<ConversationRow>(`SELECT * FROM conversations WHERE nexus_id = $1 ORDER BY updated_at DESC LIMIT 100`, [nexusId]);
  return rows.rows.map(toConversation);
}

/** Messages after a sequence number (history and polling); marks them delivered to the customer's app. */
export async function customerMessages(device: DeviceScope, conversationId: string, after = 0): Promise<{ conversation: Conversation; messages: Message[] }> {
  return withTransaction(async (tx) => {
    const c = await lockConversation(tx, conversationId, { nexusId: device.nexusId });
    await tx.query(`UPDATE conversation_messages SET delivered_at = now() WHERE conversation_id = $1 AND sequence > $2 AND sender_type <> 'CUSTOMER' AND delivered_at IS NULL`, [conversationId, after]);
    const rows = await tx.query<MessageRow>(`SELECT * FROM conversation_messages WHERE conversation_id = $1 AND sequence > $2 ORDER BY sequence LIMIT 500`, [conversationId, after]);
    return { conversation: toConversation(c), messages: rows.rows.map((r) => toMessage(r, 'customer')) };
  });
}

export async function customerSend(device: DeviceScope, conversationId: string, input: { body: string; clientMessageId?: string | null; attachment?: Attachment | null }): Promise<{ message: Message; replayed: boolean }> {
  const body = checkBody(input.body);
  const attachment = checkAttachment(input.attachment);
  return withTransaction(async (tx) => {
    const c = await lockConversation(tx, conversationId, { nexusId: device.nexusId });
    if (c.state === 'CLOSED') throw new ConflictError('The conversation is closed', 'CONVERSATION_CLOSED');
    const { row, replayed } = await append(tx, c, 'CUSTOMER', `credential:${device.credentialId}`, body, attachment, input.clientMessageId ?? null);
    if (!replayed) await notifyBank(tx, c, row);
    return { message: toMessage(row, 'customer'), replayed };
  });
}

/** The customer has read the bank's messages up to a sequence number. */
export async function customerRead(device: DeviceScope, conversationId: string, upTo: number): Promise<number> {
  return withTransaction(async (tx) => {
    await lockConversation(tx, conversationId, { nexusId: device.nexusId });
    const r = await tx.query(`UPDATE conversation_messages SET read_at = now(), delivered_at = coalesce(delivered_at, now())
      WHERE conversation_id = $1 AND sequence <= $2 AND sender_type <> 'CUSTOMER' AND read_at IS NULL`, [conversationId, upTo]);
    return r.rowCount ?? 0;
  });
}

/** Hands over to a person (customer: "talk to a person"; bot: through the bank API). */
async function handover(tx: PoolClient, c: ConversationRow, reason: string, actor: string): Promise<void> {
  if (c.state === 'CLOSED') throw new ConflictError('The conversation is closed', 'CONVERSATION_CLOSED');
  if (c.state === 'WAITING_FOR_AGENT') return;
  await tx.query(`UPDATE conversations SET state = 'WAITING_FOR_AGENT', assigned_operator = NULL, handover_reason = $2, updated_at = now() WHERE conversation_id = $1`, [c.conversation_id, reason]);
  c.state = 'WAITING_FOR_AGENT'; c.assigned_operator = null;
  const { row } = await append(tx, c, 'SYSTEM', 'system', 'The conversation was passed to a bank employee.', null, null);
  await recordAuditEvent('conversation_handover', { nexusId: c.nexus_id, clientId: c.client_id, actor }, { conversationId: c.conversation_id, reason }, tx);
  await notifyBank(tx, c, row);
}

export async function customerRequestsAgent(device: DeviceScope, conversationId: string): Promise<Conversation> {
  return withTransaction(async (tx) => {
    const c = await lockConversation(tx, conversationId, { nexusId: device.nexusId });
    await handover(tx, c, 'REQUESTED_BY_CUSTOMER', `credential:${device.credentialId}`);
    return toConversation(c);
  });
}

async function close(tx: PoolClient, c: ConversationRow, by: string): Promise<Conversation> {
  if (c.state === 'CLOSED') return toConversation(c);
  await tx.query(`UPDATE conversations SET state = 'CLOSED', assigned_operator = NULL, closed_at = now(), updated_at = now() WHERE conversation_id = $1`, [c.conversation_id]);
  c.state = 'CLOSED'; c.assigned_operator = null;
  const { row } = await append(tx, c, 'SYSTEM', 'system', 'The conversation was closed.', null, null);
  await recordAuditEvent('conversation_closed', { nexusId: c.nexus_id, clientId: c.client_id, actor: by }, { conversationId: c.conversation_id }, tx);
  await notifyBank(tx, c, row);
  return toConversation((await tx.query<ConversationRow>(`SELECT * FROM conversations WHERE conversation_id = $1`, [c.conversation_id])).rows[0]);
}

export async function customerClose(device: DeviceScope, conversationId: string): Promise<Conversation> {
  return withTransaction(async (tx) => close(tx, await lockConversation(tx, conversationId, { nexusId: device.nexusId }), `credential:${device.credentialId}`));
}

// --- The bank's backend (its bot) ---

export async function bankConversation(clientId: string, conversationId: string, after = 0): Promise<{ conversation: Conversation; messages: Message[] }> {
  const c = (await pool.query<ConversationRow>(`SELECT * FROM conversations WHERE conversation_id = $1 AND client_id = $2`, [conversationId, clientId])).rows[0];
  if (!c) throw new NotFoundError('Conversation not found');
  const rows = await pool.query<MessageRow>(`SELECT * FROM conversation_messages WHERE conversation_id = $1 AND sequence > $2 ORDER BY sequence LIMIT 500`, [conversationId, after]);
  return { conversation: toConversation(c), messages: rows.rows.map((r) => toMessage(r, 'bank')) };
}

/** The bank's bot answers; only while no person has taken the conversation. */
export async function botSend(clientId: string, conversationId: string, input: { body: string; clientMessageId?: string | null; attachment?: Attachment | null; handover?: boolean; handoverReason?: string }): Promise<{ message: Message; conversation: Conversation; replayed: boolean }> {
  const body = checkBody(input.body);
  const attachment = checkAttachment(input.attachment);
  return withTransaction(async (tx) => {
    const c = await lockConversation(tx, conversationId, { clientId });
    if (c.state !== 'WITH_BOT') throw new ConflictError(`The conversation is ${c.state}; the bot answers only before a handover`, 'CONVERSATION_NOT_WITH_BOT');
    const { row, replayed } = await append(tx, c, 'BOT', `bank:${clientId}`, body, attachment, input.clientMessageId ?? null);
    if (input.handover && !replayed) await handover(tx, c, (input.handoverReason ?? 'REQUESTED_BY_BOT').slice(0, 200), `bank:${clientId}`);
    return { message: toMessage(row, 'bank'), conversation: toConversation(c), replayed };
  });
}

export async function bankClose(clientId: string, conversationId: string): Promise<Conversation> {
  return withTransaction(async (tx) => close(tx, await lockConversation(tx, conversationId, { clientId }), `bank:${clientId}`));
}

// --- The bank's operators (console) ---

export interface Operator { username: string; clientId: string | null }

function operatorScope(operator: Operator): string {
  // A platform operator (no bank) is not the bank and does not talk to its customers.
  if (!operator.clientId) throw new NotFoundError('Conversation not found');
  return operator.clientId;
}

export async function operatorQueue(operator: Operator): Promise<Conversation[]> {
  const clientId = operatorScope(operator);
  const rows = await pool.query<ConversationRow>(
    `SELECT * FROM conversations WHERE client_id = $1 AND (state = 'WAITING_FOR_AGENT' OR (state = 'WITH_AGENT' AND assigned_operator = $2))
      ORDER BY updated_at LIMIT 200`, [clientId, operator.username]);
  return rows.rows.map(toConversation);
}

export async function operatorClaim(operator: Operator, conversationId: string): Promise<Conversation> {
  const clientId = operatorScope(operator);
  return withTransaction(async (tx) => {
    const c = await lockConversation(tx, conversationId, { clientId });
    if (c.state === 'WITH_AGENT' && c.assigned_operator === operator.username) return toConversation(c);
    if (c.state !== 'WAITING_FOR_AGENT') throw new ConflictError(`The conversation is ${c.state}`, 'CONVERSATION_NOT_WAITING');
    await tx.query(`UPDATE conversations SET state = 'WITH_AGENT', assigned_operator = $2, updated_at = now() WHERE conversation_id = $1`, [conversationId, operator.username]);
    c.state = 'WITH_AGENT'; c.assigned_operator = operator.username;
    await recordAuditEvent('conversation_claimed', { nexusId: c.nexus_id, clientId, actor: `admin:${operator.username}` }, { conversationId }, tx);
    return toConversation(c);
  });
}

export async function operatorMessages(operator: Operator, conversationId: string, after = 0): Promise<{ conversation: Conversation; messages: Message[] }> {
  return bankConversation(operatorScope(operator), conversationId, after);
}

export async function operatorSend(operator: Operator, conversationId: string, input: { body: string; clientMessageId?: string | null; attachment?: Attachment | null }): Promise<{ message: Message; replayed: boolean }> {
  const clientId = operatorScope(operator);
  const body = checkBody(input.body);
  const attachment = checkAttachment(input.attachment);
  return withTransaction(async (tx) => {
    const c = await lockConversation(tx, conversationId, { clientId });
    if (c.state !== 'WITH_AGENT' || c.assigned_operator !== operator.username) {
      throw new ConflictError('Only the operator who took the conversation answers in it', 'CONVERSATION_NOT_ASSIGNED');
    }
    const { row, replayed } = await append(tx, c, 'AGENT', `admin:${operator.username}`, body, attachment, input.clientMessageId ?? null);
    if (!replayed) await notifyBank(tx, c, row);
    return { message: toMessage(row, 'bank'), replayed };
  });
}

/** Back to the queue (another operator takes it), or closed. */
export async function operatorRelease(operator: Operator, conversationId: string): Promise<Conversation> {
  const clientId = operatorScope(operator);
  return withTransaction(async (tx) => {
    const c = await lockConversation(tx, conversationId, { clientId });
    if (c.state !== 'WITH_AGENT' || c.assigned_operator !== operator.username) throw new ConflictError('Only the operator who took the conversation releases it', 'CONVERSATION_NOT_ASSIGNED');
    await tx.query(`UPDATE conversations SET state = 'WAITING_FOR_AGENT', assigned_operator = NULL, updated_at = now() WHERE conversation_id = $1`, [conversationId]);
    c.state = 'WAITING_FOR_AGENT'; c.assigned_operator = null;
    await recordAuditEvent('conversation_released', { nexusId: c.nexus_id, clientId, actor: `admin:${operator.username}` }, { conversationId }, tx);
    return toConversation(c);
  });
}

export async function operatorClose(operator: Operator, conversationId: string): Promise<Conversation> {
  const clientId = operatorScope(operator);
  return withTransaction(async (tx) => {
    const c = await lockConversation(tx, conversationId, { clientId });
    if (c.state === 'WITH_AGENT' && c.assigned_operator !== operator.username) throw new ConflictError('Only the operator who took the conversation closes it', 'CONVERSATION_NOT_ASSIGNED');
    return close(tx, c, `admin:${operator.username}`);
  });
}

/** Recomputes the hash chain of a conversation; returns the problems found (empty when intact). */
export async function verifyConversation(clientId: string, conversationId: string): Promise<string[]> {
  const { conversation, messages } = await bankConversation(clientId, conversationId);
  const problems: string[] = [];
  let previous: string | null = null;
  messages.forEach((m, i) => {
    if (m.sequence !== i + 1) problems.push(`message ${m.sequence}: sequence gap before it`);
    if (m.previousHash !== previous) problems.push(`message ${m.sequence}: does not follow the previous message`);
    const expected = messageHash({ conversationId, sequence: m.sequence, senderType: m.senderType, sender: m.sender, body: m.body, attachment: m.attachment, createdAt: m.createdAt, previousHash: m.previousHash });
    if (expected !== m.messageHash) problems.push(`message ${m.sequence}: content does not match its hash`);
    previous = m.messageHash;
  });
  if (previous !== conversation.lastMessageHash || messages.length !== conversation.lastSequence) problems.push('the conversation head does not match its last message');
  return problems;
}
