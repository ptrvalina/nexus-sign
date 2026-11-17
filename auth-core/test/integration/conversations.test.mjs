// Conversations with the bank (migration 029), on PostgreSQL: the customer
// writes from a device, the bank's bot answers through the bank API and hands
// over, an operator of that bank (and no other) claims and answers, messages
// are idempotent, hash-chained, append-only, and delivery and read marks are
// set once.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
};

describe('conversations with the bank (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s;
  const bankA = `bank-${randomBytes(4).toString('hex')}`; const bankB = `bank-${randomBytes(4).toString('hex')}`;

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    const cache = new Map();
    s = { c: loadTs('services/conversationService.ts', { stubs, cache }), db: loadTs('db/pool.ts', { stubs, cache }) };
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    // Webhooks are queued only for a bank client with a destination.
    for (const b of [bankA, bankB]) {
      await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash, webhook_url, webhook_secret_encrypted) VALUES ($1, 'x', 'https://bank.example/hooks', 'sealed')`, [b]);
    }
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  async function customer(clientId = bankA) {
    const nexusId = String(100000000 + Math.floor(Math.random() * 899999999));
    const credentialId = randomUUID();
    await admin.query(`INSERT INTO nexus_identities (nexus_id, client_id, bank_customer_ref) VALUES ($1, $2, $3)`, [nexusId, clientId, randomUUID()]);
    return { clientId, nexusId, credentialId };
  }
  const operatorA = { username: 'anna', clientId: bankA };
  const webhooks = async (event) => (await admin.query(`SELECT payload FROM webhook_deliveries WHERE event_type = $1 ORDER BY created_at`, [event])).rows.map((r) => r.payload);

  test('customer → bot → handover → operator → closed; the bank gets every message as a webhook', async () => {
    const device = await customer();
    const { conversation, message } = await s.c.openConversation(device, { topic: 'Card blocked', body: 'My card was blocked abroad', clientMessageId: 'm1' });
    assert.equal(conversation.state, 'WITH_BOT'); assert.equal(message.sequence, 1);
    const reply = await s.c.botSend(bankA, conversation.conversationId, { body: 'I can unblock it. Shall I?', clientMessageId: 'b1' });
    assert.equal(reply.message.senderType, 'BOT');
    await s.c.customerSend(device, conversation.conversationId, { body: 'I want to talk to a person', clientMessageId: 'm2' });
    const handed = await s.c.botSend(bankA, conversation.conversationId, { body: 'Passing you to a colleague', handover: true, handoverReason: 'CUSTOMER_ASKED' });
    assert.equal(handed.conversation.state, 'WAITING_FOR_AGENT');
    await assert.rejects(s.c.botSend(bankA, conversation.conversationId, { body: 'late bot answer' }), /only before a handover/);
    assert.ok((await s.c.operatorQueue(operatorA)).some((c) => c.conversationId === conversation.conversationId));
    const claimed = await s.c.operatorClaim(operatorA, conversation.conversationId);
    assert.equal(claimed.state, 'WITH_AGENT'); assert.equal(claimed.assignedOperator, 'anna');
    await assert.rejects(s.c.operatorSend({ username: 'boris', clientId: bankA }, conversation.conversationId, { body: 'hi' }), /Only the operator who took/);
    await s.c.operatorSend(operatorA, conversation.conversationId, { body: 'Unblocked. Anything else?' });
    const seen = await s.c.customerMessages(device, conversation.conversationId, 0);
    assert.deepEqual(seen.messages.map((m) => m.senderType), ['CUSTOMER', 'BOT', 'CUSTOMER', 'BOT', 'SYSTEM', 'AGENT']);
    assert.equal(seen.messages.at(-1).sender, 'agent', 'the operator stays anonymous to the customer');
    assert.ok(seen.messages.filter((m) => m.senderType !== 'CUSTOMER').every((m) => m.deliveredAt));
    assert.equal(await s.c.customerRead(device, conversation.conversationId, 6), 4);
    const closed = await s.c.customerClose(device, conversation.conversationId);
    assert.equal(closed.state, 'CLOSED');
    await assert.rejects(s.c.customerSend(device, conversation.conversationId, { body: 'one more' }), /closed/);
    const events = (await webhooks('conversation.message')).filter((p) => p.conversationId === conversation.conversationId);
    // Two customer messages, the handover notice, the operator's answer and the closing notice;
    // the bot's own messages come from the bank and are not sent back to it.
    assert.deepEqual(events.map((e) => e.senderType), ['CUSTOMER', 'CUSTOMER', 'SYSTEM', 'AGENT', 'SYSTEM']);
    assert.deepEqual(await s.c.verifyConversation(bankA, conversation.conversationId), []);
  });

  test('another customer, another bank and a platform operator see nothing', async () => {
    const device = await customer();
    const { conversation } = await s.c.openConversation(device, { topic: 'Question', body: 'Hello' });
    const stranger = await customer();
    await assert.rejects(s.c.customerSend(stranger, conversation.conversationId, { body: 'hi' }), /not found/);
    await assert.rejects(s.c.botSend(bankB, conversation.conversationId, { body: 'hi' }), /not found/);
    await s.c.customerRequestsAgent(device, conversation.conversationId);
    await assert.rejects(s.c.operatorClaim({ username: 'eve', clientId: bankB }, conversation.conversationId), /not found/);
    await assert.rejects(s.c.operatorClaim({ username: 'root', clientId: null }, conversation.conversationId), /not found/);
    assert.ok(!(await s.c.operatorQueue({ username: 'eve', clientId: bankB })).some((c) => c.conversationId === conversation.conversationId));
    // A payment of another customer cannot be the subject.
    await assert.rejects(s.c.openConversation(device, { topic: 'x', body: 'y', authorizationId: randomUUID() }), /Authorization not found/);
  });

  test('a retried message is stored once; reusing its id for other text is refused; text is checked', async () => {
    const device = await customer();
    const { conversation } = await s.c.openConversation(device, { topic: 'Retry', body: 'first' });
    const a = await s.c.customerSend(device, conversation.conversationId, { body: 'same', clientMessageId: 'x1' });
    const b = await s.c.customerSend(device, conversation.conversationId, { body: 'same', clientMessageId: 'x1' });
    assert.equal(b.replayed, true); assert.equal(b.message.messageId, a.message.messageId);
    await assert.rejects(s.c.customerSend(device, conversation.conversationId, { body: 'other', clientMessageId: 'x1' }), /another message/);
    await assert.rejects(s.c.customerSend(device, conversation.conversationId, { body: 'pay to ‮evil' }), /direction-override/);
    await assert.rejects(s.c.customerSend(device, conversation.conversationId, { body: 'file', attachment: { reference: '../../etc/passwd', sha256: 'x', mediaType: 'text/plain', fileName: 'a', sizeBytes: 1 } }), /attachment/);
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => s.c.customerSend(device, conversation.conversationId, { body: `parallel ${i}` })));
    assert.equal(new Set(results.map((r) => r.message.sequence)).size, 8, 'concurrent messages get distinct sequence numbers');
    assert.deepEqual(await s.c.verifyConversation(bankA, conversation.conversationId), []);
  });

  test('the database keeps history: no edit, no delete, marks set once; tampering is detected', async () => {
    const device = await customer();
    const { conversation, message } = await s.c.openConversation(device, { topic: 'Keep', body: 'original text' });
    await s.c.botSend(bankA, conversation.conversationId, { body: 'answer' });
    await assert.rejects(admin.query(`DELETE FROM conversation_messages WHERE message_id = $1`, [message.messageId]), /are kept/);
    await assert.rejects(admin.query(`UPDATE conversation_messages SET body = 'changed' WHERE message_id = $1`, [message.messageId]), /only its delivery and read marks/);
    await s.c.customerRead(device, conversation.conversationId, 2);
    await assert.rejects(admin.query(`UPDATE conversation_messages SET read_at = now() + interval '1 day' WHERE conversation_id = $1 AND sequence = 2`, [conversation.conversationId]), /once/);
    await assert.rejects(admin.query(`UPDATE conversations SET nexus_id = '999999999' WHERE conversation_id = $1`, [conversation.conversationId]), /immutable/);
    await assert.rejects(admin.query(`UPDATE conversations SET state = 'WITH_BOT' WHERE conversation_id = $1 AND state = 'WITH_BOT'`, [conversation.conversationId]).then(() => admin.query(`UPDATE conversations SET state = 'WITH_AGENT' WHERE conversation_id = $1`, [conversation.conversationId])), /assigned_operator|check constraint|not permitted/);
    // The owner rewrites a message with the trigger off: the chain shows it.
    await admin.query(`ALTER TABLE conversation_messages DISABLE TRIGGER conversation_messages_append_only;
      UPDATE conversation_messages SET body = 'rewritten' WHERE message_id = '${message.messageId}';
      ALTER TABLE conversation_messages ENABLE TRIGGER conversation_messages_append_only`);
    assert.match((await s.c.verifyConversation(bankA, conversation.conversationId)).join(';'), /message 1: content does not match its hash/);
  });
});
