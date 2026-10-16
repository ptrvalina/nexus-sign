import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, generateKeyPairSync, randomBytes, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { loadTs } from './support/load-ts.mjs';

const vectors = JSON.parse(readFileSync(new URL('../test-vectors/secure-push-v1.json', import.meta.url), 'utf8'));
const push = loadTs('services/pushProtocol.ts');
const providers = loadTs('services/pushProviders.ts');
const { buildApnsProviderToken } = loadTs('crypto/apnsProviderToken.ts');

const scalar = (hex) => {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(hex, 'hex'));
  return ecdh;
};

const k = vectors.key_agreement;
const pushKey = Buffer.from(k.push_key_hex, 'hex');

const sampleContent = (overrides = {}) => ({
  v: 1, category: 'INCOMING_PAYMENT', title: 'Incoming payment', body: '+ € 10.00 from Jan', authorizationId: null,
  data: {}, sentAt: '2026-10-01T10:00:00.000Z', ...overrides,
});

test('push key agreement matches the shared vectors from both sides', () => {
  const fromDevice = scalar(k.device_private_scalar_hex).computeSecret(scalar(k.server_private_scalar_hex).getPublicKey());
  const fromServer = scalar(k.server_private_scalar_hex).computeSecret(scalar(k.device_private_scalar_hex).getPublicKey());
  assert.equal(fromDevice.toString('hex'), k.shared_secret_hex);
  assert.deepEqual(fromServer, fromDevice);
  assert.equal(push.derivePushKey(fromDevice, k.credential_id).toString('hex'), k.push_key_hex);
  assert.equal(push.pushKeyId(pushKey), k.key_id);
  assert.match(k.key_id, /^[A-Za-z0-9_-]{22}$/);
  assert.notEqual(push.derivePushKey(fromDevice, '00000000-0000-4000-8000-000000000003').toString('hex'), k.push_key_hex);
});

test('sealing reproduces every vector envelope, and opening returns the plaintext', () => {
  for (const m of vectors.messages) {
    const content = JSON.parse(m.plaintext_utf8);
    assert.equal(JSON.stringify(content), m.plaintext_utf8, `${m.name}: serialization order`);
    assert.equal(push.pushAssociatedData(m.message_id, k.credential_id).toString('utf8'), m.aad_utf8, m.name);
    const envelope = push.sealPushMessage(pushKey, m.message_id, k.credential_id, content, Buffer.from(m.iv_hex, 'hex'));
    assert.deepEqual(envelope, m.envelope, m.name);
    assert.deepEqual(push.openPushMessage(pushKey, m.envelope), content, m.name);
    assert.equal(push.pushReceipt(pushKey, m.message_id, k.credential_id), m.receipt, `${m.name}: receipt`);
  }
});

test('a receipt is accepted only for its own message, credential and key', () => {
  const m = vectors.messages[0];
  assert.ok(push.isValidPushReceipt(pushKey, m.message_id, k.credential_id, m.receipt));
  assert.ok(!push.isValidPushReceipt(pushKey, vectors.messages[1].message_id, k.credential_id, m.receipt));
  assert.ok(!push.isValidPushReceipt(pushKey, m.message_id, '00000000-0000-4000-8000-000000000003', m.receipt));
  assert.ok(!push.isValidPushReceipt(randomBytes(32), m.message_id, k.credential_id, m.receipt));
  assert.ok(!push.isValidPushReceipt(pushKey, m.message_id, k.credential_id, m.receipt.slice(0, 42)));
});

test('every invalid vector envelope is refused', () => {
  for (const c of vectors.invalid) {
    assert.throws(() => push.openPushMessage(pushKey, c.envelope), c.name);
  }
});

test('a message sealed for one device cannot be opened with another device key', () => {
  const envelope = push.sealPushMessage(pushKey, '00000000-0000-4000-8000-0000000000b1', k.credential_id, sampleContent());
  assert.throws(() => push.openPushMessage(randomBytes(32), envelope));
  assert.notEqual(envelope.iv, push.sealPushMessage(pushKey, envelope.id, k.credential_id, sampleContent()).iv, 'IV must be random');
});

test('content that could mislead or overflow the payload is refused before sealing', () => {
  const id = '00000000-0000-4000-8000-0000000000b2';
  const bad = [
    ['empty title', { title: '' }],
    ['long title', { title: 'x'.repeat(push.PUSH_TITLE_MAX + 1) }],
    ['long body', { body: 'x'.repeat(push.PUSH_BODY_MAX + 1) }],
    ['bidi override in body', { body: 'from \u202eanna' }],
    ['zero-width space in title', { title: 'Incoming\u200bpayment' }],
    ['line break in title', { title: 'Incoming\npayment' }],
    ['lone surrogate in body', { body: 'from \ud800 Jan' }],
    ['data key', { data: { 'bad key': 'v' } }],
    ['data value', { data: { key: 'x'.repeat(push.PUSH_DATA_VALUE_MAX + 1) } }],
    ['too many data fields', { data: Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`k${i}`, 'v'])) }],
    ['plaintext too large', { data: Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`k${i}`, 'v'.repeat(200)])) }],
  ];
  for (const [name, overrides] of bad) {
    assert.throws(() => push.sealPushMessage(pushKey, id, k.credential_id, sampleContent(overrides)), name);
  }
  assert.doesNotThrow(() => push.sealPushMessage(pushKey, id, k.credential_id, sampleContent({ body: 'line one\nline two' })));
});

test('the largest allowed message fits the 4 KB APNs and FCM payloads', () => {
  let data = {};
  for (let i = 0; i < 16; i += 1) {
    const next = { ...data, [`key${i}`]: 'ż'.repeat(40) };
    if (Buffer.byteLength(JSON.stringify(sampleContent({ title: 'Ł'.repeat(120), body: 'ł'.repeat(300), data: next })), 'utf8') > push.PUSH_PLAINTEXT_MAX_BYTES) break;
    data = next;
  }
  const envelope = push.sealPushMessage(pushKey, '00000000-0000-4000-8000-0000000000b3', k.credential_id,
    sampleContent({ title: 'Ł'.repeat(120), body: 'ł'.repeat(300), data }));
  const apns = providers.apnsPayload(envelope, { title: 'Ñ'.repeat(64), body: '€'.repeat(120) });
  assert.ok(Buffer.byteLength(apns, 'utf8') <= 4096, `APNs payload is ${Buffer.byteLength(apns)} bytes`);
  const fcm = providers.fcmMessage({ provider: 'FCM', deviceToken: 't', apnsEnvironment: null },
    { messageId: envelope.id, envelope, expiresAt: new Date(Date.now() + 60_000), collapseId: null });
  assert.ok(Buffer.byteLength(fcm.message.data.nexus, 'utf8') <= 4096);
});

test('providers receive only the sealed envelope, never the category or text', () => {
  const content = sampleContent({ title: 'Secret title', body: 'Secret body' });
  const envelope = push.sealPushMessage(pushKey, '00000000-0000-4000-8000-0000000000b4', k.credential_id, content);
  const apns = providers.apnsPayload(envelope, { title: 'New message', body: '' });
  const fcm = JSON.stringify(providers.fcmMessage({ provider: 'FCM', deviceToken: 't', apnsEnvironment: null },
    { messageId: envelope.id, envelope, expiresAt: new Date(Date.now() + 60_000), collapseId: null }));
  for (const wire of [apns, fcm]) {
    assert.ok(!wire.includes('Secret') && !wire.includes('INCOMING_PAYMENT'), wire);
  }
  assert.deepEqual(JSON.parse(apns).aps, { alert: { title: 'New message' }, 'mutable-content': 1, sound: 'default' });
  assert.deepEqual(Object.keys(JSON.parse(fcm).message.data), ['nexus']);
});

test('the APNs provider token is an ES256 JWT that verifies with the auth key', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const token = buildApnsProviderToken('ABCDE12345', 'KEY1234567', privateKey, 1790000000);
  const [header, claims, signature] = token.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url')), { alg: 'ES256', kid: 'KEY1234567' });
  assert.deepEqual(JSON.parse(Buffer.from(claims, 'base64url')), { iss: 'ABCDE12345', iat: 1790000000 });
  assert.equal(Buffer.from(signature, 'base64url').length, 64);
  assert.ok(verify('sha256', Buffer.from(`${header}.${claims}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')));
});

test('APNs responses are classified as Apple documents them', () => {
  const kind = (status, reason) => providers.classifyApnsResponse(status, reason, 'id').kind;
  assert.equal(kind(200, null), 'sent');
  assert.equal(providers.classifyApnsResponse(200, null, 'apns-1').providerMessageId, 'apns-1');
  assert.equal(kind(410, 'Unregistered'), 'unregistered');
  assert.equal(kind(400, 'BadDeviceToken'), 'unregistered');
  assert.equal(kind(400, 'DeviceTokenNotForTopic'), 'unregistered');
  assert.equal(kind(403, 'ExpiredProviderToken'), 'retry');
  assert.equal(kind(429, 'TooManyRequests'), 'retry');
  assert.equal(kind(503, 'ServiceUnavailable'), 'retry');
  assert.equal(kind(413, 'PayloadTooLarge'), 'rejected');
  assert.equal(kind(400, 'BadCollapseId'), 'rejected');
});

test('FCM responses are classified by their error code', () => {
  const fcmError = (status, errorCode) => ({ error: { status: 'X', details: [{ '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError', errorCode }] } });
  assert.deepEqual(providers.classifyFcmResponse(200, { name: 'projects/p/messages/1' }),
    { kind: 'sent', providerMessageId: 'projects/p/messages/1', httpStatus: 200 });
  assert.equal(providers.classifyFcmResponse(404, fcmError(404, 'UNREGISTERED')).kind, 'unregistered');
  assert.equal(providers.classifyFcmResponse(403, fcmError(403, 'SENDER_ID_MISMATCH')).kind, 'unregistered');
  assert.equal(providers.classifyFcmResponse(429, fcmError(429, 'QUOTA_EXCEEDED')).kind, 'retry');
  assert.equal(providers.classifyFcmResponse(503, fcmError(503, 'UNAVAILABLE')).kind, 'retry');
  assert.equal(providers.classifyFcmResponse(401, null).kind, 'retry');
  assert.equal(providers.classifyFcmResponse(400, fcmError(400, 'INVALID_ARGUMENT')).kind, 'rejected');
});

test('FCM messages are data-only, high priority and expire with the message', () => {
  const now = Date.parse('2026-10-01T10:00:00Z');
  const envelope = vectors.messages[1].envelope;
  const message = providers.fcmMessage({ provider: 'FCM', deviceToken: 'token-1', apnsEnvironment: null },
    { messageId: envelope.id, envelope, expiresAt: new Date(now + 120_000), collapseId: 'nexus-authorization' }, now).message;
  assert.equal(message.token, 'token-1');
  assert.equal(message.notification, undefined);
  assert.deepEqual(message.android, { priority: 'HIGH', ttl: '120s', collapse_key: 'nexus-authorization' });
  assert.deepEqual(JSON.parse(message.data.nexus), envelope);
});
