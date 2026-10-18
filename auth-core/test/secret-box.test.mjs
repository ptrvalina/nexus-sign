// FI-005: ciphertext formats and the master key ring of secretBox.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { loadTs } from './support/load-ts.mjs';

const k = () => randomBytes(32).toString('base64');
const load = (env) => loadTs('crypto/secretBox.ts', { stubs: { '../config/env': { env } } });

/** The formats written before 2.0.0, produced independently of secretBox.ts. */
function legacy(keyB64, plaintext, aad, prefix) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(keyB64, 'base64'), iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return [...(prefix ? [prefix] : []), iv.toString('base64'), cipher.getAuthTag().toString('base64'), ct.toString('base64')].join('$');
}

test('new ciphertexts name their key and are bound to purpose and owner', () => {
  const key = k();
  const box = load({ DEVICE_SECRET_ENCRYPTION_KEY: key, WEBHOOK_SECRET_ENCRYPTION_KEY: k() });
  const stored = box.encryptSecret('offline-key', 'device', 'cred-1');
  const [format, id] = stored.split('$');
  assert.equal(format, 'k1');
  assert.equal(id, box.masterKeyId(Buffer.from(key, 'base64')));
  assert.equal(box.decryptSecret(stored, 'device', 'cred-1'), 'offline-key');
  assert.throws(() => box.decryptSecret(stored, 'device', 'cred-2'), 'bound to its owner');
  assert.throws(() => box.decryptSecret(stored, 'webhook', 'cred-1'), 'bound to its purpose');
  assert.throws(() => box.decryptSecret(stored.replace(id, '0'.repeat(16)), 'device', 'cred-1'), /neither DEVICE_SECRET_ENCRYPTION_KEY nor listed in DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS/);
});

test('formats before 2.0.0 are still read, under the current or a previous key', () => {
  const oldKey = k(); const newKey = k();
  const before = load({ DEVICE_SECRET_ENCRYPTION_KEY: oldKey, WEBHOOK_SECRET_ENCRYPTION_KEY: oldKey, ADMIN_SECRET_ENCRYPTION_KEY: oldKey });
  const device = legacy(oldKey, 'd', 'device:cred-1');
  const webhookV2 = legacy(oldKey, 'w2', 'webhook:bank-1', 'v2');
  const webhookV1 = legacy(oldKey, 'w1', null);
  const admin = legacy(oldKey, 'a', 'admin:alice');
  assert.equal(before.decryptSecret(device, 'device', 'cred-1'), 'd');
  assert.equal(before.decryptSecret(webhookV2, 'webhook', 'bank-1'), 'w2');
  assert.equal(before.decryptSecret(webhookV1, 'webhook', 'bank-1'), 'w1');
  assert.equal(before.decryptSecret(admin, 'admin', 'alice'), 'a');

  const rotating = load({
    DEVICE_SECRET_ENCRYPTION_KEY: newKey, DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS: oldKey,
    WEBHOOK_SECRET_ENCRYPTION_KEY: newKey, WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: `${k()},${oldKey}`,
  });
  assert.equal(rotating.decryptSecret(device, 'device', 'cred-1'), 'd', 'legacy under a previous key');
  assert.equal(rotating.decryptSecret(webhookV2, 'webhook', 'bank-1'), 'w2', 'second previous key');
  assert.equal(rotating.needsRewrap(device, 'device'), true);
  const rewrapped = rotating.rewrapSecret(device, 'device', 'cred-1');
  assert.equal(rotating.needsRewrap(rewrapped, 'device'), false);
  assert.equal(rotating.decryptSecret(rewrapped, 'device', 'cred-1'), 'd');

  const after = load({ DEVICE_SECRET_ENCRYPTION_KEY: newKey });
  assert.equal(after.decryptSecret(rewrapped, 'device', 'cred-1'), 'd', 'no previous key needed after rewrap');
  assert.throws(() => after.decryptSecret(device, 'device', 'cred-1'), 'legacy ciphertext under a removed key');
});

test('a previous key that is malformed is refused', () => {
  const box = load({ DEVICE_SECRET_ENCRYPTION_KEY: k(), DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS: 'c2hvcnQ=' });
  assert.throws(() => box.encryptSecret('x', 'device', 'c'), /DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS must decode to exactly 32 bytes/);
});
