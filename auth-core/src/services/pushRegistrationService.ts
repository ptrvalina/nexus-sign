import { env } from '../config/env';
import { createPublicKey, diffieHellman, generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { parseP256PublicKey } from '../crypto/p256PublicKey';
import { decryptSecretBytes, encryptSecret } from '../crypto/secretBox';
import { recordAuditEvent } from './auditService';
import { getClientPushMode } from './clientService';
import { derivePushKey, pushKeyId } from './pushProtocol';
import type { ApnsEnvironment, PushProvider } from './pushProviders';
import { enqueueWebhook } from './webhookService';
import { ConflictError, ForbiddenError, ValidationError } from './errors';

/**
 * Push registration of an enrolled device: where to reach it (the APNs or FCM
 * token) and the key its messages are sealed with.
 *
 * The push key is agreed once, like the offline key: the device sends an
 * ephemeral P-256 public key, Auth Core answers with its own, and both derive
 * the same 32-byte key (pushProtocol.derivePushKey). Auth Core keeps it
 * encrypted with DEVICE_SECRET_ENCRYPTION_KEY; the device keeps it in its
 * keystore. Token refreshes later update only the token.
 */

export interface PushRegistrationInput {
  provider: PushProvider;
  deviceToken: string;
  apnsEnvironment?: ApnsEnvironment;
  /** Present when the device (re)agrees the push key. */
  devicePublicKeyPem?: string;
  /** Token refresh: the ID of the push key the device holds (pushProtocol.pushKeyId). */
  keyId?: string;
}

export interface PushRegistrationResult {
  status: 'ACTIVE';
  provider: PushProvider;
  /** Returned only when a new push key was agreed. */
  serverPublicKeyPem: string | null;
  /** ID of the key now registered, for the device to compare with its own. */
  keyId: string;
}

export interface DeviceContext {
  clientId: string;
  nexusId: string;
  credentialId: string;
  platform: 'IOS' | 'ANDROID' | 'OTHER';
}

const APNS_TOKEN = /^[0-9a-f]{64,200}$/i;
const FCM_TOKEN = /^[A-Za-z0-9_:\-]{32,4096}$/;

function pushKeyOwner(credentialId: string): string {
  return `push:${credentialId}`;
}

function validate(input: PushRegistrationInput, device: DeviceContext): void {
  if (input.provider === 'APNS') {
    if (device.platform !== 'IOS') throw new ValidationError('APNs registration requires an iOS credential');
    if (!APNS_TOKEN.test(input.deviceToken)) throw new ValidationError('deviceToken is not an APNs device token');
    if (!input.apnsEnvironment) throw new ValidationError('apnsEnvironment is required for APNs');
    // Development builds of the app are not production customers (NXS-037).
    if (input.apnsEnvironment === 'DEVELOPMENT' && env.NODE_ENV === 'production') {
      throw new ValidationError('apnsEnvironment DEVELOPMENT is not accepted in production');
    }
  } else {
    if (device.platform !== 'ANDROID') throw new ValidationError('FCM registration requires an Android credential');
    if (!FCM_TOKEN.test(input.deviceToken)) throw new ValidationError('deviceToken is not an FCM registration token');
    if (input.apnsEnvironment) throw new ValidationError('apnsEnvironment applies to APNs only');
  }
}

export async function registerPushDevice(device: DeviceContext, input: PushRegistrationInput): Promise<PushRegistrationResult> {
  if ((await getClientPushMode(device.clientId)) !== 'NEXUS') {
    // 403, not 409: 409 tells the SDK to agree a new key.
    throw new ForbiddenError('Secure push is not enabled for this bank; its own push system delivers messages');
  }
  validate(input, device);
  const apnsEnvironment = input.provider === 'APNS' ? input.apnsEnvironment ?? null : null;

  if (!input.devicePublicKeyPem) {
    if (!input.keyId) throw new ValidationError('keyId is required for a token refresh');
    // Only when the device holds the key Auth Core holds; otherwise 409 and
    // the device agrees a new one.
    const updated = await pool.query(
      `UPDATE push_registrations
       SET provider = $2, apns_environment = $3, device_token = $4, status = 'ACTIVE', last_error = NULL, invalidated_at = NULL, updated_at = now()
       WHERE credential_id = $1 AND push_key_id = $5`,
      [device.credentialId, input.provider, apnsEnvironment, input.deviceToken, input.keyId]);
    if (updated.rowCount !== 1) throw new ConflictError('This device holds no push key Auth Core knows; send devicePublicKeyPem');
    await recordAuditEvent('push_registered', { nexusId: device.nexusId }, { credentialId: device.credentialId, provider: input.provider, keyAgreed: false });
    return { status: 'ACTIVE', provider: input.provider, serverPublicKeyPem: null, keyId: input.keyId };
  }

  const devicePublicKey = parseP256PublicKey(input.devicePublicKeyPem);
  // A fresh server key per agreement; its private half is used once and discarded.
  const server = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const shared = diffieHellman({ privateKey: server.privateKey, publicKey: createPublicKey(devicePublicKey.pem) });
  const pushKey = derivePushKey(shared, device.credentialId);
  shared.fill(0);
  const encrypted = encryptSecret(pushKey, 'device', pushKeyOwner(device.credentialId));
  const keyId = pushKeyId(pushKey);
  pushKey.fill(0);

  await withTransaction(async (tx) => {
    await tx.query(
      `INSERT INTO push_registrations (credential_id, provider, apns_environment, device_token, push_key_encrypted, push_key_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (credential_id) DO UPDATE
         SET provider = EXCLUDED.provider, apns_environment = EXCLUDED.apns_environment, device_token = EXCLUDED.device_token,
             push_key_encrypted = EXCLUDED.push_key_encrypted, push_key_id = EXCLUDED.push_key_id,
             status = 'ACTIVE', last_error = NULL, invalidated_at = NULL, updated_at = now()`,
      [device.credentialId, input.provider, apnsEnvironment, input.deviceToken, encrypted, keyId]);
    // Messages still queued were sealed under the previous key, which the
    // device no longer has.
    await failQueuedMessages(tx, device.credentialId, 'PUSH_KEY_REPLACED');
    await recordAuditEvent('push_registered', { nexusId: device.nexusId }, { credentialId: device.credentialId, provider: input.provider, keyAgreed: true }, tx);
  });
  return {
    status: 'ACTIVE',
    provider: input.provider,
    serverPublicKeyPem: server.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    keyId,
  };
}

/** Fails a credential's queued messages and reports each with push.failed. */
async function failQueuedMessages(tx: PoolClient, credentialId: string, reason: string): Promise<void> {
  const failed = await tx.query<{ message_id: string; client_id: string; nexus_id: string; category: string; authorization_id: string | null }>(
    `UPDATE push_messages SET status = 'FAILED', last_error = $2
     WHERE credential_id = $1 AND status = 'QUEUED' AND NOT replacement_notice
     RETURNING message_id, client_id, nexus_id, category, authorization_id`, [credentialId, reason]);
  for (const row of failed.rows) {
    await enqueueWebhook(row.client_id, 'push.failed',
      { messageId: row.message_id, nexusId: row.nexus_id, category: row.category, authorizationId: row.authorization_id, reason }, tx);
  }
}

/**
 * Removes the push registrations of an identity's credentials that are no
 * longer ACTIVE, in the transaction that revoked them: a revoked device keeps
 * neither its token nor its push key. Its queued messages fail.
 */
export async function forgetInactivePushRegistrations(tx: PoolClient, nexusId: string): Promise<void> {
  const inactive = await tx.query<{ credential_id: string }>(
    `SELECT r.credential_id FROM push_registrations r JOIN credentials c ON c.credential_id = r.credential_id
     WHERE c.nexus_id = $1 AND c.state <> 'ACTIVE'`, [nexusId]);
  for (const row of inactive.rows) await failQueuedMessages(tx, row.credential_id, 'NO_ACTIVE_REGISTRATION');
  // A replaced device keeps its registration until its replacement notice is sent.
  await tx.query(
    `DELETE FROM push_registrations r USING credentials c
     WHERE r.credential_id = c.credential_id AND c.nexus_id = $1 AND c.state <> 'ACTIVE'
       AND NOT EXISTS (SELECT 1 FROM push_messages m WHERE m.credential_id = r.credential_id AND m.replacement_notice AND m.status = 'QUEUED')`,
    [nexusId]);
}

/** The app turned notifications off or the customer signed out of push. */
export async function unregisterPushDevice(device: DeviceContext): Promise<void> {
  await withTransaction(async (tx) => {
    const deleted = await tx.query(`DELETE FROM push_registrations WHERE credential_id = $1`, [device.credentialId]);
    if ((deleted.rowCount ?? 0) === 0) return;
    await failQueuedMessages(tx, device.credentialId, 'NO_ACTIVE_REGISTRATION');
    await recordAuditEvent('push_unregistered', { nexusId: device.nexusId }, { credentialId: device.credentialId, reason: 'DEVICE_REQUEST' }, tx);
  });
}

export function decryptPushKey(stored: string, credentialId: string): Buffer {
  return decryptSecretBytes(stored, 'device', pushKeyOwner(credentialId));
}
