import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { withTransaction, pool } from '../db/pool';
import { recordAuditEvent } from './auditService';
import { NexusIdentityNotFoundError } from './nexusIdentityService';
import type { KeyAlgorithm } from '../types';
import { parseP256PublicKey } from '../crypto/p256PublicKey';
import { ConflictError } from './errors';
import { prepareDeviceKeys, type DeviceKeysInput } from './deviceKeysService';
import { forgetInactivePushRegistrations } from './pushRegistrationService';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { sealCredentialEnrolment, type EnrolmentAttestation, type EnrolmentReason } from './evidenceService';
import { queueReplacementNotice } from './pushService';
import { enqueueWebhook } from './webhookService';
import { consumeDeviceReplacement } from './deviceReplacementService';
import { setOutcomeReason } from './outcomeReason';
import { lockOpenAuthorizations } from './openAuthorizationLocks';

export type CredentialPlatform = 'IOS' | 'ANDROID' | 'OTHER';
export type CredentialState = 'ACTIVE' | 'REVOKED';

export interface CreateCredentialInput {
  nexusId: string;
  publicKeyPem: string;
  platform: CredentialPlatform;
  securityLevel: string;
  attestationStatus: 'UNKNOWN' | 'VERIFIED' | 'FAILED' | 'EXPIRED';
  clientId: string;
  /** The bank's authorization to replace the identity's enrolled device.
   * Without it, enrolment is refused while a credential is not revoked: one
   * NEXUS ID has one active signing key, and a new device must not displace
   * the customer's device silently (the customer uses recovery instead). */
  replacement?: { method: string; reference: string; replacementId?: string; kind?: 'REPLACEMENT' | 'ADDITION' } | null;
  /** Device authentication and offline keys enrolled with the signing key. */
  deviceKeys?: DeviceKeysInput;
  /** Seals the enrolment (keys and attestation) into the identity's evidence chain. */
  hsm: HsmAdapter;
  enrolment: {
    reason: EnrolmentReason;
    attestation: EnrolmentAttestation;
  };
}

export interface CredentialRecord {
  credentialId: string;
  nexusId: string;
  keyAlgorithm: KeyAlgorithm;
  publicKeyPem: string;
  platform: CredentialPlatform;
  securityLevel: string;
  attestationStatus: CreateCredentialInput['attestationStatus'];
  state: CredentialState;
  keyVersion: number;
  createdAt: Date;
  activatedAt: Date | null;
  revokedAt: Date | null;
  lastUsedAt: Date | null;
  /** Present when the device signs its own requests. */
  authPublicKeyPem: string | null;
  /** Server half of the offline key agreement, returned to the device at enrolment. */
  offlineServerPublicKeyPem: string | null;
  offlineEnabled: boolean;
  offlinePublicKeyPem: string | null;
  /** STATIC or PER_AUTHORIZATION (offline v3, finding D-01). */
  offlineKeyAgreement: 'STATIC' | 'PER_AUTHORIZATION';
  /** The sealed CREDENTIAL_ENROLLED record the keys are checked against. */
  enrolmentEvidenceId: string | null;
}

/** Columns every credential query returns. */
const CREDENTIAL_COLUMNS = `credential_id, nexus_id, key_algorithm, public_key_pem, platform,
  security_level, attestation_status, state, key_version, created_at,
  activated_at, revoked_at, last_used_at,
  auth_public_key_pem, offline_server_public_key_pem,
  (offline_secret_encrypted IS NOT NULL OR (offline_key_agreement = 'PER_AUTHORIZATION' AND offline_public_key_pem IS NOT NULL)) AS offline_enabled,
  offline_public_key_pem, offline_key_agreement, enrolment_evidence_id`;

export class CredentialNotFoundError extends Error {
  constructor(credentialId: string) {
    super(`Credential ${credentialId} was not found`);
    this.name = 'CredentialNotFoundError';
  }
}

export async function createCredential(input: CreateCredentialInput): Promise<CredentialRecord> {
  const publicKey = parseP256PublicKey(input.publicKeyPem);
  return withTransaction(async (client) => {
    await lockOpenAuthorizations(client, input.nexusId);
    const identity = await client.query<{ status: string }>(
      `SELECT status FROM nexus_identities WHERE nexus_id = $1 AND client_id = $2 FOR UPDATE`,
      [input.nexusId, input.clientId],
    );
    const identityRow = identity.rows[0];
    if (!identityRow) throw new NexusIdentityNotFoundError(input.nexusId);
    if (identityRow.status !== 'ACTIVE') throw new ConflictError(`NEXUS ID is ${identityRow.status}`);

    // The identity row is locked above, so two concurrent enrolments are
    // decided one after the other.
    const current = await client.query<{ credential_id: string }>(
      `SELECT credential_id FROM credentials WHERE nexus_id = $1 AND state = 'ACTIVE'`, [input.nexusId]);
    const activeCredentialIds = current.rows.map((r) => r.credential_id);
    // An addition (migration 027) keeps the active devices; a replacement
    // revokes them.
    const addition = input.replacement?.kind === 'ADDITION';
    const replacedCredentialIds = addition ? [] : activeCredentialIds;
    if (addition && activeCredentialIds.length === 0) {
      throw new ConflictError('A device can be added only next to an active one; enrol or replace instead', 'NO_ACTIVE_DEVICE');
    }
    if (activeCredentialIds.length > 0 && !input.replacement) {
      throw new ConflictError(
        'The customer already has an enrolled device. Use recovery with the recovery phrase, or issue a replacement token after re-identifying the customer',
        'ACTIVE_CREDENTIAL_EXISTS');
    }
    const credentialId = randomUUID();
    // An identity that had a device before (revoked by the bank, for example)
    // gets a new one only through recovery or a replacement request with its
    // hold; otherwise "revoke, then enrol" would bypass the hold (A2-01).
    const hadDevice = activeCredentialIds.length === 0 && (await client.query(
      `SELECT 1 FROM credentials WHERE nexus_id = $1 AND state = 'REVOKED' LIMIT 1`, [input.nexusId])).rowCount !== 0;
    if (activeCredentialIds.length > 0 || hadDevice) {
      // The request must have been approved on an enrolled device or have
      // passed its hold, and is used once (audit finding A2-01); an addition
      // token uses only an addition request, a replacement token only a
      // replacement request.
      await consumeDeviceReplacement(client, input.nexusId, input.replacement?.replacementId, credentialId, addition ? 'ADDITION' : 'REPLACEMENT');
    }
    if (replacedCredentialIds.length > 0) {
      // Announced on the replaced device while it can still be reached.
      for (const credentialId of replacedCredentialIds) await queueReplacementNotice(client, input.clientId, input.nexusId, credentialId);
      await setOutcomeReason(client, 'DEVICE_REPLACED');
      await client.query(`UPDATE credentials SET state = 'REVOKED', revoked_at = now() WHERE credential_id = ANY($1::uuid[])`, [replacedCredentialIds]);
      await client.query(`UPDATE authorization_requests SET state = 'CANCELLED' WHERE credential_id = ANY($1::uuid[]) AND state = 'PENDING_USER'`, [replacedCredentialIds]);
      await recordAuditEvent('credential_revoked', { nexusId: input.nexusId }, { credentialIds: replacedCredentialIds, reason: 'DEVICE_REPLACED' }, client);
      await forgetInactivePushRegistrations(client, input.nexusId);
    }

    const keys = prepareDeviceKeys(credentialId, publicKey.pem, input.deviceKeys ?? {});
    const result = await client.query<CredentialRow>(
      `INSERT INTO credentials (
        credential_id, nexus_id, key_algorithm, public_key_pem, platform,
        security_level, attestation_status, state, activated_at,
        auth_public_key_pem, offline_public_key_pem, offline_server_public_key_pem, offline_secret_encrypted, offline_key_agreement
      ) VALUES ($1, $2, 'ES256', $3, $4, $5, $6, 'ACTIVE', now(), $7, $8, $9, $10, $11)
      RETURNING ${CREDENTIAL_COLUMNS}`,
      [credentialId, input.nexusId, publicKey.pem, input.platform, input.securityLevel, input.attestationStatus,
        keys.authPublicKeyPem, keys.offlinePublicKeyPem, keys.offlineServerPublicKeyPem, keys.offlineSecretEncrypted, keys.offlineKeyAgreement],
    );
    const enrolment = await sealCredentialEnrolment(client, input.hsm, {
      nexusId: input.nexusId,
      credentialId,
      reason: input.enrolment.reason,
      platform: input.platform,
      securityLevel: input.securityLevel,
      signingPublicKeyPem: publicKey.pem,
      authPublicKeyPem: keys.authPublicKeyPem,
      offlinePublicKeyPem: keys.offlinePublicKeyPem,
      attestation: input.enrolment.attestation,
      replacedCredentialIds,
      replacementAuthorization: (activeCredentialIds.length > 0 || hadDevice) && input.replacement
        ? { method: input.replacement.method, reference: input.replacement.reference, clientId: input.clientId }
        : null,
    });
    if (replacedCredentialIds.length > 0 && input.replacement) {
      await recordAuditEvent('credential_replaced', { nexusId: input.nexusId, actor: `bank:${input.clientId}` },
        { newCredentialId: credentialId, replacedCredentialIds, method: input.replacement.method, reference: input.replacement.reference }, client);
      await enqueueWebhook(input.clientId, 'credential.replaced', {
        nexusId: input.nexusId, newCredentialId: credentialId, replacedCredentialIds,
        method: input.replacement.method, reference: input.replacement.reference, enrolmentEvidenceHash: enrolment.evidenceHash,
      }, client);
    }
    if (addition && input.replacement) {
      // The customer's other devices and the bank learn that a device joined.
      await recordAuditEvent('credential_added', { nexusId: input.nexusId, actor: `bank:${input.clientId}` },
        { newCredentialId: credentialId, activeCredentialIds, method: input.replacement.method, reference: input.replacement.reference }, client);
      await enqueueWebhook(input.clientId, 'credential.added', {
        nexusId: input.nexusId, newCredentialId: credentialId, activeCredentialIds,
        method: input.replacement.method, reference: input.replacement.reference, enrolmentEvidenceHash: enrolment.evidenceHash,
      }, client);
    }
    await recordAuditEvent(
      'credential_created',
      { nexusId: input.nexusId },
      { credentialId, platform: input.platform, securityLevel: input.securityLevel, attestationStatus: input.attestationStatus,
        deviceAuthentication: Boolean(keys.authPublicKeyPem), offlineConfirmation: Boolean(keys.offlineSecretEncrypted),
        reason: input.enrolment.reason, enrolmentEvidenceHash: enrolment.evidenceHash },
      client,
    );
    return { ...mapCredential(result.rows[0]), enrolmentEvidenceId: enrolment.evidenceId };
  });
}

export async function getCredentialForClient(credentialId: string, clientId: string, runner: Pick<PoolClient, 'query'> = pool): Promise<CredentialRecord> {
  const result = await runner.query<CredentialRow>(
    `SELECT ${CREDENTIAL_COLUMNS}
     FROM credentials
     WHERE credential_id = $1 AND nexus_id IN (SELECT nexus_id FROM nexus_identities WHERE client_id = $2)`,
    [credentialId, clientId],
  );
  const row = result.rows[0];
  if (!row) throw new CredentialNotFoundError(credentialId);
  return mapCredential(row);
}

export async function revokeCredentialForClient(credentialId: string, clientId: string, reason: string): Promise<void> {
  await withTransaction(async (client) => {
    const owner = await client.query<{ nexus_id: string }>(`SELECT nexus_id FROM credentials WHERE credential_id = $1`, [credentialId]);
    if (owner.rows[0]) await lockOpenAuthorizations(client, owner.rows[0].nexus_id);
    await setOutcomeReason(client, `REVOKED_BY_BANK:${reason}`);
    const result = await client.query(
      `UPDATE credentials c SET state = 'REVOKED', revoked_at = now()
       FROM nexus_identities n
       WHERE c.credential_id = $1 AND c.nexus_id = n.nexus_id AND n.client_id = $2
         AND c.state = 'ACTIVE'`,
      [credentialId, clientId],
    );
    if (result.rowCount !== 1) throw new CredentialNotFoundError(credentialId);
    const identity = await client.query(`SELECT nexus_id FROM credentials WHERE credential_id = $1`, [credentialId]);
    await setOutcomeReason(client, 'CREDENTIAL_REVOKED');
    const cancelled = await client.query(
      `UPDATE authorization_requests SET state = 'CANCELLED' WHERE credential_id = $1 AND state = 'PENDING_USER'`, [credentialId]);
    await recordAuditEvent('credential_revoked', { nexusId: identity.rows[0]?.nexus_id ?? null },
      { credentialId, reason, cancelledAuthorizations: cancelled.rowCount ?? 0 }, client);
    if (identity.rows[0]?.nexus_id) await forgetInactivePushRegistrations(client, identity.rows[0].nexus_id);
  });
}

/**
 * The customer removes one of their devices from another enrolled device (or
 * from itself), for example a lost tablet. Both must be ACTIVE credentials of
 * the same NEXUS ID; the request is signed by the requesting device. Open
 * payments addressed to the removed device are cancelled with a sealed
 * outcome, and the bank is told.
 */
export async function revokeDeviceByCustomer(clientId: string, nexusId: string, requestingCredentialId: string, targetCredentialId: string): Promise<{ remainingActive: number }> {
  return withTransaction(async (client) => {
    await lockOpenAuthorizations(client, nexusId);
    await client.query(`SELECT 1 FROM nexus_identities WHERE nexus_id = $1 FOR UPDATE`, [nexusId]);
    const rows = await client.query<{ credential_id: string; state: string }>(
      `SELECT credential_id, state FROM credentials WHERE nexus_id = $1 AND credential_id = ANY($2::uuid[]) FOR UPDATE`,
      [nexusId, [requestingCredentialId, targetCredentialId]]);
    const byId = new Map(rows.rows.map((r) => [r.credential_id, r.state]));
    if (byId.get(requestingCredentialId) !== 'ACTIVE') throw new ConflictError('Only an active device of this NEXUS ID removes a device', 'CREDENTIAL_NOT_ACTIVE');
    if (!byId.has(targetCredentialId)) throw new CredentialNotFoundError(targetCredentialId);
    if (byId.get(targetCredentialId) !== 'ACTIVE') throw new ConflictError('The device is already removed', 'CREDENTIAL_NOT_ACTIVE');
    const self = requestingCredentialId === targetCredentialId;
    await setOutcomeReason(client, self ? 'REVOKED_BY_CUSTOMER:SELF' : `REVOKED_BY_CUSTOMER:FROM_${requestingCredentialId}`);
    await client.query(`UPDATE credentials SET state = 'REVOKED', revoked_at = now() WHERE credential_id = $1`, [targetCredentialId]);
    await setOutcomeReason(client, 'CREDENTIAL_REVOKED');
    const cancelled = await client.query(
      `UPDATE authorization_requests SET state = 'CANCELLED' WHERE credential_id = $1 AND state = 'PENDING_USER'`, [targetCredentialId]);
    await recordAuditEvent('credential_revoked', { nexusId, actor: `credential:${requestingCredentialId}` },
      { credentialId: targetCredentialId, reason: 'REVOKED_BY_CUSTOMER', cancelledAuthorizations: cancelled.rowCount ?? 0 }, client);
    await enqueueWebhook(clientId, 'credential.revoked', { nexusId, credentialId: targetCredentialId, reason: 'REVOKED_BY_CUSTOMER', byCredentialId: requestingCredentialId }, client);
    await forgetInactivePushRegistrations(client, nexusId);
    const remaining = await client.query<{ n: number }>(`SELECT count(*)::int AS n FROM credentials WHERE nexus_id = $1 AND state = 'ACTIVE'`, [nexusId]);
    return { remainingActive: remaining.rows[0].n };
  });
}

interface CredentialRow {
  credential_id: string; nexus_id: string; key_algorithm: KeyAlgorithm; public_key_pem: string;
  platform: CredentialPlatform; security_level: string; attestation_status: CredentialRecord['attestationStatus'];
  state: CredentialState; key_version: number; created_at: Date; activated_at: Date | null;
  revoked_at: Date | null; last_used_at: Date | null;
  auth_public_key_pem: string | null; offline_server_public_key_pem: string | null; offline_enabled: boolean;
  offline_public_key_pem: string | null; offline_key_agreement: 'STATIC' | 'PER_AUTHORIZATION'; enrolment_evidence_id: string | null;
}
function mapCredential(row: CredentialRow): CredentialRecord {
  return {
    credentialId: row.credential_id, nexusId: row.nexus_id, keyAlgorithm: row.key_algorithm,
    publicKeyPem: row.public_key_pem, platform: row.platform, securityLevel: row.security_level,
    attestationStatus: row.attestation_status, state: row.state, keyVersion: row.key_version,
    createdAt: row.created_at, activatedAt: row.activated_at,
    revokedAt: row.revoked_at, lastUsedAt: row.last_used_at,
    authPublicKeyPem: row.auth_public_key_pem, offlineServerPublicKeyPem: row.offline_server_public_key_pem,
    offlineEnabled: row.offline_enabled,
    offlinePublicKeyPem: row.offline_public_key_pem,
    offlineKeyAgreement: row.offline_key_agreement,
    enrolmentEvidenceId: row.enrolment_evidence_id,
  };
}


/** An ACTIVE credential of an ACTIVE bank client, for mobile request
 * request authentication (device signatures). */
export async function getActiveDeviceCredential(credentialId: string): Promise<(CredentialRecord & { clientId: string }) | null> {
  const result = await pool.query<CredentialRow & { client_id: string }>(
    `SELECT ${CREDENTIAL_COLUMNS},
       (SELECT n.client_id FROM nexus_identities n WHERE n.nexus_id = credentials.nexus_id) AS client_id
     FROM credentials
     WHERE credential_id = $1 AND state = 'ACTIVE'
       AND EXISTS (SELECT 1 FROM nexus_identities n JOIN bank_clients b ON b.client_id = n.client_id
                   WHERE n.nexus_id = credentials.nexus_id AND b.status = 'ACTIVE')`, [credentialId]);
  const row = result.rows[0];
  return row ? { ...mapCredential(row), clientId: row.client_id } : null;
}

/** True when the identity has a credential that is not revoked. */
export async function hasEnrolledCredential(nexusId: string): Promise<boolean> {
  const result = await pool.query(`SELECT 1 FROM credentials WHERE nexus_id = $1 AND state = 'ACTIVE' LIMIT 1`, [nexusId]);
  return result.rows.length > 0;
}

/** True when the identity had a device that is now revoked. */
export async function hasRevokedCredential(nexusId: string): Promise<boolean> {
  const result = await pool.query(`SELECT 1 FROM credentials WHERE nexus_id = $1 AND state = 'REVOKED' LIMIT 1`, [nexusId]);
  return result.rows.length > 0;
}


