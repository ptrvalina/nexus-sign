import { createHash, createPublicKey, randomBytes, randomUUID, timingSafeEqual, verify } from 'node:crypto';
import { pool, withTransaction } from '../db/pool';
import { redis } from '../db/redis';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { recordAuditEvent } from './auditService';
import { type CredentialPlatform, type CredentialRecord } from './credentialService';
import { NexusIdentityNotFoundError } from './nexusIdentityService';
import { parseP256PublicKey } from '../crypto/p256PublicKey';
import { ConflictError, ValidationError } from './errors';
import { prepareDeviceKeys, type DeviceKeysInput } from './deviceKeysService';
import { forgetInactivePushRegistrations } from './pushRegistrationService';
import { queueReplacementNotice } from './pushService';
import { getEvidenceRecord, sealCredentialEnrolment, sealRecoveryConfiguration, type EnrolmentAttestation } from './evidenceService';
import { sealProblem } from './credentialIntegrity';
import { enqueueWebhook } from './webhookService';
import { setOutcomeReason } from './outcomeReason';

/**
 * Account recovery, protocol 2 (docs/protocol/recovery-protocol-v2.md).
 *
 * Setup, on the enrolled device, with a fresh salt from Auth Core:
 *   seed     = PBKDF2-HMAC-SHA256(normalized phrase, salt, iterations, 32)
 *   wrapKey  = HKDF-SHA256(seed, salt "NEXUS-SIGN/RECOVERY-WRAP/v2", info nexusId, 32)
 *   (d, Q)   = a new random P-256 key pair
 *   wrapped  = iv || AES-256-GCM(wrapKey, iv, d, aad = recoveryWrapAssociatedData(nexusId, Q))
 * The device sends Q and `wrapped`, signed with its biometric signing key;
 * Auth Core stores Q and `wrapped` and seals Q into the evidence chain.
 *
 * Recovery, on a new device, after the bank re-identified the customer: the
 * session returns `wrapped`, the device re-derives wrapKey from the phrase,
 * recovers d and signs recoveryProofSigningInput (session, nonce, identity
 * and the new signing key) with it.
 *
 * Nothing stored by Auth Core lets anyone complete a recovery without the
 * phrase: Q only verifies, and `wrapped` needs the phrase (128 bits of entropy
 * stretched by PBKDF2) to be opened. Protocol 1 (SDK 1.x) stored an HMAC
 * key that was itself enough to produce a proof; identities still on it are
 * refused with RECOVERY_PROTOCOL_RETIRED and set up a new phrase.
 */
export const RECOVERY_PROTOCOL = 2;
const ITERATIONS = 210_000;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const NONCE_LENGTH = 32;
const WRAPPED_KEY_LENGTH = 12 + 32 + 16; // iv || encrypted scalar || GCM tag
const SESSION_TTL_SECONDS = 600;
const SETUP_TTL_SECONDS = 600;
const MAX_ATTEMPTS = 5;
/** Failed proofs per NEXUS ID across all sessions in RECOVERY_FAILURE_WINDOW. */
const MAX_IDENTITY_FAILURES = 10;
const RECOVERY_FAILURE_WINDOW = '24 hours';

export const RECOVERY_WRAP_SALT = 'NEXUS-SIGN/RECOVERY-WRAP/v2';

export class RecoveryNotConfiguredError extends Error {
  constructor() { super('Recovery has not been configured for this NEXUS ID'); this.name = 'RecoveryNotConfiguredError'; }
}
/**
 * A recovery phrase recovers the identity once (audit finding A2-02): after a
 * completed recovery the recovered device must set up a new phrase, so a
 * phished phrase cannot take the identity back after the owner recovered it.
 * Used means a completed recovery at or after the configuration was stored.
 */
async function assertPhraseNotUsed(runner: Pick<import('pg').PoolClient, 'query'>, nexusId: string): Promise<void> {
  const used = await runner.query(
    `SELECT 1 FROM recovery_sessions r JOIN nexus_identities i ON i.nexus_id = r.nexus_id
      WHERE r.nexus_id = $1 AND r.used_at IS NOT NULL AND r.used_at >= coalesce(i.recovery_updated_at, '-infinity'::timestamptz) LIMIT 1`, [nexusId]);
  if ((used.rowCount ?? 0) > 0) {
    throw new ConflictError('This recovery phrase was already used; the customer must set up a new recovery phrase on the recovered device', 'RECOVERY_PHRASE_USED');
  }
}

export class RecoverySessionNotFoundError extends Error {
  constructor() { super('Recovery session not found or expired'); this.name = 'RecoverySessionNotFoundError'; }
}
export class InvalidRecoveryProofError extends Error {
  constructor() { super('Invalid recovery proof'); this.name = 'InvalidRecoveryProofError'; }
}

export interface RecoveryParameters {
  protocol: number;
  kdf: 'PBKDF2-HMAC-SHA256';
  iterations: number;
  keyLength: number;
  salt: string;
  /** Returned during setup so the device binds the wrapped key to its identity. */
  nexusId?: string;
  credentialId?: string;
}

const sha256hex = (value: Buffer): string => createHash('sha256').update(value).digest('hex');
const spkiOf = (pem: string): Buffer => createPublicKey(pem).export({ type: 'spki', format: 'der' });

/** AES-GCM associated data of the wrapped recovery key: binds it to the
 * identity and to its public key. */
export function recoveryWrapAssociatedData(nexusId: string, recoveryPublicKeySpki: Buffer): Buffer {
  return Buffer.from(`NEXUS-SIGN/RECOVERY-KEY/v2\n${nexusId}\n${sha256hex(recoveryPublicKeySpki)}`, 'utf8');
}

/** What the device's biometric signing key signs to register a recovery key. */
export function recoverySetupSigningInput(input: { nexusId: string; credentialId: string; saltB64: string; recoveryPublicKeySpki: Buffer; wrappedRecoveryKey: Buffer }): Buffer {
  return Buffer.from(['NEXUS-SIGN/RECOVERY-SETUP/v2', input.nexusId, input.credentialId, input.saltB64,
    sha256hex(input.recoveryPublicKeySpki), sha256hex(input.wrappedRecoveryKey)].join('\n'), 'utf8');
}

/** What the recovery key signs to complete one recovery session. */
export function recoveryProofSigningInput(input: { sessionId: string; nonceB64: string; nexusId: string; newSigningKeySpki: Buffer }): Buffer {
  return Buffer.from(['NEXUS-SIGN/RECOVERY-PROOF/v2', input.sessionId, input.nonceB64, input.nexusId, sha256hex(input.newSigningKeySpki)].join('\n'), 'utf8');
}

const setupKey = (credentialId: string): string => `recovery_setup:${credentialId}`;

/** Fresh PBKDF2 parameters for the device. The salt is remembered for this
 * credential, so the setup that follows must use exactly this salt. */
export async function beginRecoverySetup(nexusId: string, clientId: string, credentialId: string): Promise<RecoveryParameters> {
  const identity = await pool.query(`SELECT nexus_id FROM nexus_identities WHERE nexus_id=$1 AND client_id=$2 AND status='ACTIVE'`, [nexusId, clientId]);
  if (!identity.rows[0]) throw new NexusIdentityNotFoundError(nexusId);
  const salt = randomBytes(SALT_LENGTH).toString('base64');
  await redis.set(setupKey(credentialId), salt, 'EX', SETUP_TTL_SECONDS);
  return { protocol: RECOVERY_PROTOCOL, kdf: 'PBKDF2-HMAC-SHA256', iterations: ITERATIONS, keyLength: KEY_LENGTH, salt, nexusId, credentialId };
}

export interface RecoverySetupInput {
  nexusId: string;
  clientId: string;
  /** The device credential; its keys have passed the integrity check. */
  credential: CredentialRecord;
  saltB64: string;
  recoveryPublicKeyPem: string;
  wrappedRecoveryKeyB64: string;
  /** The device signing key's signature over recoverySetupSigningInput. */
  signatureB64: string;
  hsm: HsmAdapter;
}

/** Registers (or replaces) the identity's recovery key. Replacing it needs
 * the customer's biometric signature, like a transaction. */
export async function completeRecoverySetup(input: RecoverySetupInput): Promise<void> {
  const issuedSalt = await redis.getdel(setupKey(input.credential.credentialId));
  if (!issuedSalt || issuedSalt !== input.saltB64) {
    throw new ConflictError('Recovery setup parameters expired or do not match; request new parameters', 'RECOVERY_SETUP_EXPIRED');
  }
  const recoveryKey = parseP256PublicKey(input.recoveryPublicKeyPem);
  const recoverySpki = spkiOf(recoveryKey.pem);
  const wrapped = decodeBase64(input.wrappedRecoveryKeyB64);
  if (!wrapped || wrapped.length !== WRAPPED_KEY_LENGTH) throw new ValidationError('wrappedRecoveryKey must be 60 bytes (iv, encrypted key, tag)');
  const signature = decodeBase64(input.signatureB64);
  const signed = recoverySetupSigningInput({
    nexusId: input.nexusId, credentialId: input.credential.credentialId, saltB64: input.saltB64, recoveryPublicKeySpki: recoverySpki, wrappedRecoveryKey: wrapped,
  });
  if (!signature || !(await input.hsm.verifySignature(input.credential.publicKeyPem, signed, signature, 'der'))) {
    await recordAuditEvent('recovery_setup_rejected', { nexusId: input.nexusId }, { credentialId: input.credential.credentialId, reason: 'signature' });
    throw new ValidationError('The recovery setup is not signed by the device signing key');
  }

  await withTransaction(async (tx) => {
    const identity = await tx.query(`SELECT nexus_id FROM nexus_identities WHERE nexus_id=$1 AND client_id=$2 AND status='ACTIVE' FOR UPDATE`, [input.nexusId, input.clientId]);
    if (!identity.rows[0]) throw new NexusIdentityNotFoundError(input.nexusId);
    const credential = await tx.query(`SELECT 1 FROM credentials WHERE credential_id=$1 AND nexus_id=$2 AND state='ACTIVE' FOR SHARE`, [input.credential.credentialId, input.nexusId]);
    if (!credential.rows[0]) throw new ConflictError('The device credential is no longer active');
    const salt = Buffer.from(input.saltB64, 'base64');
    await tx.query(
      `UPDATE nexus_identities SET recovery_protocol=2, recovery_public_key_pem=$2, recovery_wrapped_key=$3, recovery_kdf_salt=$4,
         recovery_kdf_iterations=$5, recovery_updated_at=now(), updated_at=now()
       WHERE nexus_id=$1`, [input.nexusId, recoveryKey.pem, wrapped, salt, ITERATIONS]);
    const position = await sealRecoveryConfiguration(tx, input.hsm, {
      nexusId: input.nexusId,
      credentialId: input.credential.credentialId,
      recoveryProtocol: RECOVERY_PROTOCOL,
      recoveryPublicKeyPem: recoveryKey.pem,
      wrappedRecoveryKeySha256: sha256hex(wrapped),
      kdfSaltB64: input.saltB64,
      kdfIterations: ITERATIONS,
    });
    await recordAuditEvent('recovery_configured', { nexusId: input.nexusId },
      { protocol: RECOVERY_PROTOCOL, credentialId: input.credential.credentialId, evidenceHash: position.evidenceHash }, tx);
    await enqueueWebhook(input.clientId, 'recovery.configured',
      { nexusId: input.nexusId, credentialId: input.credential.credentialId, configuredAt: new Date().toISOString() }, tx);
  });
}

export interface CreatedRecoverySession {
  sessionId: string;
  nexusId: string;
  nonce: string;
  accessToken: string;
  parameters: RecoveryParameters;
  /** The recovery public key and the key wrapped for the device. */
  recoveryPublicKeyPem: string;
  wrappedRecoveryKey: string;
  expiresAt: Date;
}

export async function createRecoverySession(bankCustomerRef: string, clientId: string): Promise<CreatedRecoverySession> {
  const result = await pool.query<{ nexus_id: string; recovery_protocol: number | null; recovery_kdf_salt: Buffer | null; recovery_kdf_iterations: number | null; recovery_public_key_pem: string | null; recovery_wrapped_key: Buffer | null; recovery_evidence_id: string | null }>(
    `SELECT nexus_id, recovery_protocol, recovery_kdf_salt, recovery_kdf_iterations, recovery_public_key_pem, recovery_wrapped_key, recovery_evidence_id
     FROM nexus_identities WHERE bank_customer_ref=$1 AND client_id=$2 AND status='ACTIVE'`, [bankCustomerRef, clientId]);
  const row = result.rows[0];
  if (!row) throw new NexusIdentityNotFoundError(bankCustomerRef);
  if (!row.recovery_protocol || !row.recovery_kdf_salt || !row.recovery_kdf_iterations) throw new RecoveryNotConfiguredError();
  if (row.recovery_protocol !== RECOVERY_PROTOCOL) {
    throw new ConflictError('The recovery phrase uses retired protocol 1; the customer must set up a new recovery phrase', 'RECOVERY_PROTOCOL_RETIRED');
  }
  await assertPhraseNotUsed(pool, row.nexus_id);
  const failures = await identityRecoveryFailures(pool, row.nexus_id);
  if (failures >= MAX_IDENTITY_FAILURES) {
    await recordAuditEvent('recovery_locked', { nexusId: row.nexus_id, actor: `bank:${clientId}` }, { failures });
    throw recoveryLocked();
  }
  // What the device receives must be what it registered.
  if (!row.recovery_public_key_pem || !row.recovery_wrapped_key) throw new RecoveryNotConfiguredError();
  await assertRecoveryKeyIntegrity(pool, row.nexus_id, row.recovery_evidence_id, row.recovery_public_key_pem, row.recovery_wrapped_key,
    { saltB64: row.recovery_kdf_salt.toString('base64'), iterations: row.recovery_kdf_iterations });

  const sessionId = randomUUID();
  const accessToken = `rc_${randomBytes(32).toString('base64url')}`;
  const accessTokenHash = createHash('sha256').update(accessToken).digest();
  const nonce = randomBytes(NONCE_LENGTH);
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
  await pool.query(
    `INSERT INTO recovery_sessions (recovery_session_id,nexus_id,client_id,nonce,nonce_hash,kdf_salt,kdf_algorithm,access_token_hash,access_token_expires_at,expires_at,protocol,created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())`,
    [sessionId, row.nexus_id, clientId, nonce, sha256hex(nonce), row.recovery_kdf_salt, 'PBKDF2-HMAC-SHA256', accessTokenHash, expiresAt, expiresAt, row.recovery_protocol]);
  await recordAuditEvent('recovery_started', { nexusId: row.nexus_id, bankCustomerRef, actor: `bank:${clientId}` }, { recoverySessionId: sessionId, protocol: row.recovery_protocol });
  return {
    sessionId,
    nexusId: row.nexus_id,
    nonce: nonce.toString('base64'),
    accessToken,
    parameters: { protocol: row.recovery_protocol, kdf: 'PBKDF2-HMAC-SHA256', iterations: row.recovery_kdf_iterations, keyLength: KEY_LENGTH, salt: row.recovery_kdf_salt.toString('base64') },
    recoveryPublicKeyPem: row.recovery_public_key_pem,
    wrappedRecoveryKey: row.recovery_wrapped_key.toString('base64'),
    expiresAt,
  };
}

/** The nonce of an open, unexpired recovery session, after its access token is checked. */
export async function getRecoveryAttestationBinding(sessionId: string, accessToken: string): Promise<Buffer> {
  const result = await pool.query<{ nonce: Buffer; access_token_hash: Buffer; expires_at: Date; access_token_expires_at: Date; used_at: Date | null }>(
    `SELECT nonce,access_token_hash,expires_at,access_token_expires_at,used_at FROM recovery_sessions WHERE recovery_session_id=$1`,
    [sessionId],
  );
  const session = result.rows[0];
  if (!session || session.used_at || session.expires_at.getTime() <= Date.now() || session.access_token_expires_at.getTime() <= Date.now()) throw new RecoverySessionNotFoundError();
  const tokenHash = createHash('sha256').update(accessToken).digest();
  if (!timingSafeEqual(session.access_token_hash, tokenHash)) throw new RecoverySessionNotFoundError();
  return session.nonce;
}

export interface CompleteRecoveryInput {
  sessionId: string;
  accessToken: string;
  proofB64: string;
  newPublicKeyPem: string;
  platform: CredentialPlatform;
  securityLevel: string;
  attestationStatus: 'UNKNOWN' | 'VERIFIED' | 'FAILED' | 'EXPIRED';
  attestation: EnrolmentAttestation;
  deviceKeys?: DeviceKeysInput;
  hsm: HsmAdapter;
}

/** Failed recovery proofs of a NEXUS ID, across all its sessions, in RECOVERY_FAILURE_WINDOW. */
async function identityRecoveryFailures(runner: Pick<import('pg').PoolClient, 'query'>, nexusId: string): Promise<number> {
  const result = await runner.query<{ failures: string }>(
    `SELECT COALESCE(SUM(failed_attempt_count), 0) AS failures FROM recovery_sessions
     WHERE nexus_id = $1 AND created_at > now() - interval '${RECOVERY_FAILURE_WINDOW}'`, [nexusId]);
  return Number(result.rows[0]?.failures ?? 0);
}

const recoveryLocked = () => new ConflictError('Too many failed recovery attempts for this customer; try again later', 'RECOVERY_LOCKED');

export async function completeRecovery(input: CompleteRecoveryInput): Promise<RecoveryResult> {
  // A wrong proof must be committed as a failed attempt; throwing inside the
  // transaction would roll back the attempt counter and the audit event. The
  // transaction returns a sentinel instead, and the error is raised after commit.
  const newPublicKey = parseP256PublicKey(input.newPublicKeyPem);
  const outcome = await withTransaction(async (tx): Promise<RecoveryResult | 'INVALID_PROOF'> => {
    const session = await tx.query<{ recovery_session_id: string; nexus_id: string; client_id: string; nonce: Buffer; expires_at: Date; access_token_expires_at: Date; access_token_hash: Buffer; used_at: Date | null; attempt_count: number; protocol: number }>(
      `SELECT recovery_session_id,nexus_id,client_id,nonce,expires_at,access_token_expires_at,access_token_hash,used_at,attempt_count,protocol
       FROM recovery_sessions WHERE recovery_session_id=$1 FOR UPDATE`, [input.sessionId]);
    const s = session.rows[0];
    if (!s || s.used_at || s.expires_at.getTime() <= Date.now() || s.access_token_expires_at.getTime() <= Date.now()) throw new RecoverySessionNotFoundError();
    const accessTokenHash = createHash('sha256').update(input.accessToken).digest();
    if (!s.access_token_hash || s.access_token_hash.length !== accessTokenHash.length || !timingSafeEqual(s.access_token_hash, accessTokenHash)) throw new RecoverySessionNotFoundError();
    if (s.attempt_count >= MAX_ATTEMPTS) throw new RecoverySessionNotFoundError();
    const identity = await tx.query<{ nexus_id: string; recovery_protocol: number | null; recovery_public_key_pem: string | null; recovery_wrapped_key: Buffer | null; recovery_evidence_id: string | null }>(
      `SELECT nexus_id, recovery_protocol, recovery_public_key_pem, recovery_wrapped_key, recovery_evidence_id
       FROM nexus_identities WHERE nexus_id=$1 AND client_id=$2 AND status='ACTIVE'
         AND client_id IN (SELECT client_id FROM bank_clients WHERE status='ACTIVE') FOR UPDATE`, [s.nexus_id, s.client_id]);
    const i = identity.rows[0];
    if (!i) throw new ConflictError('NEXUS ID is not ACTIVE; recovery is not possible');
    if (!i.recovery_protocol || i.recovery_protocol !== s.protocol) throw new RecoveryNotConfiguredError();

    if (i.recovery_protocol !== RECOVERY_PROTOCOL) {
      throw new ConflictError('The recovery phrase uses retired protocol 1; the customer must set up a new recovery phrase', 'RECOVERY_PROTOCOL_RETIRED');
    }
    if (!i.recovery_public_key_pem || !i.recovery_wrapped_key) throw new RecoveryNotConfiguredError();
    await assertPhraseNotUsed(tx, s.nexus_id);
    // The identity-wide limit applies to every attempt, not only when a session
    // is opened: sessions opened in parallel share it (finding A2-04). The
    // identity row is locked above, so attempts of one identity are serialized.
    if (await identityRecoveryFailures(tx, s.nexus_id) >= MAX_IDENTITY_FAILURES) throw recoveryLocked();
    await assertRecoveryKeyIntegrity(tx, s.nexus_id, i.recovery_evidence_id, i.recovery_public_key_pem, i.recovery_wrapped_key);
    const proof = decodeBase64(input.proofB64);
    const signed = recoveryProofSigningInput({ sessionId: s.recovery_session_id, nonceB64: s.nonce.toString('base64'), nexusId: s.nexus_id, newSigningKeySpki: spkiOf(newPublicKey.pem) });
    const proofValid = proof !== null && verifyEcdsa(i.recovery_public_key_pem, signed, proof);
    await tx.query(`UPDATE recovery_sessions SET attempt_count=attempt_count+1, failed_attempt_count=failed_attempt_count+$2 WHERE recovery_session_id=$1`,
      [input.sessionId, proofValid ? 0 : 1]);
    if (!proofValid) {
      await recordAuditEvent('recovery_failed', { nexusId: s.nexus_id }, { recoverySessionId: input.sessionId, reason: 'invalid_proof', attempt: s.attempt_count + 1 }, tx);
      return 'INVALID_PROOF';
    }

    const oldCredentials = await tx.query<{ credential_id: string; key_version: number }>(
      `SELECT credential_id,key_version FROM credentials WHERE nexus_id=$1 AND state = 'ACTIVE' FOR UPDATE`, [s.nexus_id]);
    const revokedIds = oldCredentials.rows.map((c) => c.credential_id);
    // Announced on the old device while it can still be reached, as for a
    // device replacement (audit finding A2-02): the owner learns that the
    // identity moved, also when someone else recovered it with a phished phrase.
    for (const credentialId of revokedIds) await queueReplacementNotice(tx, s.client_id, s.nexus_id, credentialId);
    await setOutcomeReason(tx, 'IDENTITY_RECOVERED');
    if (revokedIds.length > 0) await tx.query(`UPDATE credentials SET state='REVOKED',revoked_at=now() WHERE credential_id = ANY($1::uuid[])`, [revokedIds]);
    await tx.query(`UPDATE authorization_requests SET state='CANCELLED' WHERE nexus_id=$1 AND state='PENDING_USER'`, [s.nexus_id]);
    await forgetInactivePushRegistrations(tx, s.nexus_id);
    const nextVersion = Math.max(1, ...oldCredentials.rows.map((c) => c.key_version)) + 1;
    const newId = randomUUID();
    const keys = prepareDeviceKeys(newId, newPublicKey.pem, input.deviceKeys ?? {});
    const created = await tx.query<{ credential_id: string; key_version: number }>(
      `INSERT INTO credentials (credential_id,nexus_id,key_algorithm,public_key_pem,platform,security_level,attestation_status,state,key_version,activated_at,
         auth_public_key_pem,offline_public_key_pem,offline_server_public_key_pem,offline_secret_encrypted)
       VALUES ($1,$2,'ES256',$3,$4,$5,$6,'ACTIVE',$7,now(),$8,$9,$10,$11) RETURNING credential_id,key_version`,
      [newId, s.nexus_id, newPublicKey.pem, input.platform, input.securityLevel, input.attestationStatus, nextVersion,
        keys.authPublicKeyPem, keys.offlinePublicKeyPem, keys.offlineServerPublicKeyPem, keys.offlineSecretEncrypted]);
    const enrolment = await sealCredentialEnrolment(tx, input.hsm, {
      nexusId: s.nexus_id,
      credentialId: newId,
      reason: 'RECOVERY',
      platform: input.platform,
      securityLevel: input.securityLevel,
      signingPublicKeyPem: newPublicKey.pem,
      authPublicKeyPem: keys.authPublicKeyPem,
      offlinePublicKeyPem: keys.offlinePublicKeyPem,
      attestation: input.attestation,
      replacedCredentialIds: revokedIds,
      replacementAuthorization: null,
    });
    await tx.query(`UPDATE recovery_sessions SET used_at=now() WHERE recovery_session_id=$1`, [input.sessionId]);
    await recordAuditEvent('credential_revoked', { nexusId: s.nexus_id }, { reason: 'RECOVERY', credentialIds: revokedIds }, tx);
    await recordAuditEvent('credential_created', { nexusId: s.nexus_id }, { credentialId: newId, reason: 'RECOVERY', keyVersion: created.rows[0].key_version, enrolmentEvidenceHash: enrolment.evidenceHash }, tx);
    await recordAuditEvent('recovery_completed', { nexusId: s.nexus_id }, { recoverySessionId: input.sessionId, credentialId: newId, protocol: i.recovery_protocol }, tx);
    await enqueueWebhook(s.client_id, 'identity.recovered', { nexusId: s.nexus_id, newCredentialId: newId, revokedCredentialIds: revokedIds }, tx);
    return { nexusId: s.nexus_id, credentialId: newId, keyVersion: created.rows[0].key_version, offlineServerPublicKeyPem: keys.offlineServerPublicKeyPem };
  });
  if (outcome === 'INVALID_PROOF') throw new InvalidRecoveryProofError();
  return outcome;
}

export interface RecoveryResult { nexusId: string; credentialId: string; keyVersion: number; offlineServerPublicKeyPem: string | null }

/**
 * The stored recovery key and wrapped key must be the ones sealed when the
 * device last registered them: a database writer can neither substitute their
 * own nor restore an earlier configuration the customer has replaced (the
 * record must be the identity's latest RECOVERY_CONFIGURED record). With
 * `kdf`, the salt and iteration count handed to the device must be the sealed
 * ones too.
 */
async function assertRecoveryKeyIntegrity(
  tx: Parameters<typeof getEvidenceRecord>[0], nexusId: string, evidenceId: string | null, publicKeyPem: string, wrapped: Buffer,
  kdf?: { saltB64: string; iterations: number },
): Promise<void> {
  const fail = async (reason: string): Promise<never> => {
    await recordAuditEvent('integrity_violation', { nexusId }, { reason: `recovery key: ${reason}` }).catch(() => undefined);
    throw new ConflictError('Recovery configuration failed its integrity check', 'RECOVERY_INTEGRITY');
  };
  if (!evidenceId) return fail('no sealed recovery configuration');
  const record = await getEvidenceRecord(tx, evidenceId);
  if (!record) return fail('the sealed record does not exist');
  const problem = await sealProblem(record);
  if (problem) return fail(problem);
  const sealed = record.sealedPayload as { recordType?: string; nexusId?: string; recoveryPublicKeyPem?: string; wrappedRecoveryKeySha256?: string };
  if (sealed.recordType !== 'RECOVERY_CONFIGURED' || sealed.nexusId !== nexusId || !sealed.recoveryPublicKeyPem) return fail('the sealed record is not this identity\'s recovery configuration');
  if (!spkiOf(sealed.recoveryPublicKeyPem).equals(spkiOf(publicKeyPem)) || sealed.wrappedRecoveryKeySha256 !== sha256hex(wrapped)) {
    return fail('the stored recovery key differs from the sealed one');
  }
  const latest = await tx.query<{ evidence_id: string }>(
    `SELECT evidence_id FROM evidence_records WHERE nexus_id = $1 AND record_type = 'RECOVERY_CONFIGURED' ORDER BY chain_sequence DESC LIMIT 1`, [nexusId]);
  if (latest.rows[0]?.evidence_id !== evidenceId) return fail('the stored recovery configuration is not the latest sealed one');
  const sealedKdf = sealed as { kdfSaltB64?: string; kdfIterations?: number };
  if (kdf && (sealedKdf.kdfSaltB64 !== kdf.saltB64 || Number(sealedKdf.kdfIterations) !== kdf.iterations)) {
    return fail('the stored key derivation parameters differ from the sealed ones');
  }
}

function verifyEcdsa(publicKeyPem: string, data: Buffer, signature: Buffer): boolean {
  try {
    return verify('sha256', data, { key: publicKeyPem, dsaEncoding: 'der' }, signature);
  } catch {
    return false;
  }
}

function decodeBase64(value: string): Buffer | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) return null;
  return Buffer.from(value, 'base64');
}
