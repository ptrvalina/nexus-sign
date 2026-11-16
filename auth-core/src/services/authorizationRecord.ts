import { pool } from '../db/pool';
import type { AuthorizationBeneficiary, AuthorizationObject } from './canonicalAuthorization';

export const OPEN_STATES = ['PENDING_USER'];
export const FINAL_STATES = ['VERIFIED', 'EXPIRED', 'REJECTED', 'CANCELLED', 'OFFLINE_UNSIGNED'];
/** Offline confirmation v2: code accepted, device signature not yet received.
 * Neither open nor final; only the deferred signature or the sweep moves it. */
export const PROVISIONAL_STATE = 'OFFLINE_PROVISIONAL';

export type ConfirmationMethod = 'DEVICE_SIGNATURE' | 'OFFLINE_CODE' | 'OFFLINE_SIGNED';

export interface AuthorizationRecord {
  authorizationId: string;
  nexusId: string;
  credentialId: string | null;
  transactionReference: string;
  operationType: string;
  amountMinor: string;
  currency: string;
  beneficiary: AuthorizationBeneficiary;
  policyReference: string;
  policyVersion: string;
  canonicalPayloadHash: string;
  nonce: string;
  issuedAt: Date;
  expiresAt: Date;
  state: string;
  signature: string | null;
  signatureAlgorithm: string;
  signatureFormat: 'der' | 'raw' | 'hmac' | null;
  confirmationMethod: ConfirmationMethod | null;
  verifiedAt: Date | null;
  /** When an offline code was accepted (v1 and v2). */
  offlineCodeAcceptedAt: Date | null;
  /** v2: until when the device signature may arrive. */
  offlineSignatureDeadline: Date | null;
  /** OFFLINE_UNSIGNED: deadline, credential_not_active or identity_not_active. */
  offlineUnsignedReason: string | null;
}

export class AuthorizationNotFoundError extends Error {
  constructor(id: string) { super(`Authorization ${id} was not found`); this.name = 'AuthorizationNotFoundError'; }
}

/** The signed v1 object for a stored authorization. */
export function authorizationObjectOf(auth: AuthorizationRecord): AuthorizationObject {
  return {
    protocol_version: '1',
    domain: 'NEXUS-SIGN/TRANSACTION-AUTH',
    authorization_id: auth.authorizationId,
    nexus_id: auth.nexusId,
    credential_id: auth.credentialId ?? '',
    transaction_reference: auth.transactionReference,
    operation_type: auth.operationType,
    amount_minor: auth.amountMinor,
    currency: auth.currency,
    beneficiary: auth.beneficiary,
    policy_reference: auth.policyReference,
    policy_version: auth.policyVersion,
    issued_at: auth.issuedAt.toISOString(),
    expires_at: auth.expiresAt.toISOString(),
    nonce: auth.nonce,
  };
}

export async function getAuthorizationForClient(id: string, clientId: string): Promise<AuthorizationRecord> {
  const result = await pool.query<AuthorizationRow>(`SELECT * FROM authorization_requests WHERE authorization_id = $1 AND client_id = $2`, [id, clientId]);
  const row = result.rows[0];
  if (!row) throw new AuthorizationNotFoundError(id);
  return mapAuthorization(row);
}


/** A row of authorization_requests as returned by `SELECT *`. */
export interface AuthorizationRow {
  authorization_id: string; client_id: string; nexus_id: string; credential_id: string | null; transaction_reference: string;
  operation_type: string; amount_minor: string; currency: string; beneficiary: AuthorizationBeneficiary; policy_reference: string;
  policy_version: string; canonical_payload_hash: string; nonce: string; issued_at: Date; expires_at: Date; state: string;
  signature: string | null; signature_algorithm: string; signature_format: 'der' | 'raw' | 'hmac' | null; verified_at: Date | null;
  confirmation_method: ConfirmationMethod | null;
  offline_code_tag: string | null; offline_code_accepted_at: Date | null; offline_signature_deadline: Date | null;
  offline_unsigned_reason: string | null;
  correlation_id: string | null; idempotency_key: string | null;
}

export function mapAuthorization(row: AuthorizationRow): AuthorizationRecord {
  return {
    authorizationId: row.authorization_id,
    nexusId: row.nexus_id,
    credentialId: row.credential_id,
    transactionReference: row.transaction_reference,
    operationType: row.operation_type,
    amountMinor: row.amount_minor.toString(),
    currency: row.currency,
    beneficiary: row.beneficiary,
    policyReference: row.policy_reference,
    policyVersion: row.policy_version,
    canonicalPayloadHash: row.canonical_payload_hash,
    nonce: row.nonce,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    state: row.state,
    signature: row.signature,
    signatureAlgorithm: row.signature_algorithm,
    signatureFormat: row.signature_format,
    confirmationMethod: row.confirmation_method ?? null,
    verifiedAt: row.verified_at,
    offlineCodeAcceptedAt: row.offline_code_accepted_at ?? null,
    offlineSignatureDeadline: row.offline_signature_deadline ?? null,
    offlineUnsignedReason: row.offline_unsigned_reason ?? null,
  };
}
