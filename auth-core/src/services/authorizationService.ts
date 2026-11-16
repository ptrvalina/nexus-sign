import { env } from '../config/env';
import { randomBytes, randomUUID } from 'node:crypto';
import { pool, withTransaction } from '../db/pool';
import { recordAuditEvent } from './auditService';
import { getNexusIdentityForClient } from './nexusIdentityService';
import { getCredentialForClient } from './credentialService';
import {
  assertValidBeneficiary,
  hashCanonicalAuthorization,
  hashCanonicalJson,
  type AuthorizationBeneficiary,
} from './canonicalAuthorization';
import {
  createVerificationPlan,
  getVerificationPlan,
  type VerificationPlan,
  type VerificationPolicyInput,
} from './adaptiveVerificationService';
import { mapAuthorization, type AuthorizationRecord, type AuthorizationRow } from './authorizationRecord';
import { getPushMessageForClient, queueAuthorizationPush, type PushMessageRecord } from './pushService';
import { ConflictError, ValidationError } from './errors';

const DEFAULT_TTL_SECONDS = 120;

export interface CreateAuthorizationInput {
  nexusId: string;
  credentialId: string;
  transactionReference: string;
  operationType: string;
  amountMinor: string;
  currency: string;
  beneficiary: AuthorizationBeneficiary;
  policyReference: string;
  policyVersion: string;
  verificationPolicy?: VerificationPolicyInput;
  expiresInSeconds?: number;
  idempotencyKey?: string;
  correlationId?: string;
  /** Text of the secure push (push mode NEXUS); defaults from PUSH_AUTHORIZATION_*. */
  pushNotification?: { title?: string; body?: string };
}

export interface CreatedAuthorization {
  authorization: AuthorizationRecord;
  plan: VerificationPlan;
  /** The secure push queued for it (push mode NEXUS only). */
  push: PushMessageRecord | null;
  replayed: boolean;
}

export async function createAuthorization(input: CreateAuthorizationInput, clientId: string): Promise<CreatedAuthorization> {
  // An idempotent replay returns the original result even if the credential
  // or identity changed since, so it is resolved before any state checks.
  if (input.idempotencyKey) {
    const replay = await findIdempotentReplay(input, clientId);
    if (replay) return { ...replay, replayed: true };
  }

  if (!/^(0|[1-9]\d{0,29})$/.test(input.amountMinor)) throw new ValidationError('amountMinor must be a non-negative integer decimal string');
  if (!/^[A-Z]{3}$/.test(input.currency)) throw new ValidationError('currency must be an ISO 4217 three-letter code');
  assertValidBeneficiary(input.beneficiary);

  const identity = await getNexusIdentityForClient(input.nexusId, clientId);
  if (identity.status !== 'ACTIVE') throw new ConflictError(`NEXUS ID is ${identity.status}`);
  const credential = await getCredentialForClient(input.credentialId, clientId);
  if (credential.nexusId !== input.nexusId || credential.state !== 'ACTIVE') throw new ConflictError('Credential is not ACTIVE for the specified NEXUS ID');
  // With attestation required, a credential enrolled before the requirement
  // (attestation UNKNOWN) cannot approve transactions until the customer's
  // device is enrolled again with verified evidence.
  if (env.REQUIRE_VALID_ATTESTATION && credential.attestationStatus !== 'VERIFIED') {
    throw new ConflictError('The device credential has no verified attestation; enrol the device again', 'CREDENTIAL_NOT_ATTESTED');
  }

  const ttl = Math.min(Math.max(input.expiresInSeconds ?? DEFAULT_TTL_SECONDS, 30), 900);
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + ttl * 1000);
  const authorizationId = randomUUID();
  const nonce = randomBytes(32).toString('hex');
  const canonicalPayloadHash = hashCanonicalAuthorization({
    protocol_version: '1',
    domain: 'NEXUS-SIGN/TRANSACTION-AUTH',
    authorization_id: authorizationId,
    nexus_id: input.nexusId,
    credential_id: credential.credentialId,
    transaction_reference: input.transactionReference,
    operation_type: input.operationType,
    amount_minor: input.amountMinor,
    currency: input.currency,
    beneficiary: input.beneficiary,
    policy_reference: input.policyReference,
    policy_version: input.policyVersion,
    issued_at: issuedAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    nonce,
  });

  try {
    return await withTransaction(async (tx) => {
      const inserted = await tx.query<AuthorizationRow>(
        `INSERT INTO authorization_requests (
          authorization_id, client_id, nexus_id, credential_id, transaction_reference,
          operation_type, amount_minor, currency, beneficiary, protocol_version, domain,
          policy_reference, policy_version, canonical_payload_hash, nonce, issued_at, expires_at,
          state, correlation_id, idempotency_key
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'1','NEXUS-SIGN/TRANSACTION-AUTH',$10,$11,$12,$13,$14,$15,'PENDING_USER',$16,$17)
        RETURNING *`,
        [authorizationId, clientId, input.nexusId, credential.credentialId, input.transactionReference,
          input.operationType, input.amountMinor, input.currency, JSON.stringify(input.beneficiary), input.policyReference,
          input.policyVersion, canonicalPayloadHash, nonce, issuedAt, expiresAt, input.correlationId ?? null, input.idempotencyKey ?? null],
      );
      // The verification plan is created in the same transaction: an
      // authorization without a plan could never be signed.
      const plan = await createVerificationPlan({
        ...(input.verificationPolicy ?? {}),
        authorizationId,
        nexusId: input.nexusId,
        clientId,
        policyVersion: input.policyVersion,
        amountMinor: input.amountMinor,
      }, tx);
      await recordAuditEvent('authorization_created', { nexusId: input.nexusId },
        { authorizationId, transactionReference: input.transactionReference, canonicalPayloadHash, policyReference: input.policyReference, requiredStep: plan.requiredStep }, tx);
      // Queued in the same transaction: no authorization without its push, and no push for a rolled-back authorization.
      const push = await queueAuthorizationPush(tx, {
        clientId, nexusId: input.nexusId, credentialId: credential.credentialId, authorizationId, expiresAt,
        title: input.pushNotification?.title, body: input.pushNotification?.body,
      });
      return { authorization: mapAuthorization(inserted.rows[0]), plan, push, replayed: false };
    });
  } catch (error: unknown) {
    if (isUniqueViolation(error)) {
      // A concurrent request with the same Idempotency-Key won the race.
      if (input.idempotencyKey) {
        const replay = await findIdempotentReplay(input, clientId);
        if (replay) return { ...replay, replayed: true };
      }
      throw new ConflictError('Transaction reference or idempotency key already exists for this bank client');
    }
    throw error;
  }
}

async function findIdempotentReplay(input: CreateAuthorizationInput, clientId: string): Promise<Omit<CreatedAuthorization, 'replayed'> | null> {
  const existing = await pool.query<AuthorizationRow>(
    `SELECT * FROM authorization_requests WHERE client_id = $1 AND idempotency_key = $2`, [clientId, input.idempotencyKey]);
  const row = existing.rows[0];
  if (!row) return null;
  const sameRequest = row.nexus_id === input.nexusId
    && row.credential_id === input.credentialId
    && row.transaction_reference === input.transactionReference
    && row.operation_type === input.operationType
    && row.amount_minor.toString() === input.amountMinor
    && row.currency === input.currency
    // JSONB does not preserve key order, so compare canonical forms.
    && hashCanonicalJson(row.beneficiary) === hashCanonicalJson(input.beneficiary)
    && row.policy_reference === input.policyReference
    && row.policy_version === input.policyVersion;
  if (!sameRequest) throw new ConflictError('Idempotency-Key is already bound to a different authorization request');
  const plan = await pool.query(`SELECT 1 FROM authorization_verification_plans WHERE authorization_id = $1`, [row.authorization_id]);
  if (!plan.rows[0]) throw new ConflictError('Authorization exists without a verification plan');
  const push = await pool.query<{ message_id: string }>(
    `SELECT message_id FROM push_messages WHERE authorization_id = $1 ORDER BY created_at LIMIT 1`, [row.authorization_id]);
  return {
    authorization: mapAuthorization(row),
    plan: await getVerificationPlan(row.authorization_id, clientId),
    push: push.rows[0] ? await getPushMessageForClient(push.rows[0].message_id, clientId) : null,
  };
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && (error as { code?: string }).code === '23505';
}
