import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { assertValidBeneficiary, canonicalJson, displayTextViolation, type AuthorizationBeneficiary } from './canonicalAuthorization';
import { assertCredentialIntegrity, CredentialIntegrityError } from './credentialIntegrity';
import { getCredentialForClient } from './credentialService';
import { ConflictError, NotFoundError, UnprocessableError, ValidationError } from './errors';
import { sealMandateEvent, type MandateEvent } from './evidenceService';
import { getNexusIdentityForClient } from './nexusIdentityService';
import { recordAuditEvent } from './auditService';
import { enqueueWebhook } from './webhookService';

/**
 * Recurring payment mandates (presentation pages 17 to 19).
 *
 * The bank proposes a mandate for one of the customer's devices; the device
 * shows the terms and signs their canonical bytes (domain
 * NEXUS-SIGN/MANDATE, so a mandate signature can never be taken for a
 * payment signature, whose domain is NEXUS-SIGN/TRANSACTION-AUTH, or the
 * reverse). Before each debit the bank asks Auth Core, which allows it only
 * inside the signed terms; the database checks the same rules again
 * (migration 028, trigger mandate_debits_check). The bank can withdraw a
 * mandate but not change it: changed terms are a new mandate the customer
 * signs. Every event is sealed into the identity's evidence chain.
 */

export const MANDATE_DOMAIN = 'NEXUS-SIGN/MANDATE';
export type MandateFrequency = 'WEEKLY' | 'MONTHLY' | 'QUARTERLY' | 'YEARLY';
export type MandateState = 'PENDING_SIGNATURE' | 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'EXPIRED' | 'DECLINED' | 'WITHDRAWN';
const FINAL: ReadonlySet<MandateState> = new Set(['REVOKED', 'EXPIRED', 'DECLINED', 'WITHDRAWN']);

export interface MandateInput {
  nexusId: string;
  credentialId: string;
  mandateReference: string;
  payee: AuthorizationBeneficiary;
  currency: string;
  perPaymentLimitMinor: string;
  totalLimitMinor: string | null;
  frequency: MandateFrequency;
  validFrom: string;
  validUntil: string;
  termsVersion: string;
  /** How long the customer has to sign (60 s to 7 days, default 1 day). */
  offerExpiresInSeconds?: number;
}

export interface Mandate {
  mandateId: string;
  nexusId: string;
  credentialId: string;
  mandateReference: string;
  payee: AuthorizationBeneficiary;
  currency: string;
  perPaymentLimitMinor: string;
  totalLimitMinor: string | null;
  frequency: MandateFrequency;
  validFrom: string;
  validUntil: string;
  termsVersion: string;
  termsHash: string;
  /** The exact bytes the device shows and signs (base64). */
  termsBase64: string;
  offerExpiresAt: string;
  state: MandateState;
  stateReason: string | null;
  signedAt: string | null;
  usedTotalMinor: string;
  createdAt: string;
}

interface MandateRow {
  mandate_id: string; client_id: string; nexus_id: string; credential_id: string; mandate_reference: string; payee: AuthorizationBeneficiary;
  currency: string; per_payment_limit_minor: string; total_limit_minor: string | null; frequency: MandateFrequency; valid_from: Date;
  valid_until: Date; terms_version: string; canonical_terms: Buffer; terms_hash: string; offer_expires_at: Date; state: MandateState;
  signature: string | null; signature_format: 'der' | 'raw' | null; signed_at: Date | null; state_reason: string | null; created_at: Date;
  used_total: string;
}

const SELECT = `SELECT m.*, (SELECT coalesce(sum(d.amount_minor), 0)::text FROM mandate_debits d
  WHERE d.mandate_id = m.mandate_id AND d.decision = 'ALLOWED') AS used_total FROM mandates m`;

const toMandate = (r: MandateRow): Mandate => ({
  mandateId: r.mandate_id, nexusId: r.nexus_id, credentialId: r.credential_id, mandateReference: r.mandate_reference, payee: r.payee,
  currency: r.currency, perPaymentLimitMinor: String(r.per_payment_limit_minor), totalLimitMinor: r.total_limit_minor === null ? null : String(r.total_limit_minor),
  frequency: r.frequency, validFrom: new Date(r.valid_from).toISOString(), validUntil: new Date(r.valid_until).toISOString(),
  termsVersion: r.terms_version, termsHash: r.terms_hash, termsBase64: Buffer.from(r.canonical_terms).toString('base64'),
  offerExpiresAt: new Date(r.offer_expires_at).toISOString(), state: r.state, stateReason: r.state_reason,
  signedAt: r.signed_at ? new Date(r.signed_at).toISOString() : null, usedTotalMinor: r.used_total ?? '0',
  createdAt: new Date(r.created_at).toISOString(),
});

const MINOR = /^[1-9]\d{0,29}$/;

/** The canonical terms object: what the device shows and signs. */
export function mandateTermsObject(m: {
  mandateId: string; nexusId: string; credentialId: string; mandateReference: string; payee: AuthorizationBeneficiary; currency: string;
  perPaymentLimitMinor: string; totalLimitMinor: string | null; frequency: MandateFrequency; validFrom: string; validUntil: string;
  termsVersion: string; issuedAt: string; offerExpiresAt: string; nonce: string;
}): Record<string, unknown> {
  return {
    protocol_version: '1',
    domain: MANDATE_DOMAIN,
    mandate_id: m.mandateId,
    nexus_id: m.nexusId,
    credential_id: m.credentialId,
    mandate_reference: m.mandateReference,
    payee: m.payee,
    currency: m.currency,
    per_payment_limit_minor: m.perPaymentLimitMinor,
    total_limit_minor: m.totalLimitMinor,
    frequency: m.frequency,
    valid_from: m.validFrom,
    valid_until: m.validUntil,
    terms_version: m.termsVersion,
    issued_at: m.issuedAt,
    offer_expires_at: m.offerExpiresAt,
    nonce: m.nonce,
  };
}

function validateInput(input: MandateInput): void {
  assertValidBeneficiary(input.payee);
  const refProblem = displayTextViolation(input.mandateReference);
  if (refProblem) throw new ValidationError(`Invalid mandateReference: ${refProblem}`);
  if (!/^[A-Z]{3}$/.test(input.currency)) throw new ValidationError('currency must be an ISO 4217 three-letter code');
  if (!MINOR.test(input.perPaymentLimitMinor)) throw new ValidationError('perPaymentLimitMinor must be a positive integer decimal string');
  if (input.totalLimitMinor !== null && (!MINOR.test(input.totalLimitMinor) || BigInt(input.totalLimitMinor) < BigInt(input.perPaymentLimitMinor))) {
    throw new ValidationError('totalLimitMinor must be a positive integer decimal string not below perPaymentLimitMinor');
  }
  const from = Date.parse(input.validFrom); const until = Date.parse(input.validUntil);
  if (!Number.isFinite(from) || !Number.isFinite(until) || until <= from) throw new ValidationError('validUntil must be after validFrom');
  if (until <= Date.now()) throw new ValidationError('validUntil is in the past');
  if (until - from > 10 * 366 * 24 * 3600 * 1000) throw new ValidationError('A mandate is valid for at most 10 years');
}

async function enrolmentHash(runner: Pick<PoolClient, 'query'>, credentialId: string): Promise<string | null> {
  const row = await runner.query<{ evidence_hash: string }>(
    `SELECT e.evidence_hash FROM credentials c JOIN evidence_records e ON e.evidence_id = c.enrolment_evidence_id WHERE c.credential_id = $1`, [credentialId]);
  return row.rows[0]?.evidence_hash ?? null;
}

/** The bank proposes a mandate; the addressed device signs it. */
export async function createMandate(clientId: string, input: MandateInput): Promise<Mandate> {
  validateInput(input);
  const identity = await getNexusIdentityForClient(input.nexusId, clientId);
  if (identity.status !== 'ACTIVE') throw new ConflictError(`NEXUS ID is ${identity.status}`);
  const credential = await getCredentialForClient(input.credentialId, clientId);
  if (credential.nexusId !== input.nexusId || credential.state !== 'ACTIVE') throw new ConflictError('Credential is not ACTIVE for the specified NEXUS ID', 'CREDENTIAL_NOT_ACTIVE');
  const ttl = Math.min(Math.max(input.offerExpiresInSeconds ?? 24 * 3600, 60), 7 * 24 * 3600);
  const issuedAt = new Date();
  const offerExpiresAt = new Date(issuedAt.getTime() + ttl * 1000);
  const mandateId = randomUUID();
  const validFrom = new Date(input.validFrom).toISOString();
  const validUntil = new Date(input.validUntil).toISOString();
  const terms = canonicalJson(mandateTermsObject({
    mandateId, nexusId: input.nexusId, credentialId: credential.credentialId, mandateReference: input.mandateReference, payee: input.payee,
    currency: input.currency, perPaymentLimitMinor: input.perPaymentLimitMinor, totalLimitMinor: input.totalLimitMinor, frequency: input.frequency,
    validFrom, validUntil, termsVersion: input.termsVersion, issuedAt: issuedAt.toISOString(), offerExpiresAt: offerExpiresAt.toISOString(),
    nonce: randomBytes(32).toString('hex'),
  }));
  const termsHash = createHash('sha256').update(terms).digest('hex');
  return withTransaction(async (tx) => {
    try {
      await tx.query(
        `INSERT INTO mandates (mandate_id, client_id, nexus_id, credential_id, mandate_reference, payee, currency, per_payment_limit_minor,
           total_limit_minor, frequency, valid_from, valid_until, terms_version, canonical_terms, terms_hash, offer_expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
        [mandateId, clientId, input.nexusId, credential.credentialId, input.mandateReference, JSON.stringify(input.payee), input.currency,
          input.perPaymentLimitMinor, input.totalLimitMinor, input.frequency, validFrom, validUntil, input.termsVersion, terms, termsHash, offerExpiresAt]);
    } catch (error) {
      if ((error as { code?: string }).code === '23505') throw new ConflictError('A mandate with this mandateReference exists for this bank client', 'MANDATE_REFERENCE_EXISTS');
      throw error;
    }
    await recordAuditEvent('mandate_created', { nexusId: input.nexusId, actor: `bank:${clientId}` },
      { mandateId, mandateReference: input.mandateReference, termsHash, credentialId: credential.credentialId }, tx);
    return toMandate((await tx.query<MandateRow>(`${SELECT} WHERE m.mandate_id = $1`, [mandateId])).rows[0]);
  });
}

export async function getMandateForClient(clientId: string, mandateId: string): Promise<Mandate> {
  const row = (await pool.query<MandateRow>(`${SELECT} WHERE m.mandate_id = $1 AND m.client_id = $2`, [mandateId, clientId])).rows[0];
  if (!row) throw new NotFoundError(`Mandate ${mandateId} was not found`);
  return toMandate(row);
}

export async function listMandatesForIdentity(nexusId: string, clientId?: string): Promise<Mandate[]> {
  const rows = await pool.query<MandateRow>(`${SELECT} WHERE m.nexus_id = $1 AND ($2::text IS NULL OR m.client_id = $2) ORDER BY m.created_at DESC LIMIT 200`,
    [nexusId, clientId ?? null]);
  return rows.rows.map(toMandate);
}

export async function getMandateForDevice(nexusId: string, mandateId: string): Promise<Mandate> {
  const row = (await pool.query<MandateRow>(`${SELECT} WHERE m.mandate_id = $1 AND m.nexus_id = $2`, [mandateId, nexusId])).rows[0];
  if (!row) throw new NotFoundError(`Mandate ${mandateId} was not found`);
  return toMandate(row);
}

async function lockMandate(tx: PoolClient, mandateId: string, scope: { nexusId?: string; clientId?: string }): Promise<MandateRow> {
  const row = (await tx.query<MandateRow>(
    `SELECT m.*, '0' AS used_total FROM mandates m WHERE m.mandate_id = $1 AND ($2::text IS NULL OR m.nexus_id = $2) AND ($3::text IS NULL OR m.client_id = $3) FOR UPDATE`,
    [mandateId, scope.nexusId ?? null, scope.clientId ?? null])).rows[0];
  if (!row) throw new NotFoundError(`Mandate ${mandateId} was not found`);
  return row;
}

/** Changes the state, seals the event and tells the bank, in one transaction. */
async function transition(tx: PoolClient, hsm: HsmAdapter, m: MandateRow, to: MandateState, event: MandateEvent, reason: string, actor: string,
  signed?: { signature: string; signatureFormat: 'der' | 'raw'; publicKeyPem: string; enrolmentEvidenceHash: string }): Promise<Mandate> {
  const now = new Date();
  if (signed) {
    await tx.query(`UPDATE mandates SET state = $2, signature = $3, signature_format = $4, signed_at = $5, state_reason = $6, updated_at = now() WHERE mandate_id = $1`,
      [m.mandate_id, to, signed.signature, signed.signatureFormat, now, reason]);
  } else {
    await tx.query(`UPDATE mandates SET state = $2, state_reason = $3, updated_at = now() WHERE mandate_id = $1`, [m.mandate_id, to, reason]);
  }
  await sealMandateEvent(tx, hsm, {
    nexusId: m.nexus_id, mandateId: m.mandate_id, credentialId: m.credential_id, event, termsHash: m.terms_hash, mandateReference: m.mandate_reference,
    reason, occurredAt: now, enrolmentEvidenceHash: signed?.enrolmentEvidenceHash ?? await enrolmentHash(tx, m.credential_id),
    signed: signed ? { termsBase64: Buffer.from(m.canonical_terms).toString('base64'), signature: signed.signature, signatureFormat: signed.signatureFormat, publicKeyPem: signed.publicKeyPem } : undefined,
  });
  await recordAuditEvent('mandate_changed', { nexusId: m.nexus_id, actor }, { mandateId: m.mandate_id, from: m.state, to, event, reason }, tx);
  await enqueueWebhook(m.client_id, `mandate.${event.toLowerCase()}`, { mandateId: m.mandate_id, mandateReference: m.mandate_reference, nexusId: m.nexus_id, state: to, reason }, tx);
  return toMandate((await tx.query<MandateRow>(`${SELECT} WHERE m.mandate_id = $1`, [m.mandate_id])).rows[0]);
}

function decodeSignature(value: string): Buffer | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) return null;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length ? decoded : null;
}

/** The addressed device signs the terms it showed. */
export async function signMandate(hsm: HsmAdapter, device: { clientId: string; nexusId: string; credentialId: string }, mandateId: string,
  signatureB64: string, signatureFormat: 'der' | 'raw'): Promise<Mandate> {
  return withTransaction(async (tx) => {
    const m = await lockMandate(tx, mandateId, { nexusId: device.nexusId });
    if (m.state !== 'PENDING_SIGNATURE') throw new ConflictError(`Mandate is ${m.state}`, 'MANDATE_NOT_PENDING');
    if (m.credential_id !== device.credentialId) throw new ConflictError('The mandate was offered to another device of this customer', 'CREDENTIAL_MISMATCH');
    if (new Date(m.offer_expires_at).getTime() <= Date.now()) throw new ConflictError('The offer to sign this mandate has expired', 'MANDATE_OFFER_EXPIRED');
    const credential = await getCredentialForClient(device.credentialId, device.clientId, tx);
    if (credential.state !== 'ACTIVE') throw new ConflictError('Credential is not ACTIVE', 'CREDENTIAL_NOT_ACTIVE');
    let enrolmentEvidenceHash: string;
    try {
      enrolmentEvidenceHash = await assertCredentialIntegrity(credential, tx);
    } catch (error) {
      if (error instanceof CredentialIntegrityError) throw new ConflictError('credential_integrity', 'CREDENTIAL_INTEGRITY');
      throw error;
    }
    const signature = decodeSignature(signatureB64);
    const terms = Buffer.from(m.canonical_terms);
    if (createHash('sha256').update(terms).digest('hex') !== m.terms_hash) throw new ConflictError('Mandate integrity check failed', 'MANDATE_INTEGRITY');
    const valid = signature !== null && await hsm.verifySignature(credential.publicKeyPem, terms, signature, signatureFormat);
    if (!valid) {
      await recordAuditEvent('mandate_signature_invalid', { nexusId: device.nexusId, actor: `credential:${device.credentialId}` }, { mandateId }, tx);
      throw new UnprocessableError('The signature does not verify over the mandate terms');
    }
    return transition(tx, hsm, m, 'ACTIVE', 'SIGNED', 'SIGNED_BY_CUSTOMER', `credential:${device.credentialId}`,
      { signature: signatureB64, signatureFormat, publicKeyPem: credential.publicKeyPem, enrolmentEvidenceHash });
  });
}

export type CustomerMandateAction = 'DECLINE' | 'SUSPEND' | 'RESUME' | 'REVOKE';

/**
 * The customer declines an offered mandate, or suspends, resumes or revokes
 * a signed one, from any active device of the NEXUS ID (a device-signed
 * request). Resuming re-enables the terms already signed; it changes nothing
 * in them.
 */
export async function customerMandateAction(hsm: HsmAdapter, device: { nexusId: string; credentialId: string }, mandateId: string, action: CustomerMandateAction): Promise<Mandate> {
  return withTransaction(async (tx) => {
    const active = await tx.query(`SELECT 1 FROM credentials WHERE credential_id = $1 AND nexus_id = $2 AND state = 'ACTIVE'`, [device.credentialId, device.nexusId]);
    if (active.rowCount === 0) throw new ConflictError('Only an active device of this NEXUS ID manages its mandates', 'CREDENTIAL_NOT_ACTIVE');
    const m = await lockMandate(tx, mandateId, { nexusId: device.nexusId });
    const actor = `credential:${device.credentialId}`;
    const refuse = (): never => { throw new ConflictError(`Mandate is ${m.state}; ${action.toLowerCase()} is not possible`, 'MANDATE_STATE_CONFLICT'); };
    switch (action) {
      case 'DECLINE': return m.state === 'PENDING_SIGNATURE' ? transition(tx, hsm, m, 'DECLINED', 'DECLINED', 'DECLINED_BY_CUSTOMER', actor) : refuse();
      case 'SUSPEND': return m.state === 'ACTIVE' ? transition(tx, hsm, m, 'SUSPENDED', 'SUSPENDED', 'SUSPENDED_BY_CUSTOMER', actor) : refuse();
      case 'RESUME':
        if (m.state !== 'SUSPENDED') refuse();
        // A hold placed by the bank's staff is lifted by the bank, not by the customer.
        if (m.state_reason?.startsWith(BANK_HOLD)) throw new ConflictError('The bank holds this mandate; only the bank lifts the hold', 'MANDATE_HELD_BY_BANK');
        if (new Date(m.valid_until).getTime() <= Date.now()) return transition(tx, hsm, m, 'EXPIRED', 'EXPIRED', 'VALIDITY_ENDED', 'system:expiry');
        return transition(tx, hsm, m, 'ACTIVE', 'RESUMED', 'RESUMED_BY_CUSTOMER', actor);
      case 'REVOKE': return m.state === 'ACTIVE' || m.state === 'SUSPENDED' ? transition(tx, hsm, m, 'REVOKED', 'REVOKED', 'REVOKED_BY_CUSTOMER', actor) : refuse();
      default: return refuse();
    }
  });
}

const BANK_HOLD = 'SUSPENDED_BY_BANK:';

/**
 * The bank's staff hold an active mandate (suspected fraud, a dispute): no
 * debit is allowed while it is SUSPENDED. The customer cannot lift a bank
 * hold; another member of the bank's staff does (four eyes), with
 * releaseBankHold.
 */
export async function placeBankHold(hsm: HsmAdapter, clientId: string, mandateId: string, staff: string, reason: string): Promise<Mandate> {
  return withTransaction(async (tx) => {
    const m = await lockMandate(tx, mandateId, { clientId });
    if (m.state !== 'ACTIVE') throw new ConflictError(`Mandate is ${m.state}; only an active mandate is held`, 'MANDATE_STATE_CONFLICT');
    return transition(tx, hsm, m, 'SUSPENDED', 'SUSPENDED', `${BANK_HOLD}${staff}:${reason}`.slice(0, 128), `admin:${staff}`);
  });
}

/** Lifts a bank hold. The staff member who placed it cannot lift it. */
export async function releaseBankHold(hsm: HsmAdapter, clientId: string, mandateId: string, staff: string): Promise<Mandate> {
  return withTransaction(async (tx) => {
    const m = await lockMandate(tx, mandateId, { clientId });
    if (m.state !== 'SUSPENDED' || !m.state_reason?.startsWith(BANK_HOLD)) {
      throw new ConflictError(`Mandate is ${m.state} without a bank hold`, 'MANDATE_STATE_CONFLICT');
    }
    if (m.state_reason.startsWith(`${BANK_HOLD}${staff}:`)) throw new ConflictError('Another member of staff lifts the hold you placed', 'SAME_STAFF_MEMBER');
    if (new Date(m.valid_until).getTime() <= Date.now()) return transition(tx, hsm, m, 'EXPIRED', 'EXPIRED', 'VALIDITY_ENDED', 'system:expiry');
    return transition(tx, hsm, m, 'ACTIVE', 'RESUMED', 'BANK_HOLD_RELEASED', `admin:${staff}`);
  });
}

/** The debits the bank asked about, allowed and refused, newest first. */
export async function listMandateDebits(mandateId: string, limit = 200): Promise<Array<{ debitId: string; debitReference: string; amountMinor: string; currency: string;
  periodStart: string; decision: 'ALLOWED' | 'REFUSED'; reason: string | null; createdAt: string }>> {
  const rows = await pool.query(
    `SELECT debit_id, debit_reference, amount_minor::text AS amount_minor, currency, period_start::text AS period_start, decision, reason, created_at
       FROM mandate_debits WHERE mandate_id = $1 ORDER BY created_at DESC LIMIT $2`, [mandateId, Math.min(Math.max(limit, 1), 500)]);
  return rows.rows.map((r) => ({
    debitId: r.debit_id, debitReference: r.debit_reference, amountMinor: r.amount_minor, currency: r.currency,
    periodStart: r.period_start, decision: r.decision, reason: r.reason, createdAt: new Date(r.created_at).toISOString(),
  }));
}

/** The bank withdraws a mandate (it cannot change one). */
export async function withdrawMandate(hsm: HsmAdapter, clientId: string, mandateId: string, reason: string): Promise<Mandate> {
  return withTransaction(async (tx) => {
    const m = await lockMandate(tx, mandateId, { clientId });
    if (FINAL.has(m.state)) throw new ConflictError(`Mandate is ${m.state}`, 'MANDATE_STATE_CONFLICT');
    return transition(tx, hsm, m, 'WITHDRAWN', 'WITHDRAWN', `WITHDRAWN_BY_BANK:${reason}`.slice(0, 128), `bank:${clientId}`);
  });
}

export type DebitRefusal = 'MANDATE_NOT_ACTIVE' | 'NOT_YET_VALID' | 'VALIDITY_ENDED' | 'CURRENCY_MISMATCH' | 'ABOVE_PAYMENT_LIMIT' | 'PERIOD_ALREADY_DEBITED' | 'ABOVE_TOTAL_LIMIT';

export interface DebitDecision {
  debitId: string;
  mandateId: string;
  debitReference: string;
  amountMinor: string;
  currency: string;
  periodStart: string;
  decision: 'ALLOWED' | 'REFUSED';
  reason: DebitRefusal | null;
  replayed: boolean;
}

/**
 * Before each debit the bank asks whether it is inside the signed terms.
 * The decision is recorded (append-only) and is idempotent per
 * debitReference; the database refuses an ALLOWED row outside the terms.
 */
export async function requestMandateDebit(clientId: string, mandateId: string, debit: { debitReference: string; amountMinor: string; currency: string }): Promise<DebitDecision> {
  if (!MINOR.test(debit.amountMinor)) throw new ValidationError('amountMinor must be a positive integer decimal string');
  if (!/^[A-Z]{3}$/.test(debit.currency)) throw new ValidationError('currency must be an ISO 4217 three-letter code');
  return withTransaction(async (tx) => {
    const m = await lockMandate(tx, mandateId, { clientId });
    const previous = (await tx.query<{ debit_id: string; amount_minor: string; currency: string; period_start: Date; decision: 'ALLOWED' | 'REFUSED'; reason: DebitRefusal | null }>(
      `SELECT debit_id, amount_minor::text, currency, period_start, decision, reason FROM mandate_debits WHERE mandate_id = $1 AND debit_reference = $2`,
      [mandateId, debit.debitReference])).rows[0];
    if (previous) {
      if (previous.amount_minor !== debit.amountMinor || previous.currency !== debit.currency) {
        throw new ConflictError('This debitReference was used with another amount or currency', 'DEBIT_REFERENCE_REUSED');
      }
      return { debitId: previous.debit_id, mandateId, debitReference: debit.debitReference, amountMinor: previous.amount_minor, currency: previous.currency,
        periodStart: new Date(previous.period_start).toISOString().slice(0, 10), decision: previous.decision, reason: previous.reason, replayed: true };
    }
    const period = (await tx.query<{ p: Date }>(`SELECT mandate_period_start($1, now()) AS p`, [m.frequency])).rows[0].p;
    const periodStart = new Date(period).toISOString().slice(0, 10);
    const amount = BigInt(debit.amountMinor);
    let reason: DebitRefusal | null = null;
    const now = Date.now();
    if (m.state !== 'ACTIVE') reason = 'MANDATE_NOT_ACTIVE';
    else if (now < new Date(m.valid_from).getTime()) reason = 'NOT_YET_VALID';
    else if (now >= new Date(m.valid_until).getTime()) reason = 'VALIDITY_ENDED';
    else if (debit.currency !== m.currency) reason = 'CURRENCY_MISMATCH';
    else if (amount > BigInt(m.per_payment_limit_minor)) reason = 'ABOVE_PAYMENT_LIMIT';
    else {
      const used = (await tx.query<{ in_period: number; total: string }>(
        `SELECT count(*) FILTER (WHERE period_start = $2)::int AS in_period, coalesce(sum(amount_minor), 0)::text AS total
           FROM mandate_debits WHERE mandate_id = $1 AND decision = 'ALLOWED'`, [mandateId, periodStart])).rows[0];
      if (used.in_period > 0) reason = 'PERIOD_ALREADY_DEBITED';
      else if (m.total_limit_minor !== null && BigInt(used.total) + amount > BigInt(m.total_limit_minor)) reason = 'ABOVE_TOTAL_LIMIT';
    }
    const debitId = randomUUID();
    await tx.query(
      `INSERT INTO mandate_debits (debit_id, mandate_id, debit_reference, amount_minor, currency, period_start, decision, reason)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [debitId, mandateId, debit.debitReference, debit.amountMinor, debit.currency, periodStart, reason ? 'REFUSED' : 'ALLOWED', reason]);
    await recordAuditEvent(reason ? 'mandate_debit_refused' : 'mandate_debit_allowed', { nexusId: m.nexus_id, actor: `bank:${clientId}` },
      { mandateId, debitId, debitReference: debit.debitReference, amountMinor: debit.amountMinor, currency: debit.currency, reason }, tx);
    if (reason) {
      await enqueueWebhook(clientId, 'mandate.debit_refused', { mandateId, debitId, debitReference: debit.debitReference, amountMinor: debit.amountMinor, currency: debit.currency, reason }, tx);
    }
    return { debitId, mandateId, debitReference: debit.debitReference, amountMinor: debit.amountMinor, currency: debit.currency, periodStart,
      decision: reason ? 'REFUSED' : 'ALLOWED', reason, replayed: false };
  });
}

/** Ends offers nobody signed and mandates past their validity; each is sealed. */
export async function expireMandates(hsm: HsmAdapter, limit = 100): Promise<number> {
  const due = await pool.query<{ mandate_id: string }>(
    `SELECT mandate_id FROM mandates
      WHERE (state = 'PENDING_SIGNATURE' AND offer_expires_at <= now()) OR (state IN ('ACTIVE','SUSPENDED') AND valid_until <= now())
      ORDER BY coalesce(valid_until, offer_expires_at) LIMIT $1`, [limit]);
  let expired = 0;
  for (const { mandate_id: mandateId } of due.rows) {
    await withTransaction(async (tx) => {
      const m = await lockMandate(tx, mandateId, {});
      const offerEnded = m.state === 'PENDING_SIGNATURE' && new Date(m.offer_expires_at).getTime() <= Date.now();
      const validityEnded = (m.state === 'ACTIVE' || m.state === 'SUSPENDED') && new Date(m.valid_until).getTime() <= Date.now();
      if (!offerEnded && !validityEnded) return; // decided concurrently
      await transition(tx, hsm, m, 'EXPIRED', 'EXPIRED', offerEnded ? 'OFFER_NOT_SIGNED' : 'VALIDITY_ENDED', 'system:expiry');
      expired += 1;
    });
  }
  return expired;
}
