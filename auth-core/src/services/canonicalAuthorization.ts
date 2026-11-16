import { createHash } from 'node:crypto';
import { ValidationError } from './errors';

export type AuthorizationBeneficiary = Record<string, string>;

export interface AuthorizationObject {
  protocol_version: '1';
  domain: 'NEXUS-SIGN/TRANSACTION-AUTH';
  authorization_id: string;
  nexus_id: string;
  credential_id: string;
  transaction_reference: string;
  operation_type: string;
  amount_minor: string;
  currency: string;
  beneficiary: AuthorizationBeneficiary;
  policy_reference: string;
  policy_version: string;
  issued_at: string;
  expires_at: string;
  nonce: string;
}

/**
 * Beneficiary keys are restricted to lowercase identifiers. JavaScript
 * enumerates integer-like keys ("0", "10") before all others, so such a key
 * would make JSON.stringify emit bytes out of sorted-key order that no
 * independent verifier (mobile SDK, auditor) could reproduce.
 */
export const BENEFICIARY_KEY_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
export const BENEFICIARY_MAX_FIELDS = 16;
/** ISO 20022 Max140Text, in UTF-16 code units as every SDK counts them. A
 * longer value could push the account identifier out of the visible part of
 * the confirmation prompt. Until 2.0.0-rc.2 the limit was 512. */
export const BENEFICIARY_MAX_VALUE_LENGTH = 140;
/** A value must not be blank or padded with space separators (Zs): padding
 * changes what the prompt shows without changing how the value reads. */
const PADDED = /^\p{Zs}|\p{Zs}$/u;

/**
 * Characters that change how text is laid out without being visible: control
 * characters (including line breaks), format characters (bidi overrides,
 * zero-width characters) and line or paragraph separators. A payee name with
 * a bidi override or a line break can push the real IBAN out of the
 * confirmation prompt, so no displayed field may contain them. Lone UTF-16
 * surrogates (\p{Cs}) are refused too: they have no UTF-8 encoding, so the
 * signed bytes would not match the text and the SDKs reject them.
 * The SDKs apply the same rule to the signed bytes.
 */
export const DISPLAY_UNSAFE_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u;

export function assertValidBeneficiary(beneficiary: unknown): asserts beneficiary is AuthorizationBeneficiary {
  if (!beneficiary || typeof beneficiary !== 'object' || Array.isArray(beneficiary)) throw new ValidationError('Invalid beneficiary: must be an object');
  const entries = Object.entries(beneficiary as Record<string, unknown>);
  if (entries.length > BENEFICIARY_MAX_FIELDS) throw new ValidationError(`Invalid beneficiary: at most ${BENEFICIARY_MAX_FIELDS} fields`);
  for (const [key, value] of entries) {
    if (!BENEFICIARY_KEY_PATTERN.test(key)) throw new ValidationError(`Invalid beneficiary key "${key}": must match ${BENEFICIARY_KEY_PATTERN}`);
    if (typeof value !== 'string' || value.length === 0 || value.length > BENEFICIARY_MAX_VALUE_LENGTH) {
      throw new ValidationError(`Invalid beneficiary value for "${key}": 1 to ${BENEFICIARY_MAX_VALUE_LENGTH} characters`);
    }
    if (PADDED.test(value)) throw new ValidationError(`Invalid beneficiary value for "${key}": leading or trailing space`);
    if (DISPLAY_UNSAFE_CHARACTER.test(value)) throw new ValidationError(`Invalid beneficiary value for "${key}": control, format or separator characters are not allowed`);
  }
}

/** Applies the display rule to every top-level string field. */
export function assertDisplaySafeFields(value: AuthorizationObject): void {
  for (const [key, field] of Object.entries(value)) {
    if (typeof field === 'string' && DISPLAY_UNSAFE_CHARACTER.test(field)) {
      throw new ValidationError(`Invalid ${key}: control, format or separator characters are not allowed`);
    }
  }
}

function normalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') {
    const input = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(input).sort().map((key) => [key, normalize(input[key])]));
  }
  return value;
}

/**
 * Deterministic JSON canonicalization for the v1 authorization object.
 * Protocol fields avoid floating-point values: amount_minor is an integer
 * decimal string, timestamps are RFC 3339 UTC strings, and object keys are
 * sorted recursively. This is the wire contract until an RFC 8785
 * implementation is introduced as a hard dependency.
 */
export function canonicalizeAuthorization(value: AuthorizationObject): Buffer {
  assertValidBeneficiary(value.beneficiary);
  assertDisplaySafeFields(value);
  const normalized = normalize(value);
  return Buffer.from(JSON.stringify(normalized), 'utf8');
}

export function hashCanonicalAuthorization(value: AuthorizationObject): string {
  return createHash('sha256').update(canonicalizeAuthorization(value)).digest('hex');
}

/** Canonical JSON of any value: keys sorted recursively, JSON.stringify
 * escaping, UTF-8. Used for evidence and for idempotency comparisons. */
export function canonicalJson(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(normalize(value)), 'utf8');
}

export function hashCanonicalJson(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}
