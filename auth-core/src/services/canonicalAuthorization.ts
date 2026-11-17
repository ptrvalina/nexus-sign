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
/**
 * Display text rules. They protect the fields a customer reads before signing
 * (beneficiary values and transaction_reference) against text that looks like
 * something else. The same rules are applied by both SDKs to the signed bytes
 * and are specified in docs/protocol/authorization-protocol-v1.md, "Display
 * text rules".
 *
 * - No control, format, line or paragraph separator characters, and no lone
 *   UTF-16 surrogates (\p{Cs}): bidi overrides, zero-width characters and
 *   line breaks can push the real account out of the confirmation prompt, and
 *   a lone surrogate has no UTF-8 encoding, so the signed bytes would not
 *   match the text.
 * - Unicode Normalization Form C. "José" in NFC and NFD looks identical and
 *   hashes differently; only one of them may be signed.
 * - No compatibility characters: the value is unchanged by NFKC. Full-width
 *   "Ｐ", mathematical "𝐏", superscript "²" and ligatures read as ordinary
 *   letters and digits.
 * - The only space is U+0020, never doubled and never leading or trailing.
 *   A no-break or ideographic space, or a run of spaces, changes the layout
 *   without changing how the value reads.
 * - Decimal digits are ASCII 0-9. Full-width or other-script digits render
 *   like ASCII digits in many fonts.
 * - One value does not mix letters of Latin, Cyrillic, Greek, Armenian or
 *   Cherokee, the scripts with letters that look like Latin ones: "PаyPal" with a
 *   Cyrillic "а" is the classic payee confusable (a subset of the UTS #39
 *   mixed-script check, limited to the scripts that share glyphs). The three
 *   letter sets are fixed code point ranges rather than the Unicode Script
 *   property, so that Auth Core, both SDKs and the sandbox decide the same
 *   way whatever Unicode version their runtime ships.
 * - A beneficiary "iban" is an ISO 13616 IBAN in electronic format (no
 *   spaces) with check digits 02 to 98 that verify, and a "bic" is an ISO
 *   9362 BIC.
 * - The characters → (U+2192), · (U+00B7) and • (U+2022) are reserved for
 *   the layout of the confirmation prompt (finding D-02).
 * - A beneficiary value outside the account fields (iban, account,
 *   account_number) must not itself be a valid IBAN once spaces and hyphens
 *   are removed: the prompt would offer the customer a second account
 *   number to check (finding D-02).
 * The rules apply to every beneficiary value, transaction_reference and
 * operation_type: all three are shown in the confirmation prompt.
 */
export const DISPLAY_UNSAFE_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u;
const NON_ASCII_SPACE = /(?! )\p{Zs}/u;
const SPACE_RUN = / {2}/;
const PADDED = /^\p{Zs}|\p{Zs}$/u;
const NON_ASCII_DIGIT = /(?![0-9])\p{Nd}/u;
const PROMPT_SEPARATOR = /[\u2192\u00B7\u2022]/;
export const ACCOUNT_KEYS: readonly string[] = ['iban', 'account', 'account_number'];
const CONFUSABLE_SCRIPTS = [
  /[A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u024F\u1E00-\u1EFF]/, // Basic Latin letters, Latin-1 letters, Latin Extended-A/B, Latin Extended Additional
  /[\u0400-\u052F]/, // Cyrillic, Cyrillic Supplement
  /[\u0370-\u03FF\u1F00-\u1FFF]/, // Greek and Coptic, Greek Extended
  /[\u0530-\u058F]/, // Armenian
  /[\u13A0-\u13FF\uAB70-\uABBF]/, // Cherokee, Cherokee Supplement
];
const IBAN = /^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/;
const BIC = /^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/;

export function isValidIban(value: string): boolean {
  if (!IBAN.test(value)) return false;
  const check = Number(value.slice(2, 4));
  if (check < 2 || check > 98) return false;
  const rearranged = value.slice(4) + value.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const digits = ch >= 'A' ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of digits) remainder = (remainder * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return remainder === 1;
}

/** True when the value, without spaces and hyphens and in upper case, is a valid IBAN. */
export function looksLikeIban(value: string): boolean {
  return isValidIban(value.replace(/[ -]/g, '').toUpperCase());
}

function mixesConfusableScripts(value: string): boolean {
  return CONFUSABLE_SCRIPTS.filter((script) => script.test(value)).length > 1;
}

/** Returns why a displayed value breaks the display text rules, or null. */
export function displayTextViolation(value: string): string | null {
  if (DISPLAY_UNSAFE_CHARACTER.test(value)) return 'control, format or separator characters are not allowed';
  if (PROMPT_SEPARATOR.test(value)) return 'the characters \u2192 \u00B7 \u2022 are reserved for the confirmation prompt';
  if (value !== value.normalize('NFC')) return 'text must be in Unicode Normalization Form C';
  if (value !== value.normalize('NFKC')) return 'compatibility characters (full-width, mathematical, superscript, ligature) are not allowed';
  if (NON_ASCII_SPACE.test(value)) return 'only the ASCII space U+0020 is allowed';
  if (PADDED.test(value)) return 'leading or trailing space';
  if (SPACE_RUN.test(value)) return 'repeated spaces are not allowed';
  if (NON_ASCII_DIGIT.test(value)) return 'only ASCII digits 0-9 are allowed';
  if (mixesConfusableScripts(value)) return 'Latin, Cyrillic, Greek, Armenian and Cherokee letters must not be mixed in one value';
  return null;
}

export function assertValidBeneficiary(beneficiary: unknown): asserts beneficiary is AuthorizationBeneficiary {
  if (!beneficiary || typeof beneficiary !== 'object' || Array.isArray(beneficiary)) throw new ValidationError('Invalid beneficiary: must be an object');
  const entries = Object.entries(beneficiary as Record<string, unknown>);
  if (entries.length > BENEFICIARY_MAX_FIELDS) throw new ValidationError(`Invalid beneficiary: at most ${BENEFICIARY_MAX_FIELDS} fields`);
  for (const [key, value] of entries) {
    if (!BENEFICIARY_KEY_PATTERN.test(key)) throw new ValidationError(`Invalid beneficiary key "${key}": must match ${BENEFICIARY_KEY_PATTERN}`);
    if (typeof value !== 'string' || value.length === 0 || value.length > BENEFICIARY_MAX_VALUE_LENGTH) {
      throw new ValidationError(`Invalid beneficiary value for "${key}": 1 to ${BENEFICIARY_MAX_VALUE_LENGTH} characters`);
    }
    const violation = displayTextViolation(value);
    if (violation) throw new ValidationError(`Invalid beneficiary value for "${key}": ${violation}`);
    if (!ACCOUNT_KEYS.includes(key) && looksLikeIban(value)) {
      throw new ValidationError(`Invalid beneficiary value for "${key}": looks like an account number; put the account in iban, account or account_number`);
    }
    if (key === 'iban' && !isValidIban(value)) throw new ValidationError('Invalid beneficiary value for "iban": not a valid IBAN in electronic format');
    if (key === 'bic' && !BIC.test(value)) throw new ValidationError('Invalid beneficiary value for "bic": not a valid BIC');
  }
}

/** Applies the display text rules to the displayed top-level fields
 * (transaction_reference, operation_type) and the character rule to every
 * other top-level string field. */
const DISPLAYED_FIELDS = new Set(['transaction_reference', 'operation_type']);
export function assertDisplaySafeFields(value: AuthorizationObject): void {
  for (const [key, field] of Object.entries(value)) {
    if (typeof field !== 'string') continue;
    const violation = DISPLAYED_FIELDS.has(key) ? displayTextViolation(field) : DISPLAY_UNSAFE_CHARACTER.test(field) ? 'control, format or separator characters are not allowed' : null;
    if (violation) throw new ValidationError(`Invalid ${key}: ${violation}`);
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
