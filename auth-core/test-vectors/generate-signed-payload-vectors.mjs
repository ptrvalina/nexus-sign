// Generates the shared "what you see is what you sign" test vectors.
//
// The mobile SDKs never trust the JSON fields of an authorization response
// for display. They parse the exact bytes they are about to sign, require
// those bytes to be the canonical form the server produces, and show the
// amount, currency and beneficiary from the signed bytes only. These vectors
// pin that behavior across Auth Core (this file), Android and iOS.
//
// Usage: node test-vectors/generate-signed-payload-vectors.mjs
// Writes the vector file and copies it into both SDK test resource folders.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { writeVectors } from './vector-files.mjs';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// Same algorithm as src/services/canonicalAuthorization.ts (recursive key
// sort, then JSON.stringify). check-signed-payload-vectors.mjs asserts the two
// stay identical.
function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, normalize(value[k])]));
  }
  return value;
}
const canonical = (obj) => Buffer.from(JSON.stringify(normalize(obj)), 'utf8');
const b64 = (buf) => buf.toString('base64');
const sha = (buf) => createHash('sha256').update(buf).digest('hex');

const base = {
  protocol_version: '1',
  domain: 'NEXUS-SIGN/TRANSACTION-AUTH',
  authorization_id: '00000000-0000-4000-8000-000000000001',
  nexus_id: '123456789',
  credential_id: '00000000-0000-4000-8000-000000000002',
  transaction_reference: 'BANK-2026-000001',
  operation_type: 'transfer',
  amount_minor: '125000',
  currency: 'PLN',
  beneficiary: { name: 'Jan Kowalski', iban: 'PL61109010140000071219812874' },
  policy_reference: 'TRANSFER-DEFAULT',
  policy_version: '2026-09',
  issued_at: '2026-09-26T10:00:00.000Z',
  expires_at: '2026-09-26T10:02:00.000Z',
  nonce: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
};

// What the SDKs show in the system confirmation prompt: amount and
// the account identifier first, so a long payee name cannot push the account
// out of the visible part of the prompt; then the payee name, the BIC, any
// other fields by key; on a second line the operation type and the reference.
const ACCOUNT_KEYS = ['iban', 'account', 'account_number'];
const MINOR_UNITS = Object.fromEntries([
  ...['BIF', 'CLP', 'DJF', 'GNF', 'ISK', 'JPY', 'KMF', 'KRW', 'PYG', 'RWF', 'UGX', 'UYI', 'VND', 'VUV', 'XAF', 'XOF', 'XPF'].map((c) => [c, 0]),
  ...['BHD', 'IQD', 'JOD', 'KWD', 'LYD', 'OMR', 'TND'].map((c) => [c, 3]),
  ...['CLF', 'UYW'].map((c) => [c, 4]),
]);
function formatAmount(minor, currency) {
  const digits = MINOR_UNITS[currency] ?? 2;
  if (digits === 0) return minor;
  const padded = minor.padStart(digits + 1, '0');
  return `${padded.slice(0, -digits)}.${padded.slice(-digits)}`;
}
function beneficiaryDisplay(beneficiary) {
  const keys = Object.keys(beneficiary);
  const account = ACCOUNT_KEYS.find((k) => k in beneficiary);
  const ordered = [account, 'name', 'bic'].filter((k) => k && k in beneficiary);
  const rest = keys.filter((k) => !ordered.includes(k)).sort();
  return [...ordered, ...rest].map((k) => beneficiary[k]).join(' · ');
}
function confirmationText(f) {
  const who = beneficiaryDisplay(f.beneficiary);
  return `${formatAmount(f.amount_minor, f.currency)} ${f.currency}${who ? ` → ${who}` : ''}\n${f.operation_type} • ${f.transaction_reference}`;
}

const valid = [];
const addValid = (name, obj) => {
  const bytes = canonical(obj);
  valid.push({ name, canonical_base64: b64(bytes), canonical_sha256: sha(bytes), fields: obj, beneficiary_display: beneficiaryDisplay(obj.beneficiary), confirmation_text: confirmationText(obj) });
};

addValid('baseline transfer', base);
addValid('unicode, quotes, backslash and slash in beneficiary', {
  ...base,
  authorization_id: '00000000-0000-4000-8000-000000000003',
  beneficiary: {
    name: 'Zażółć gęślą jaźń "Sp. z o.o." \\ ✓ 😀',
    address_line_1: 'ul. Marszałkowska 1/2',
    note: 'Faktura 2026/09 <ref> & \u00e9',
    iban: 'PL61109010140000071219812874',
  },
});
addValid('zero amount and a currency without minor units', {
  ...base,
  authorization_id: '00000000-0000-4000-8000-000000000004',
  amount_minor: '0',
  currency: 'JPY',
  beneficiary: { account: '1234567', name: 'Tanaka' },
});
addValid('large amount (30 digits)', {
  ...base,
  authorization_id: '00000000-0000-4000-8000-000000000005',
  amount_minor: '123456789012345678901234567890',
});
addValid('empty beneficiary', { ...base, authorization_id: '00000000-0000-4000-8000-000000000006', beneficiary: {} });
addValid('payee name of 140 characters (the maximum) is shown after the account', {
  ...base,
  authorization_id: '00000000-0000-4000-8000-000000000007',
  beneficiary: { name: `ACME ${'N'.repeat(130)} GmbH`, iban: 'DE89370400440532013000', bic: 'COBADEFFXXX' },
});
// Phase 10 additions (appended, so the indexes of the vectors above stay).
// Look-alike letters are not a protocol error: the bytes are signed and shown
// as they are (Cyrillic А U+0410 and о U+043E here), so the signature binds
// them; whether a bank flags confusable payee names is .
addValid('payee name with Cyrillic look-alike letters is signed and shown as is', {
  ...base,
  authorization_id: '00000000-0000-4000-8000-000000000008',
  beneficiary: { name: '\u0410nna N\u043ewak', iban: 'PL61109010140000071219812874' },
});
addValid('smallest non-zero amount', { ...base, authorization_id: '00000000-0000-4000-8000-000000000009', amount_minor: '1', currency: 'EUR' });

const baseBytes = canonical(base);
const baseText = baseBytes.toString('utf8');
const invalid = [];
const addInvalid = (name, text, reason) => invalid.push({ name, reason, canonical_base64: b64(Buffer.from(text, 'utf8')) });

// A duplicated key is the classic way to show one value and sign another:
// many JSON parsers keep the last value, some keep the first.
addInvalid('duplicate amount_minor key', baseText.replace('{"amount_minor":"125000",', '{"amount_minor":"125000","amount_minor":"9999999",'), 'duplicate_key');
addInvalid('whitespace (not canonical)', JSON.stringify(normalize(base), null, 1), 'not_canonical');
addInvalid('keys not sorted', JSON.stringify(base), 'not_canonical');
addInvalid('unknown extra field', JSON.stringify(normalize({ ...base, display_amount: '1.00' })), 'unexpected_field');
{
  const { policy_version: _drop, ...missing } = base;
  addInvalid('missing policy_version', JSON.stringify(normalize(missing)), 'missing_field');
}
addInvalid('amount as JSON number', baseText.replace('"amount_minor":"125000"', '"amount_minor":125000'), 'invalid_value');
addInvalid('amount with leading zero', JSON.stringify(normalize({ ...base, amount_minor: '0125000' })), 'invalid_value');
addInvalid('amount with decimal point', JSON.stringify(normalize({ ...base, amount_minor: '1250.00' })), 'invalid_value');
addInvalid('lowercase currency', JSON.stringify(normalize({ ...base, currency: 'pln' })), 'invalid_value');
addInvalid('wrong domain', JSON.stringify(normalize({ ...base, domain: 'OTHER/DOMAIN' })), 'wrong_protocol');
addInvalid('wrong protocol version', JSON.stringify(normalize({ ...base, protocol_version: '2' })), 'wrong_protocol');
addInvalid('nested object in beneficiary', JSON.stringify(normalize({ ...base, beneficiary: { name: { first: 'Jan' } } })), 'invalid_value');
// Integer-like keys are enumerated first by JavaScript, so JSON.stringify
// emits them out of sorted order: rejected by the server and by the SDKs.
addInvalid('integer-like beneficiary key', JSON.stringify(normalize({ ...base, beneficiary: { 0: 'x', name: 'Jan' } })), 'invalid_value');
addInvalid('uppercase beneficiary key', JSON.stringify(normalize({ ...base, beneficiary: { Name: 'Jan' } })), 'invalid_value');
addInvalid('trailing data after object', `${baseText} `, 'not_canonical');
addInvalid('escaped slash (not canonical)', baseText.replace('BANK-2026-000001', 'BANK\\/2026'), 'not_canonical');
// Text that lays out differently from how it reads: a line break or a bidi
// override in a payee name can push the real IBAN out of the prompt.
addInvalid('line break in beneficiary value', JSON.stringify(normalize({ ...base, beneficiary: { name: 'ACME Energy\nPL00 0000', iban: 'PL61109010140000071219812874' } })), 'invalid_value');
addInvalid('bidi override in beneficiary name', JSON.stringify(normalize({ ...base, beneficiary: { name: 'Jan \u202eikswoloK', iban: 'PL61109010140000071219812874' } })), 'invalid_value');
addInvalid('line separator in beneficiary value', JSON.stringify(normalize({ ...base, beneficiary: { name: 'Jan\u2028Kowalski' } })), 'invalid_value');
addInvalid('zero-width space in transaction reference', JSON.stringify(normalize({ ...base, transaction_reference: 'BANK-2026\u200b-000001' })), 'invalid_value');
// Display limits: a value longer than an ISO 20022 Max140Text, a
// blank value, or one with leading or trailing space is refused, so the
// prompt cannot be padded or flooded.
addInvalid('beneficiary value of 141 characters', JSON.stringify(normalize({ ...base, beneficiary: { name: 'N'.repeat(141), iban: 'PL61109010140000071219812874' } })), 'invalid_value');
addInvalid('empty beneficiary value', JSON.stringify(normalize({ ...base, beneficiary: { name: '', iban: 'PL61109010140000071219812874' } })), 'invalid_value');
addInvalid('beneficiary value of spaces only', JSON.stringify(normalize({ ...base, beneficiary: { name: '   ', iban: 'PL61109010140000071219812874' } })), 'invalid_value');
addInvalid('leading space in beneficiary value', JSON.stringify(normalize({ ...base, beneficiary: { name: ' Jan Kowalski', iban: 'PL61109010140000071219812874' } })), 'invalid_value');
addInvalid('trailing no-break space in beneficiary value', JSON.stringify(normalize({ ...base, beneficiary: { name: 'Jan Kowalski\u00a0', iban: 'PL61109010140000071219812874' } })), 'invalid_value');
addInvalid('17 beneficiary fields', JSON.stringify(normalize({ ...base, beneficiary: Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`f${String(i).padStart(2, '0')}`, 'x'])) })), 'invalid_value');
addInvalid('amount of 31 digits', JSON.stringify(normalize({ ...base, amount_minor: '1'.repeat(31) })), 'invalid_value');
addInvalid('currency with a digit', JSON.stringify(normalize({ ...base, currency: 'PL1' })), 'invalid_value');
addInvalid('currency of four letters', JSON.stringify(normalize({ ...base, currency: 'PLNX' })), 'invalid_value');
addInvalid('empty nonce', JSON.stringify(normalize({ ...base, nonce: '' })), 'invalid_value');
addInvalid('nonce in uppercase hex', JSON.stringify(normalize({ ...base, nonce: base.nonce.toUpperCase() })), 'invalid_value');
addInvalid('nonce of 31 bytes', JSON.stringify(normalize({ ...base, nonce: base.nonce.slice(0, 62) })), 'invalid_value');
addInvalid('authorization_id not a UUID', JSON.stringify(normalize({ ...base, authorization_id: 'auth-1' })), 'invalid_value');
addInvalid('credential_id in uppercase', JSON.stringify(normalize({ ...base, credential_id: '00000000-0000-4000-8000-00000000000A' })), 'invalid_value');
addInvalid('nexus_id of 8 digits', JSON.stringify(normalize({ ...base, nexus_id: '12345678' })), 'invalid_value');
addInvalid('top level is an array', `[${baseText}]`, 'invalid_json');
invalid.push({ name: 'invalid UTF-8 byte', reason: 'invalid_json', canonical_base64: b64(Buffer.concat([baseBytes.subarray(0, 10), Buffer.from([0xff]), baseBytes.subarray(10)])) });

// Response JSON fields that disagree with the signed bytes. The SDK must
// refuse these even though the bytes themselves are valid and canonical.
const mismatches = [
  { name: 'displayed amount differs from signed amount', field: 'amountMinor', value: '100' },
  { name: 'displayed currency differs', field: 'currency', value: 'EUR' },
  { name: 'displayed beneficiary differs', field: 'beneficiary', value: { name: 'Jan Kowalski', iban: 'PL00000000000000000000000000' } },
  { name: 'displayed transaction reference differs', field: 'transactionReference', value: 'BANK-2026-999999' },
  { name: 'displayed expiry differs', field: 'expiresAt', value: '2026-09-26T11:00:00.000Z' },
  { name: 'authorization id differs', field: 'authorizationId', value: '00000000-0000-4000-8000-00000000ffff' },
  { name: 'payload hash differs', field: 'canonicalPayloadHash', value: '0'.repeat(64) },
];

const out = {
  description: 'Shared WYSIWYS vectors. Generated by generate-signed-payload-vectors.mjs - do not edit by hand.',
  valid,
  invalid,
  response_mismatch: { base_canonical_base64: b64(baseBytes), base_canonical_sha256: sha(baseBytes), cases: mismatches },
  amount_formatting: [
    { amount_minor: '125000', fraction_digits: 2, expected: '1250.00' },
    { amount_minor: '5', fraction_digits: 2, expected: '0.05' },
    { amount_minor: '0', fraction_digits: 2, expected: '0.00' },
    { amount_minor: '1500', fraction_digits: 0, expected: '1500' },
    { amount_minor: '1234567', fraction_digits: 3, expected: '1234.567' },
    { amount_minor: '123456789012345678901234567890', fraction_digits: 2, expected: '1234567890123456789012345678.90' },
  ],
};

// Recovery: the verifier must be identical on iOS and Android so a phrase set
// up on one platform recovers the identity on the other. Reference values come
// from Node's own PBKDF2/HMAC implementation.
{
  const { pbkdf2Sync, createHmac } = await import('node:crypto');
  const phrase = ['legal', 'winner', 'thank', 'year', 'wave', 'sausage', 'worth', 'useful', 'legal', 'winner', 'thank', 'yellow'];
  const salt = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const nonce = Buffer.from('f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f', 'hex');
  const iterations = 2048;
  const verifier = pbkdf2Sync(phrase.join(' '), salt, iterations, 32, 'sha256');
  out.recovery = {
    phrase,
    // The SDKs normalize case and whitespace before deriving; this variant must give the same verifier.
    phrase_unnormalized: ['  Legal', 'WINNER', 'thank  ', 'year', 'wave', 'sausage', 'worth', 'useful', 'legal', 'winner', 'thank', 'yellow '],
    salt_base64: salt.toString('base64'),
    iterations,
    key_length: 32,
    verifier_base64: verifier.toString('base64'),
    nonce_base64: nonce.toString('base64'),
    proof_base64: createHmac('sha256', verifier).update(nonce).digest('base64'),
  };
}

writeVectors('signed-payload-v1.json', `${JSON.stringify(out, null, 2)}\n`);

// Keep the original single example in step with the current protocol.
const example = { ...base, currency: 'EUR', beneficiary: { account: 'DE89370400440532013000', name: 'Example GmbH' } };
const exampleBytes = canonical(example);
writeFileSync(join(here, 'authorization-v1-example.json'), `${JSON.stringify({ ...example, _canonical_utf8_base64: b64(exampleBytes), _canonical_sha256: sha(exampleBytes) }, null, 2)}\n`);

console.log(`wrote signed payload vectors (valid=${valid.length}, invalid=${invalid.length}, mismatch=${mismatches.length})`);
