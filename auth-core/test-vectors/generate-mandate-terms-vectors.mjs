// Vectors for payment mandate terms (docs/protocol/payment-mandates-v1.md):
// the canonical bytes Auth Core builds and the device signs, and terms the
// SDK must refuse before it shows or signs anything. The SDK tests compare
// against this file; Auth Core's own encoder is checked against it in
// test/integration/mandates.test.mjs.
//
//   node test-vectors/generate-mandate-terms-vectors.mjs
import { createHash } from 'node:crypto';
import { canonicalJson } from '../scripts/lib/evidence.mjs';
import { writeVectors } from './vector-files.mjs';

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const MANDATE_ID = '5b0f3c9a-6d1e-4b7a-9c2f-0e8d7a6b5c4d';
const CREDENTIAL_ID = '3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b';
const base = {
  protocol_version: '1',
  domain: 'NEXUS-SIGN/MANDATE',
  mandate_id: MANDATE_ID,
  nexus_id: '123456789',
  credential_id: CREDENTIAL_ID,
  mandate_reference: 'MANDATE-2026-0001',
  payee: { iban: 'PL61109010140000071219812874', name: 'Energy Co' },
  currency: 'EUR',
  per_payment_limit_minor: '15000',
  total_limit_minor: null,
  frequency: 'MONTHLY',
  valid_from: '2026-11-01T00:00:00.000Z',
  valid_until: '2027-11-01T00:00:00.000Z',
  terms_version: '2026-11',
  issued_at: '2026-11-16T10:00:00.000Z',
  offer_expires_at: '2026-11-17T10:00:00.000Z',
  nonce: 'a'.repeat(64),
};
const terms = (o) => canonicalJson(o);
const entry = (name, bytes, extra = {}) => ({
  name, mandateId: MANDATE_ID, credentialId: CREDENTIAL_ID, termsBase64: bytes.toString('base64'), termsHash: sha256(bytes), ...extra,
});

const valid = [
  entry('monthly, no total limit', terms(base)),
  entry('yearly, total limit, BIC payee', terms({ ...base, frequency: 'YEARLY', total_limit_minor: '120000', payee: { bic: 'COBADEFFXXX', iban: 'DE89370400440532013000', name: 'ACME GmbH' } })),
  entry('all-Cyrillic payee name', terms({ ...base, currency: 'PLN', payee: { name: 'Энергосбыт' } })),
].map((v) => ({ ...v, expected: JSON.parse(Buffer.from(v.termsBase64, 'base64').toString('utf8')) }));

const invalid = [
  entry('payment-domain bytes', terms({ ...base, domain: 'NEXUS-SIGN/TRANSACTION-AUTH' }), { reason: 'wrong_domain' }),
  entry('other protocol version', terms({ ...base, protocol_version: '2' }), { reason: 'wrong_domain' }),
  entry('another mandate', terms({ ...base, mandate_id: '00000000-0000-4000-8000-000000000000' }), { reason: 'mismatch' }),
  entry('another device', terms({ ...base, credential_id: '00000000-0000-4000-8000-000000000001' }), { reason: 'wrong_device' }),
  { ...entry('hash does not match the bytes', terms(base)), termsHash: 'f'.repeat(64), reason: 'hash_mismatch' },
  entry('bytes not in canonical form', Buffer.from(JSON.stringify(base, null, 1)), { reason: 'not_canonical' }),
  entry('mixed-script payee name', terms({ ...base, payee: { name: 'Еnergy Co' } }), { reason: 'display' }),
  entry('bidi override in the reference', terms({ ...base, mandate_reference: 'REF‮gnp.exe' }), { reason: 'display' }),
  entry('IBAN with wrong check digits', terms({ ...base, payee: { iban: 'PL62109010140000071219812874', name: 'Energy Co' } }), { reason: 'iban' }),
  entry('missing field', terms(Object.fromEntries(Object.entries(base).filter(([k]) => k !== 'frequency'))), { reason: 'missing_field' }),
  entry('unexpected field', terms({ ...base, debit_day: '15' }), { reason: 'unexpected_field' }),
  entry('unknown frequency', terms({ ...base, frequency: 'DAILY' }), { reason: 'invalid_value' }),
  entry('limit not an integer string', terms({ ...base, per_payment_limit_minor: '150.00' }), { reason: 'invalid_value' }),
  entry('total below the per-payment limit', terms({ ...base, total_limit_minor: '100' }), { reason: 'invalid_value' }),
  entry('validity ends before it starts', terms({ ...base, valid_until: '2026-10-01T00:00:00.000Z' }), { reason: 'invalid_value' }),
];

writeVectors('mandate-terms-v1.json', `${JSON.stringify({
  description: 'Payment mandate terms v1: canonical bytes the device signs (valid) and terms the SDK refuses before showing (invalid, with the reason).',
  valid, invalid,
}, null, 2)}\n`);
