// Vectors for the bank's trust in device keys (bank-credential-trust-v1.md):
// the signing key fingerprint the SDKs compute on the device, and the exact
// bytes a bank signs for a credential approval and a revocation. Computed
// here independently of the SDKs; the SDK tests compare against this file.
//
//   node test-vectors/generate-bank-trust-vectors.mjs
import { createHash, createPublicKey } from 'node:crypto';
import { canonicalJson } from '../scripts/lib/evidence.mjs';
import { writeVectors } from './vector-files.mjs';

// Test keys generated once for these vectors (public keys only).
const KEYS = [
  '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoI8KSPMtpbRVeuK+gfVNiu9oa6kq\nWiWUr5Q4Jqtzj6xwoh09LdR7uFhLtozuRmLsDok0yXVQDUmPszSc7WuiuQ==\n-----END PUBLIC KEY-----\n',
  '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbAGWkTnz76+7nea/ZBvNB9z5VH27\nIu+KHdNyytXNCBuXWrbGVy1nsn2A/cOiDdVb/SdZKQy6OroqD22b4YPj1g==\n-----END PUBLIC KEY-----\n',
];

const spki = (pem) => createPublicKey(pem).export({ type: 'spki', format: 'der' });
const fingerprint = (pem) => createHash('sha256').update(spki(pem)).digest('hex');

const fingerprints = KEYS.map((pem, i) => ({
  name: `p256-key-${i + 1}`,
  publicKeyPem: pem,
  spkiDerBase64: spki(pem).toString('base64'),
  signingKeySha256: fingerprint(pem),
}));

const bankKeyId = fingerprint(KEYS[1]);
const approval = {
  type: 'NEXUS_CREDENTIAL_APPROVAL', version: 1, nexusId: '123456789', credentialId: '3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b',
  signingKeySha256: fingerprint(KEYS[0]), reference: 'app-session-0001', approvedAt: '2026-10-19T10:00:00.000Z', bankKeyId,
};
const revocation = {
  type: 'NEXUS_CREDENTIAL_REVOCATION', version: 1, nexusId: '123456789', credentialId: '3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b',
  reason: 'lost', revokedAt: '2026-10-19T12:00:00.000Z', bankKeyId,
};

writeVectors('bank-trust-v1.json', `${JSON.stringify({
  description: 'Signing key fingerprints (hex SHA-256 of DER SubjectPublicKeyInfo) and the canonical bytes of bank trust statements (signed with ECDSA P-256 SHA-256, DER).',
  fingerprints,
  statements: [
    { name: 'approval', statement: approval, canonicalUtf8: canonicalJson(approval).toString('utf8') },
    { name: 'revocation', statement: revocation, canonicalUtf8: canonicalJson(revocation).toString('utf8') },
  ],
}, null, 2)}\n`);
