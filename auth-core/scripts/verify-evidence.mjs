#!/usr/bin/env node
// Verifies an evidence export offline, without trusting Auth Core: the HSM
// seals, the hash chain and its numbering, the provenance of every device key
// (sealed enrolment), and the customer's device signature over the exact
// transaction bytes.
//
//   node scripts/verify-evidence.mjs <export.json> [--public-keys=<file.pem>] [--expect-head=<sequence>:<evidenceHash>]
//
// <export.json> is the response of either
//   GET /v1/authorizations/{id}/evidence        (one record with its enrolment)
//   GET /v1/nexus-identities/{nexusId}/evidence (the whole chain)
// Both include the evidence public keys; for an audit, pass keys obtained out
// of band with --public-keys (one or more PEM public keys in one file).
// Exit codes: 0 valid against the given keys, 1 invalid, 2 usage error,
// 3 consistent only with the keys inside the export (no --public-keys).
// --expect-head is the chainSequence and evidenceHash the bank received with
// its latest confirmation: records removed after it are then detected.
import { readFileSync } from 'node:fs';
import { describeSignedTransaction, legacyRecords, verifyEvidenceChain, verifyEvidenceRecord } from './lib/evidence.mjs';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
if (!file) {
  console.error('usage: node scripts/verify-evidence.mjs <export.json> [--public-keys=<file.pem>] [--expect-head=<sequence>:<hash>]');
  process.exit(2);
}
const option = (name) => args.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);
const exported = JSON.parse(readFileSync(file, 'utf8'));
const keyFile = option('public-keys') ?? option('public-key');
const keys = keyFile
  ? readFileSync(keyFile, 'utf8').match(/-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/g)
  : exported.evidencePublicKeys ?? exported.evidencePublicKeyPem;
if (!keys || (Array.isArray(keys) && keys.length === 0)) {
  console.error('No evidence public key: pass --public-keys=<file.pem>');
  process.exit(2);
}
const headOption = option('expect-head');
let expectedHead;
if (headOption) {
  const [sequence, hash] = headOption.split(':');
  expectedHead = { chainSequence: Number(sequence), evidenceHash: hash };
}

const isChain = Array.isArray(exported.records);
const records = isChain ? exported.records : [exported];
const problems = isChain ? verifyEvidenceChain(records, keys, { expectedHead }) : verifyEvidenceRecord(exported, keys, { standalone: true });
if (problems.length > 0) {
  for (const p of problems) console.error(`INVALID  ${p}`);
  process.exit(1);
}
for (const record of records) {
  const payload = record.sealedPayload;
  const type = payload.schemaVersion === '3' ? payload.recordType : 'AUTHORIZATION';
  if (type === 'AUTHORIZATION') console.log(`VALID  #${record.chainSequence ?? '-'}  ${record.authorizationId}  ${describeSignedTransaction(payload)}`);
  else if (type === 'CREDENTIAL_ENROLLED') console.log(`VALID  #${record.chainSequence}  credential ${payload.credentialId} enrolled (${payload.reason}, attestation ${payload.attestation?.status})`);
  else console.log(`VALID  #${record.chainSequence}  recovery key configured by credential ${payload.credentialId}`);
}
const authorizations = records.filter((r) => (r.sealedPayload.schemaVersion === '3' ? r.sealedPayload.recordType : 'AUTHORIZATION') === 'AUTHORIZATION');
const offline = authorizations.filter((r) => r.sealedPayload.confirmationMethod === 'OFFLINE_CODE').length;
const legacy = legacyRecords(records).length;
const signatures = `device_signatures=${authorizations.length - offline}/${authorizations.length} verified${offline ? ` offline_codes=${offline} (not third-party verifiable)` : ''}`;
// Keys taken from the export only show that the export is self-consistent:
// whoever produced it could have sealed it with a key of their own. That
// result is reported differently and with exit code 3, so a script cannot
// mistake it for an independent verification.
const pinned = Boolean(keyFile);
if (!pinned) console.error('WARNING  seals were checked against the public keys inside the export; pass --public-keys with keys obtained out of band for an independent check');
console.log(`${pinned ? 'EVIDENCE_VALID' : 'EVIDENCE_SELF_CONSISTENT'} records=${records.length} hsm_seal=${pinned ? 'verified' : 'verified_with_export_keys'} ${signatures}${isChain ? ' chain=linked' : ''}`
  + `${expectedHead ? ' head=matched' : isChain ? ' head=not_checked' : ''}${legacy ? ` legacy_records=${legacy} (sealed before schema 3: no key provenance)` : ''}`);
if (!pinned) process.exitCode = 3;
