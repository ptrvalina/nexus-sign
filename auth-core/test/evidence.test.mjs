import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadTs } from './support/load-ts.mjs';
import { canonicalJson, describeSignedTransaction, verifyEvidenceChain, verifyEvidenceRecord } from '../scripts/lib/evidence.mjs';
import { fileURLToPath } from 'node:url';

const stubs = { '../db/pool': { pool: {}, withTransaction: async () => { throw new Error('no database in unit tests'); } } };
const { evidenceHash } = loadTs('services/evidenceService.ts', { stubs });
const { canonicalJson: serverCanonicalJson, canonicalizeAuthorization } = loadTs('services/canonicalAuthorization.ts');
const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts');

const device = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const devicePem = device.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const CREDENTIAL = '00000000-0000-4000-8000-000000000002';

/** Canonical bytes exactly as Auth Core builds and the device signs them. */
const signedBytes = (authorizationId, amountMinor = '125000') => canonicalizeAuthorization({
  protocol_version: '1',
  domain: 'NEXUS-SIGN/TRANSACTION-AUTH',
  authorization_id: authorizationId,
  nexus_id: '123456789',
  credential_id: CREDENTIAL,
  transaction_reference: `TX-${authorizationId}`,
  operation_type: 'transfer',
  amount_minor: amountMinor,
  currency: 'PLN',
  beneficiary: { name: 'Jan Kowalski', iban: 'PL61109010140000071219812874' },
  policy_reference: 'TRANSFER',
  policy_version: '2026-09',
  issued_at: '2026-09-29T09:58:00.000Z',
  expires_at: '2026-09-29T10:03:00.000Z',
  nonce: 'bm9uY2Utbm9uY2Utbm9uY2U',
});

const payload = (authorizationId, previousEvidenceHash, bytes = signedBytes(authorizationId)) => ({
  schemaVersion: '2',
  authorizationId,
  nexusId: '123456789',
  credentialId: CREDENTIAL,
  transactionReference: `TX-${authorizationId}`,
  canonicalPayloadHash: createHash('sha256').update(bytes).digest('hex'),
  signedPayloadBase64: bytes.toString('base64'),
  credentialPublicKeyPem: devicePem,
  signature: sign('sha256', bytes, { key: device.privateKey, dsaEncoding: 'der' }).toString('base64'),
  signatureFormat: 'der',
  signatureAlgorithm: 'ES256',
  keyVersion: 1,
  policyReference: 'TRANSFER',
  policyVersion: '2026-09',
  attestationVerdict: 'VERIFIED',
  verifiedAt: '2026-09-29T10:00:00.000Z',
  result: 'VERIFIED',
  correlationId: null,
  verificationFactors: [{ channel: 'AUDIO', status: 'VERIFIED', providerReference: 'p-1', assertionHash: 'ab'.repeat(32), completedAt: '2026-09-29T09:59:00.000Z' }],
  previousEvidenceHash,
});

async function seal(hsm, sealedPayload) {
  const hash = evidenceHash(sealedPayload);
  const { signature } = await hsm.signEvidence(Buffer.from(hash, 'hex'));
  return {
    authorizationId: sealedPayload.authorizationId,
    nexusId: sealedPayload.nexusId,
    sealedPayload,
    evidenceHash: hash,
    previousEvidenceHash: sealedPayload.previousEvidenceHash,
    hsmSignature: signature.toString('base64'),
  };
}

test('server evidence hash equals the independent verifier canonicalization', () => {
  const p = payload('a', null);
  assert.deepEqual(serverCanonicalJson(p), canonicalJson(p));
  assert.equal(evidenceHash(p), createHash('sha256').update(canonicalJson(p)).digest('hex'));
});

test('a sealed chain verifies offline; any tampering is detected', async () => {
  const hsm = new SoftwareHsmAdapter();
  const key = await hsm.evidencePublicKeyPem();
  const first = await seal(hsm, payload('a', null));
  const second = await seal(hsm, payload('b', first.evidenceHash));
  assert.deepEqual(verifyEvidenceChain([first, second], key), []);

  const altered = structuredClone(second);
  altered.sealedPayload.canonicalPayloadHash = '00'.repeat(32);
  assert.ok(verifyEvidenceRecord(altered, key).some((p) => p.includes('hash')));

  const reordered = verifyEvidenceChain([second, first], key);
  assert.ok(reordered.some((p) => p.includes('chain broken')));

  const otherKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.ok(verifyEvidenceRecord(first, otherKey).some((p) => p.includes('seal')));
});

test('the device signature is verified offline, so a re-sealed record with altered terms is caught', async () => {
  const hsm = new SoftwareHsmAdapter();
  const key = await hsm.evidencePublicKeyPem();
  const genuine = await seal(hsm, payload('c', null));
  assert.deepEqual(verifyEvidenceRecord(genuine, key), []);
  assert.match(describeSignedTransaction(genuine.sealedPayload), /transfer 125000 \(minor units\) PLN to \[.*iban=PL61.*\], ref TX-c/);

  // Whoever controls the evidence key can seal anything, but cannot make the
  // customer's key sign different terms.
  const forged = payload('c', null);
  const altered = signedBytes('c', '9900000');
  forged.signedPayloadBase64 = altered.toString('base64');
  forged.canonicalPayloadHash = createHash('sha256').update(altered).digest('hex');
  const resealed = await seal(hsm, forged);
  assert.ok(verifyEvidenceRecord(resealed, key).some((p) => p.includes('device signature does not verify')));

  const rawFormat = payload('d', null);
  rawFormat.signatureFormat = 'raw';
  rawFormat.signature = sign('sha256', signedBytes('d'), { key: device.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
  assert.deepEqual(verifyEvidenceRecord(await seal(hsm, rawFormat), key), []);

  const otherRecord = payload('e', null, signedBytes('f'));
  assert.ok(verifyEvidenceRecord(await seal(hsm, otherRecord), key).some((p) => p.includes('different authorization')));
});

test('an offline confirmation is sealed and chained, but its code is not treated as a device signature', async () => {
  const hsm = new SoftwareHsmAdapter();
  const key = await hsm.evidencePublicKeyPem();
  const offline = payload('g', null);
  offline.confirmationMethod = 'OFFLINE_CODE';
  offline.signatureFormat = 'hmac';
  offline.signatureAlgorithm = 'HMAC-SHA256';
  offline.signature = Buffer.alloc(32, 9).toString('base64');
  const record = await seal(hsm, offline);
  assert.deepEqual(verifyEvidenceRecord(record, key), []);
  assert.match(describeSignedTransaction(record.sealedPayload), /confirmed offline with a code/);

  const altered = payload('g', null, signedBytes('g', '1'));
  altered.confirmationMethod = 'OFFLINE_CODE';
  altered.canonicalPayloadHash = '00'.repeat(32);
  assert.ok(verifyEvidenceRecord(await seal(hsm, altered), key).some((p) => p.includes('canonicalPayloadHash')),
    'the signed bytes are still bound to the sealed hash');
});

// --- Schema 3: enrolment provenance, numbering, chain head ---

async function chainV3(hsm) {
  const keyId = await hsm.evidenceKeyId();
  const records = [];
  const append = async (recordType, body) => {
    const previous = records.at(-1);
    const sealedPayload = { schemaVersion: '3', recordType, nexusId: '123456789', chainSequence: records.length + 1, previousEvidenceHash: previous?.evidenceHash ?? null, sealKeyId: keyId, ...body };
    const hash = evidenceHash(sealedPayload);
    const { signature } = await hsm.signEvidence(Buffer.from(hash, 'hex'));
    // Export shape (mapEvidence): the columns that repeat sealed values, including seal key and schema.
    const record = { recordType, authorizationId: body.authorizationId ?? null, nexusId: '123456789', credentialId: CREDENTIAL, chainSequence: records.length + 1, sealedPayload, evidenceHash: hash, previousEvidenceHash: sealedPayload.previousEvidenceHash, hsmSignature: signature.toString('base64'), sealKeyId: keyId, schemaVersion: '3' };
    records.push(record);
    return record;
  };
  const enrolment = await append('CREDENTIAL_ENROLLED', { credentialId: CREDENTIAL, reason: 'ENROLMENT', keys: { signingPublicKeyPem: devicePem, authPublicKeyPem: null, offlinePublicKeyPem: null }, attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } });
  for (const id of ['a', 'b']) {
    const v2 = payload(id, null);
    delete v2.schemaVersion; delete v2.previousEvidenceHash; delete v2.nexusId;
    await append('AUTHORIZATION', { ...v2, enrolmentEvidenceHash: enrolment.evidenceHash });
  }
  return records;
}

test('schema 3: a complete chain verifies, with and without the expected head', async () => {
  const hsm = new SoftwareHsmAdapter();
  const records = await chainV3(hsm);
  const key = await hsm.evidencePublicKeyPem();
  assert.deepEqual(verifyEvidenceChain(records, key), []);
  const head = { chainSequence: 3, evidenceHash: records[2].evidenceHash };
  assert.deepEqual(verifyEvidenceChain(records, key, { expectedHead: head }), []);
  assert.ok(verifyEvidenceChain(records.slice(0, 2), key, { expectedHead: head }).some((p) => p.includes('missing at the end')));
});

test('schema 3: a gap, a duplicated position and a foreign signing key are reported', async () => {
  const hsm = new SoftwareHsmAdapter();
  const key = await hsm.evidencePublicKeyPem();
  const records = await chainV3(hsm);
  assert.ok(verifyEvidenceChain([records[0], records[2]], key).length > 0, 'gap');
  assert.ok(verifyEvidenceChain([records[0], records[1], records[1]], key).length > 0, 'duplicate');

  // An authorization whose key is not the enrolled key, sealed by the HSM:
  // what a database writer obtains by swapping the key before signing.
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const swapped = await chainV3(hsm);
  const last = swapped[2].sealedPayload;
  const bytes = Buffer.from(last.signedPayloadBase64, 'base64');
  const forgedPayload = { ...last, credentialPublicKeyPem: other.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    signature: sign('sha256', bytes, { key: other.privateKey, dsaEncoding: 'der' }).toString('base64') };
  const hash = evidenceHash(forgedPayload);
  swapped[2] = { ...swapped[2], sealedPayload: forgedPayload, evidenceHash: hash, hsmSignature: (await hsm.signEvidence(Buffer.from(hash, 'hex'))).signature.toString('base64') };
  assert.ok(verifyEvidenceChain(swapped, key).some((p) => p.includes('differs from the key sealed at enrolment')));
});

test('schema 3: a record sealed with an unknown evidence key is refused', async () => {
  const records = await chainV3(new SoftwareHsmAdapter());
  const otherKey = await new SoftwareHsmAdapter().evidencePublicKeyPem();
  assert.ok(verifyEvidenceChain(records, otherKey).some((p) => p.includes('HSM seal')));
});

test('schema 3: an authorization exported alone must bring its enrolment record (red-team RT-07)', async () => {
  const hsm = new SoftwareHsmAdapter();
  const key = await hsm.evidencePublicKeyPem();
  const [enrolment, authorization] = await chainV3(hsm);
  assert.deepEqual(verifyEvidenceRecord({ ...authorization, credentialEnrolment: enrolment }, key, { standalone: true }), []);
  const { credentialEnrolment, ...stripped } = { ...authorization, credentialEnrolment: enrolment };
  assert.ok(credentialEnrolment);
  assert.ok(verifyEvidenceRecord(stripped, key, { standalone: true }).some((p) => p.includes('enrolment record of the signing credential is missing')));
  assert.ok(verifyEvidenceRecord({ ...stripped, credentialEnrolment: null }, key, { standalone: true }).length > 0);
});

test('the verifier trusts only keys passed out of band: exit 0 with --public-keys, 3 with the export keys, 1 with a foreign key (red-team RT-06, RT-12)', async () => {
  const hsm = new SoftwareHsmAdapter();
  const records = await chainV3(hsm);
  const key = await hsm.evidencePublicKeyPem();
  const dir = mkdtempSync(join(tmpdir(), 'nexus-verify-'));
  const exportFile = join(dir, 'chain.json');
  writeFileSync(exportFile, JSON.stringify({ nexusId: '123456789', records, evidencePublicKeyPem: key, evidencePublicKeys: [key] }));
  writeFileSync(join(dir, 'keys.pem'), key);
  writeFileSync(join(dir, 'other.pem'), await new SoftwareHsmAdapter().evidencePublicKeyPem());
  const verify = (...extra) => spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/verify-evidence.mjs', import.meta.url)), exportFile, ...extra], { encoding: 'utf8' });
  const pinned = verify(`--public-keys=${join(dir, 'keys.pem')}`, `--expect-head=3:${records[2].evidenceHash}`);
  assert.equal(pinned.status, 0, pinned.stdout + pinned.stderr);
  assert.match(pinned.stdout, /^EVIDENCE_VALID /m);
  const selfConsistent = verify();
  assert.equal(selfConsistent.status, 3, selfConsistent.stdout + selfConsistent.stderr);
  assert.match(selfConsistent.stdout, /EVIDENCE_SELF_CONSISTENT .*hsm_seal=verified_with_export_keys/);
  assert.match(selfConsistent.stderr, /WARNING/);
  assert.equal(verify(`--public-keys=${join(dir, 'other.pem')}`).status, 1, 'a key not used by the HSM makes the chain invalid');
});

test('the verifier does not call a chain valid when its end was not checked (audit B-05)', async () => {
  const hsm = new SoftwareHsmAdapter();
  const records = await chainV3(hsm);
  const key = await hsm.evidencePublicKeyPem();
  const dir = mkdtempSync(join(tmpdir(), 'nexus-verify-head-'));
  writeFileSync(join(dir, 'keys.pem'), key);
  const run = (exported, ...extra) => {
    const file = join(dir, `e-${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(file, JSON.stringify({ nexusId: '123456789', evidencePublicKeys: [key], ...exported }));
    return spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/verify-evidence.mjs', import.meta.url)), file, `--public-keys=${join(dir, 'keys.pem')}`, ...extra], { encoding: 'utf8' });
  };
  const head = { chainSequence: 3, evidenceHash: records[2].evidenceHash };
  // Whole chain, no head the bank kept: valid seals, but exit 4, not 0.
  const unchecked = run({ records, head });
  assert.equal(unchecked.status, 4, unchecked.stdout + unchecked.stderr);
  assert.match(unchecked.stdout, /head=not_checked/);
  assert.equal(run({ records, head }, '--allow-unchecked-head').status, 0);
  // The last record removed: the export's own head shows it.
  const truncated = run({ records: records.slice(0, 2), head }, '--allow-unchecked-head');
  assert.equal(truncated.status, 1, truncated.stdout + truncated.stderr);
  assert.match(truncated.stderr, /records missing at the end of the chain/);
  // Removed together with the export's head: only a head the bank kept shows it.
  assert.equal(run({ records: records.slice(0, 2) }).status, 4);
  assert.equal(run({ records: records.slice(0, 2) }, `--expect-head=3:${records[2].evidenceHash}`).status, 1);
  // Nothing at all is never a valid chain.
  const empty = run({ records: [], head: null }, '--allow-unchecked-head');
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /no records/);
});
