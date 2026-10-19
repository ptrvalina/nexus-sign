// Unit tests of the bank's own execution decision (scripts/lib/bankTrust.mjs)
// and its statements; the Auth Core compromise cases run against a live Auth
// Core on SoftHSM in test/integration/bank-trust-compromise.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalJson } from '../scripts/lib/evidence.mjs';
import {
  approvalStatement, bankExecutionDecision, readRegistry, revocationStatement, signStatement, signingKeyFingerprint,
} from '../scripts/lib/bankTrust.mjs';

const vectors = JSON.parse(readFileSync(new URL('../test-vectors/bank-trust-v1.json', import.meta.url), 'utf8'));
const pair = () => generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pem = (k) => k.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const NEXUS = '123456789';
const CRED = '3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b';

test('fingerprints and statement bytes match the shared vectors', () => {
  for (const c of vectors.fingerprints) assert.equal(signingKeyFingerprint(c.publicKeyPem), c.signingKeySha256, c.name);
  for (const s of vectors.statements) assert.equal(canonicalJson(s.statement).toString('utf8'), s.canonicalUtf8, s.name);
});

test('statements: valid ones are read; unknown key, altered content, malformed fields are reported', () => {
  const bank = pair(); const other = pair();
  const device = pair();
  const approval = signStatement(approvalStatement({ nexusId: NEXUS, credentialId: CRED, signingKeySha256: signingKeyFingerprint(pem(device)), reference: 'r' }), bank.privateKey);
  const revocation = signStatement(revocationStatement({ nexusId: NEXUS, credentialId: CRED, reason: 'lost' }), bank.privateKey);
  const read = readRegistry([approval, revocation], [pem(bank)]);
  assert.deepEqual(read.problems, []);
  assert.equal(read.approvals.length, 1);
  assert.equal(read.revocations.length, 1);

  const foreign = signStatement(approval.statement, other.privateKey);
  const altered = { ...approval, statement: { ...approval.statement, credentialId: '00000000-0000-4000-8000-000000000000' } };
  const rebound = { ...approval, statement: { ...approval.statement, bankKeyId: foreign.statement.bankKeyId } };
  const malformed = signStatement({ ...approval.statement, signingKeySha256: 'XYZ' }, bank.privateKey);
  const wrongVersion = signStatement({ ...approval.statement, version: 2 }, bank.privateKey);
  const result = readRegistry([foreign, altered, rebound, malformed, wrongVersion, { statement: null }], [pem(bank)]);
  assert.equal(result.approvals.length, 0);
  assert.equal(result.problems.length, 6);
  assert.match(result.problems[0], /unknown bank key/);
  assert.match(result.problems[1], /does not verify/);
  assert.match(result.problems[2], /unknown bank key/);
  assert.match(result.problems[3], /malformed approval/);
  assert.match(result.problems[4], /unknown version/);
});

test('the decision fails closed without pinned evidence keys, bank keys, a record or expected terms', () => {
  assert.equal(bankExecutionDecision({}).allowed, false);
  const d = bankExecutionDecision({ evidence: { sealedPayload: { schemaVersion: '3', recordType: 'AUTHORIZATION' } }, evidenceKeys: [], bankTrustKeys: [] });
  assert.equal(d.allowed, false);
  assert.ok(d.problems.some((p) => /no pinned evidence keys/.test(p)));
  assert.ok(d.problems.some((p) => /no bank trust keys/.test(p)));
  assert.ok(d.problems.some((p) => /no expected terms/.test(p)));
  const notAuth = bankExecutionDecision({ evidence: { sealedPayload: { schemaVersion: '3', recordType: 'CREDENTIAL_ENROLLED' } }, evidenceKeys: ['x'], bankTrustKeys: ['y'] });
  assert.ok(notAuth.problems.some((p) => /not a schema 3 AUTHORIZATION/.test(p)));
  const heads = bankExecutionDecision({ evidence: { sealedPayload: { schemaVersion: '3', recordType: 'AUTHORIZATION', signedPayloadBase64: '' } }, expectedHead: { chainSequence: 1, evidenceHash: 'a' } });
  assert.ok(heads.problems.some((p) => /only be checked against the chain export/.test(p)));
});
