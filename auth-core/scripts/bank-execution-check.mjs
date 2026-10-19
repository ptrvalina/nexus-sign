#!/usr/bin/env node
// The bank's own check before it executes an operation confirmed through
// NEXUS-SIGN (bank credential trust v1). Decides from the bank's trust
// sources only: its pinned evidence keys, its trust keys and signed
// credential approvals and revocations, the terms it asked for, and the chain
// heads it kept. Auth Core's answers (VERIFIED, confirmed: true, a 202 for
// the commit request) are not inputs.
//
//   node scripts/bank-execution-check.mjs <authorization-evidence.json>
//        --public-keys=<pinned evidence keys .pem> --bank-trust-keys=<bank keys .pem>
//        --registry=<statements .jsonl or .json> --expect=<expected terms .json>
//        [--chain=<chain export .json>] [--expect-head=<sequence>:<evidenceHash>] [--heads=<file>]
//
// <authorization-evidence.json>: GET /v1/authorizations/{id}/evidence.
// <expected terms>: { authorizationId, nexusId, transactionReference,
//   amountMinor, currency, beneficiary, operationType? } from the bank's own records.
// Exit codes: 0 execute, 1 do not execute (reasons on stderr), 2 usage error.
import { readFileSync } from 'node:fs';
import { bankExecutionDecision } from './lib/bankTrust.mjs';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
const option = (name) => args.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);
const usage = (why) => {
  console.error(`${why}\nusage: node scripts/bank-execution-check.mjs <authorization-evidence.json> --public-keys=<pem> --bank-trust-keys=<pem> --registry=<file> --expect=<file> [--chain=<file>] [--expect-head=<seq>:<hash>] [--heads=<file>]`);
  process.exit(2);
};
const pems = (path) => readFileSync(path, 'utf8').match(/-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/g) ?? [];
const jsonOrLines = (path) => {
  const text = readFileSync(path, 'utf8').trim();
  if (!text) return [];
  return text.startsWith('[') ? JSON.parse(text) : text.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
};

if (!file) usage('no evidence file');
for (const required of ['public-keys', 'bank-trust-keys', 'registry', 'expect']) if (!option(required)) usage(`--${required} is required`);
let input;
try {
  const head = option('expect-head');
  input = {
    evidence: JSON.parse(readFileSync(file, 'utf8')),
    evidenceKeys: pems(option('public-keys')),
    bankTrustKeys: pems(option('bank-trust-keys')),
    registry: jsonOrLines(option('registry')),
    expected: JSON.parse(readFileSync(option('expect'), 'utf8')),
    chain: option('chain') ? JSON.parse(readFileSync(option('chain'), 'utf8')) : undefined,
    expectedHead: head ? { chainSequence: Number(head.split(':')[0]), evidenceHash: head.split(':')[1] } : undefined,
    heads: option('heads') ? jsonOrLines(option('heads')) : undefined,
  };
} catch (error) {
  usage(`cannot read the inputs: ${error.message}`);
}
const decision = bankExecutionDecision(input);
if (!decision.allowed) {
  for (const p of decision.problems) console.error(`DO NOT EXECUTE  ${p}`);
  process.exit(1);
}
console.log(`EXECUTE  ${input.evidence.authorizationId}: device key approved by the bank, evidence sealed with a pinned key, terms as requested`);
