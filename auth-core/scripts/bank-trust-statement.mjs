#!/usr/bin/env node
// Signs one bank trust statement (bank credential trust v1) and prints it as
// one JSON line, to be appended to the bank's registry. For development and
// tests: in production the bank's backend signs with a key in its own HSM,
// never with a file, and never with anything Auth Core holds.
//
//   node scripts/bank-trust-statement.mjs approve --key=<private.pem> --nexus-id=<id> --credential-id=<uuid>
//        (--signing-key-sha256=<hex> | --signing-key-pem=<file>) [--reference=<text>]
//   node scripts/bank-trust-statement.mjs revoke --key=<private.pem> --nexus-id=<id> --credential-id=<uuid> [--reason=<text>]
//
// --signing-key-sha256 is the fingerprint the bank's app reported from the
// SDK (signingKeyFingerprint()); approve only after checking it equals the
// key in the credential's sealed enrolment record.
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { approvalStatement, readRegistry, revocationStatement, signStatement, signingKeyFingerprint } from './lib/bankTrust.mjs';

const [command, ...rest] = process.argv.slice(2);
const option = (name) => rest.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);
const fail = (why) => { console.error(why); process.exit(2); };
if (!['approve', 'revoke'].includes(command)) fail('usage: bank-trust-statement.mjs approve|revoke --key=<private.pem> --nexus-id=<id> --credential-id=<uuid> ...');
if (!option('key') || !option('nexus-id') || !option('credential-id')) fail('--key, --nexus-id and --credential-id are required');
const key = createPrivateKey(readFileSync(option('key'), 'utf8'));
let statement;
if (command === 'approve') {
  const fingerprint = option('signing-key-sha256') ?? (option('signing-key-pem') ? signingKeyFingerprint(readFileSync(option('signing-key-pem'), 'utf8')) : undefined);
  if (!fingerprint) fail('approve needs --signing-key-sha256 or --signing-key-pem');
  statement = approvalStatement({ nexusId: option('nexus-id'), credentialId: option('credential-id'), signingKeySha256: fingerprint.toLowerCase(), reference: option('reference') ?? '' });
} else {
  statement = revocationStatement({ nexusId: option('nexus-id'), credentialId: option('credential-id'), reason: option('reason') ?? 'revoked' });
}
const entry = signStatement(statement, key);
// Refuse to print a statement this module would not accept itself.
const check = readRegistry([entry], [createPublicKey(key).export({ type: 'spki', format: 'pem' }).toString()]);
if (check.problems.length) fail(check.problems.join('\n'));
console.log(JSON.stringify(entry));
