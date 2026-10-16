// Guards the shared WYSIWYS vectors against drift. It loads the server's real
// src/services/canonicalAuthorization.ts (transpiled in memory with the
// project's TypeScript compiler) and checks that:
// 1. the vector field set equals the server's AuthorizationObject;
// 2. every valid vector's bytes equal the server's canonicalizeAuthorization();
// 3. the server rejects the beneficiary shapes the SDKs reject.
// The copies are checked by check-vector-copies.mjs.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { loadTs } from '../test/support/load-ts.mjs';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const fail = (msg) => { console.error(`error: ${msg}`); process.exit(1); };

const master = readFileSync(join(here, 'signed-payload-v1.json'), 'utf8');
const vectors = JSON.parse(master);

// Load the real server module.
const sourcePath = join(here, '..', 'src', 'services', 'canonicalAuthorization.ts');
const source = readFileSync(sourcePath, 'utf8');
const server = { exports: loadTs('services/canonicalAuthorization.ts') };
const { canonicalizeAuthorization, assertValidBeneficiary } = server.exports;
if (typeof canonicalizeAuthorization !== 'function' || typeof assertValidBeneficiary !== 'function') fail('server exports changed');

const iface = /export interface AuthorizationObject \{([\s\S]*?)\n\}/.exec(source);
if (!iface) fail('AuthorizationObject interface not found');
const serverFields = [...iface[1].matchAll(/^\s*([a-z_]+):/gm)].map((m) => m[1]).sort();
const sha = (buf) => createHash('sha256').update(buf).digest('hex');

for (const v of vectors.valid) {
  const fields = Object.keys(v.fields).sort();
  if (JSON.stringify(fields) !== JSON.stringify(serverFields)) fail(`vector "${v.name}" fields ${fields} != server AuthorizationObject ${serverFields}`);
  const bytes = canonicalizeAuthorization(v.fields);
  if (bytes.toString('base64') !== v.canonical_base64) fail(`vector "${v.name}" bytes differ from the server's canonicalizeAuthorization()`);
  if (sha(bytes) !== v.canonical_sha256) fail(`vector "${v.name}" hash mismatch`);
}

for (const bad of [{ 0: 'x', name: 'Jan' }, { Name: 'Jan' }, { name: { first: 'Jan' } }, { name: 1 }, { name: 'Jan\nPL61' }, { name: 'Jan \u202eKowalski' }]) {
  let rejected = false;
  try { assertValidBeneficiary(bad); } catch { rejected = true; }
  if (!rejected) fail(`server accepted beneficiary ${JSON.stringify(bad)}`);
}

const example = JSON.parse(readFileSync(join(here, 'authorization-v1-example.json'), 'utf8'));
const { _canonical_utf8_base64: exampleB64, _canonical_sha256: exampleSha, ...exampleFields } = example;
if (JSON.stringify(Object.keys(exampleFields).sort()) !== JSON.stringify(serverFields)) fail('authorization-v1-example.json field set is out of date with AuthorizationObject');
if (canonicalizeAuthorization(exampleFields).toString('base64') !== exampleB64) fail('authorization-v1-example.json canonical bytes are stale');
if (sha(Buffer.from(exampleB64, 'base64')) !== exampleSha) fail('authorization-v1-example.json hash is stale');

console.log(`ok: signed payload vectors (valid=${vectors.valid.length} invalid=${vectors.invalid.length} fields=${serverFields.length})`);
