// App Attest and Play Integrity verification with test material generated
// here. Not real device tokens: the App Attest chain is issued by a root
// created by this test with OpenSSL (pinned through the same setting as
// Apple's root), and the Play Integrity answer stands in for Google's
// decodeIntegrityToken response. What this proves is Auth Core's own
// checks: chain to the pinned root, the nonce extension, keyId, authData
// fields and environment for App Attest; package, nonce, signing
// certificate and freshness for Play Integrity. A recorded token from a real
// device remains to be added (docs/engineering/KNOWN_LIMITATIONS.md).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadTs } from './support/load-ts.mjs';

const require = createRequire(import.meta.url);
const APP_ID = 'ABCDE12345.com.bank.app';

// --- minimal CBOR (RFC 8949) for the attestation object ---
function cborHead(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
}
function cbor(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([cborHead(2, value.length), value]);
  if (typeof value === 'string') { const s = Buffer.from(value, 'utf8'); return Buffer.concat([cborHead(3, s.length), s]); }
  if (Array.isArray(value)) return Buffer.concat([cborHead(4, value.length), ...value.map(cbor)]);
  if (typeof value === 'number') return cborHead(0, value);
  const entries = Object.entries(value);
  return Buffer.concat([cborHead(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)])]);
}
/** Decoder used only when the 'cbor' package is not installed (as in the review environment). */
function decodeFirstMinimal(buf) {
  let i = 0;
  const read = () => {
    const first = buf[i++]; const major = first >> 5; let n = first & 31;
    if (n === 24) n = buf[i++]; else if (n === 25) { n = buf.readUInt16BE(i); i += 2; } else if (n === 26) { n = buf.readUInt32BE(i); i += 4; } else if (n > 26) throw new Error('unsupported CBOR');
    if (major === 0) return n;
    if (major === 2) { const v = Buffer.from(buf.subarray(i, i + n)); i += n; return v; }
    if (major === 3) { const v = buf.toString('utf8', i, i + n); i += n; return v; }
    if (major === 4) return Array.from({ length: n }, read);
    if (major === 5) { const m = new Map(); for (let k = 0; k < n; k += 1) { const key = read(); m.set(key, read()); } return m; }
    throw new Error('unsupported CBOR major type');
  };
  return Promise.resolve(read());
}
let cborModule;
try { cborModule = require('cbor'); } catch { cborModule = { decodeFirst: decodeFirstMinimal }; }

// --- an App Attest-shaped chain from a test root, with OpenSSL ---
let dir;
const ossl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
function ca(name, issuer) {
  ossl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`);
  writeFileSync(join(dir, `${name}.ext`), 'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n');
  if (!issuer) {
    ossl('req', '-new', '-x509', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-days', '30', '-out', `${name}.pem`, '-addext', 'basicConstraints=critical,CA:true', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  } else {
    ossl('req', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-out', `${name}.csr`);
    ossl('x509', '-req', '-in', `${name}.csr`, '-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`, '-CAcreateserial', '-days', '30', '-extfile', `${name}.ext`, '-out', `${name}.pem`);
  }
}
const der = (pem) => Buffer.from(readFileSync(join(dir, pem), 'utf8').replace(/-----[^-]+-----|\s/g, ''), 'base64');

/** A fresh leaf for one attestation: returns the attestation object and keyId. */
function attestation({ clientDataHash, appId = APP_ID, aaguid = 'appattestdevelop', counter = 0, issuer = 'intermediate', fmt = 'apple-appattest', nonceOverride } = {}) {
  const name = `leaf-${randomBytes(4).toString('hex')}`;
  ossl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`);
  const spki = Buffer.from(execFileSync('openssl', ['ec', '-in', `${name}.key`, '-pubout', '-outform', 'DER'], { cwd: dir, stdio: ['ignore', 'pipe', 'ignore'] }));
  const keyId = createHash('sha256').update(spki.subarray(spki.length - 65)).digest();
  const counterBytes = Buffer.alloc(4); counterBytes.writeUInt32BE(counter);
  const aaguidBytes = Buffer.alloc(16); Buffer.from(aaguid).copy(aaguidBytes);
  const credLen = Buffer.alloc(2); credLen.writeUInt16BE(32);
  const authData = Buffer.concat([createHash('sha256').update(appId).digest(), Buffer.from([0x40]), counterBytes, aaguidBytes, credLen, keyId]);
  const nonce = nonceOverride ?? createHash('sha256').update(Buffer.concat([authData, clientDataHash])).digest();
  writeFileSync(join(dir, `${name}.ext`), `1.2.840.113635.100.8.2=DER:3024a1220420${nonce.toString('hex')}\n`);
  ossl('req', '-new', '-key', `${name}.key`, '-subj', '/CN=leaf', '-out', `${name}.csr`);
  ossl('x509', '-req', '-in', `${name}.csr`, '-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`, '-CAcreateserial', '-days', '5', '-extfile', `${name}.ext`, '-out', `${name}.pem`);
  const object = cbor({ fmt, attStmt: { x5c: [der(`${name}.pem`), der(`${issuer}.pem`)], receipt: Buffer.from('receipt') }, authData });
  return { attestationObjectBase64: object.toString('base64'), keyId: keyId.toString('base64') };
}

let appAttest;
before(() => {
  dir = mkdtempSync(join(tmpdir(), 'nexus-attest-'));
  ca('root'); ca('intermediate', 'root');
  ca('other-root'); ca('other-intermediate', 'other-root');
  const env = { APPLE_APP_ID: APP_ID, APPLE_APP_ATTEST_ROOT_CA_PEM: readFileSync(join(dir, 'root.pem'), 'utf8') };
  const cache = new Map();
  appAttest = loadTs('services/appAttestService.ts', { cache, stubs: { cbor: cborModule, '../config/env': { env } } });
});
after(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

test('App Attest: a chain to the pinned root with the right nonce, keyId and authData verifies; the environment follows the aaguid', async () => {
  const clientDataHash = randomBytes(32);
  assert.deepEqual(await appAttest.verifyAppAttestAttestation({ ...attestation({ clientDataHash }), clientDataHash }), { environment: 'development' });
  assert.deepEqual(await appAttest.verifyAppAttestAttestation({ ...attestation({ clientDataHash, aaguid: 'appattest' }), clientDataHash }), { environment: 'production' });
});

for (const [why, make, pattern] of [
  ['another session (clientDataHash)', (h) => ({ ...attestation({ clientDataHash: h }), clientDataHash: randomBytes(32) }), /nonce extension did not match/],
  ['a nonce extension for other data', (h) => ({ ...attestation({ clientDataHash: h, nonceOverride: randomBytes(32) }), clientDataHash: h }), /nonce extension did not match/],
  ['another key (keyId)', (h) => ({ ...attestation({ clientDataHash: h }), keyId: randomBytes(32).toString('base64'), clientDataHash: h }), /keyId did not match/],
  ['a chain from another root', (h) => ({ ...attestation({ clientDataHash: h, issuer: 'other-intermediate' }), clientDataHash: h }), /Apple App Attest root/],
  ['another app', (h) => ({ ...attestation({ clientDataHash: h, appId: 'ZZZZZ99999.com.evil.app' }), clientDataHash: h }), /rpIdHash/],
  ['a counter above 0 (an assertion, not an attestation)', (h) => ({ ...attestation({ clientDataHash: h, counter: 1 }), clientDataHash: h }), /counter == 0/],
  ['an unknown aaguid', (h) => ({ ...attestation({ clientDataHash: h, aaguid: 'emulator' }), clientDataHash: h }), /Unrecognized aaguid/],
  ['another format', (h) => ({ ...attestation({ clientDataHash: h, fmt: 'packed' }), clientDataHash: h }), /Unexpected attestation format/],
]) {
  test(`App Attest: refused for ${why}`, async () => {
    const h = randomBytes(32);
    await assert.rejects(appAttest.verifyAppAttestAttestation(make(h)), pattern);
  });
}

// --- Play Integrity: Auth Core's checks on Google's decoded verdict ---
function playIntegrity(payload, { status = 200, certs = [] } = {}) {
  const env = { GOOGLE_SERVICE_ACCOUNT_JSON: '{}', ANDROID_PACKAGE_NAME: 'com.bank.app', ANDROID_APP_CERT_SHA256: certs, ATTESTATION_MAX_AGE_SECONDS: 300 };
  const svc = loadTs('services/playIntegrityService.ts', { stubs: {
    '../config/env': { env },
    '../crypto/googleServiceAccount': { parseServiceAccountJson: () => ({}), getGoogleAccessToken: async () => 'access-token' },
  } });
  const realFetch = globalThis.fetch;
  return { svc, run: async (nonce) => {
    globalThis.fetch = async (url, init) => {
      assert.match(String(url), /playintegrity\.googleapis\.com\/v1\/com\.bank\.app:decodeIntegrityToken$/);
      assert.equal(init.headers.Authorization, 'Bearer access-token');
      return { ok: status === 200, status, json: async () => ({ tokenPayloadExternal: payload }) };
    };
    try { return await svc.verifyPlayIntegrityToken('token', nonce); } finally { globalThis.fetch = realFetch; }
  } };
}
const digest = createHash('sha256').update('app signing cert').digest();
const verdict = (over = {}) => ({
  requestDetails: { requestPackageName: 'com.bank.app', nonce: 'bm9uY2U', timestampMillis: String(Date.now()), ...over.requestDetails },
  appIntegrity: { appRecognitionVerdict: 'PLAY_RECOGNIZED', packageName: 'com.bank.app', certificateSha256Digest: [digest.toString('base64url')], ...over.appIntegrity },
  deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'], ...over.deviceIntegrity },
});

test('Play Integrity: a fresh verdict for this package, nonce and signing certificate is accepted', async () => {
  const r = await playIntegrity(verdict(), { certs: [digest.toString('hex')] }).run('bm9uY2U');
  assert.equal(r.appRecognized, true); assert.deepEqual(r.deviceIntegrityVerdicts, ['MEETS_DEVICE_INTEGRITY']);
});

for (const [why, payload, opts, pattern] of [
  ['another nonce (replay)', verdict({ requestDetails: { nonce: 'b3RoZXI' } }), {}, /nonce did not match/],
  ['another requesting package', verdict({ requestDetails: { requestPackageName: 'com.evil.app' } }), {}, /requestPackageName/],
  ['another app package', verdict({ appIntegrity: { packageName: 'com.evil.app' } }), {}, /appIntegrity.packageName/],
  ['another signing certificate', verdict(), { certs: [createHash('sha256').update('other').digest('hex')] }, /accepted certificate/],
  ['an old verdict', verdict({ requestDetails: { timestampMillis: String(Date.now() - 3_600_000) } }), {}, /freshness/],
  ['an error from Google', verdict(), { status: 400 }, /HTTP 400/],
]) {
  test(`Play Integrity: refused for ${why}`, async () => {
    await assert.rejects(playIntegrity(payload, opts).run('bm9uY2U'), pattern);
  });
}
