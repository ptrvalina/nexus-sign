#!/usr/bin/env node
// End-to-end check of a running Auth Core, exercising the full flow the way the
// bank backend and the mobile SDK do: bank OAuth -> identity -> mobile bootstrap
// with real P-256 keys -> device-signed requests (no token) -> transaction
// authorization -> device-side payload check -> signature (tampered, valid,
// replayed) -> evidence verified offline -> bank commit -> adaptive verification
// (audio, video, escalation, failure) -> offline confirmation with a QR code and
// an 8-digit code -> recovery (protocol 2) -> rotated keys.
//
// No dependencies (Node 20+). Works on Linux, macOS and Windows PowerShell:
//
//   node scripts/e2e-smoke.mjs http://localhost:8080
//
// Requires a registered bank client (npm run register-client -- <id>) and
// REQUIRE_VALID_ATTESTATION=false (the local default), since a script cannot
// produce genuine App Attest / Play Integrity evidence.
import { createHash, createHmac, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, sign } from 'node:crypto';
import { verifyEvidenceChain, verifyEvidenceRecord } from './lib/evidence.mjs';
import { createRecoveryKey, openRecoveryKey, proofSigningInput, setupSigningInput, signDerB64 } from './lib/recovery.mjs';

const BASE_URL = (process.argv[2] ?? process.env.NEXUS_SIGN_BASE_URL ?? 'http://localhost:8080').replace(/\/$/, '');
const CLIENT_ID = process.env.NEXUS_SIGN_SMOKE_CLIENT_ID ?? 'smoke-test-bank';
const CLIENT_SECRET = process.env.NEXUS_SIGN_SMOKE_CLIENT_SECRET;
if (!CLIENT_SECRET) {
  console.error('Set NEXUS_SIGN_SMOKE_CLIENT_SECRET to the client_secret printed by `npm run register-client`.');
  console.error('  PowerShell: $env:NEXUS_SIGN_SMOKE_CLIENT_SECRET = "<secret>"');
  console.error('  bash:       export NEXUS_SIGN_SMOKE_CLIENT_SECRET=<secret>');
  process.exit(2);
}

let passed = 0;
const pass = (msg) => { passed += 1; console.log(`PASS  ${msg}`); };
const fail = (msg, detail) => {
  console.error(`FAIL  ${msg}`);
  if (detail !== undefined) console.error(typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2));
  console.error(`\n${passed} checks passed before the failure.`);
  process.exit(1);
};
const expect = (ok, msg, detail) => (ok ? pass(msg) : fail(msg, detail));

/**
 * `token` sends a bearer token; `device` ({ credentialId, authKey }) signs the
 * request with the device authentication key, as the SDKs do after enrolment.
 */
async function call(method, path, { token, device, body, headers = {} } = {}) {
  const raw = body !== undefined ? JSON.stringify(body) : undefined;
  let response;
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      method,
      headers: {
        ...(raw !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(device ? deviceHeaders(device, method, path, raw ?? '') : {}),
        ...headers,
      },
      body: raw,
    });
  } catch (error) {
    fail(`${method} ${path}: server not reachable at ${BASE_URL}`, String(error?.cause ?? error));
  }
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON body */ }
  return { status: response.status, json, text };
}

// Same canonicalization as the server and both SDKs (sorted keys, JSON.stringify).
const normalize = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, normalize(v[k])])) : v);
const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');

// What the mobile SDK does before it lets the customer sign.
function verifySignedPayload(auth) {
  const bytes = Buffer.from(auth.canonicalPayloadBase64, 'base64');
  const parsed = JSON.parse(bytes.toString('utf8'));
  if (Buffer.compare(Buffer.from(JSON.stringify(normalize(parsed)), 'utf8'), bytes) !== 0) return 'not canonical';
  if (sha256hex(bytes) !== auth.canonicalPayloadHash) return 'hash mismatch';
  const pairs = [
    ['authorization_id', auth.authorizationId], ['nexus_id', auth.nexusId], ['credential_id', auth.credentialId],
    ['transaction_reference', auth.transactionReference], ['operation_type', auth.operationType],
    ['amount_minor', auth.amountMinor], ['currency', auth.currency], ['policy_reference', auth.policyReference],
    ['policy_version', auth.policyVersion], ['issued_at', auth.issuedAt], ['expires_at', auth.expiresAt],
  ];
  for (const [field, value] of pairs) if (parsed[field] !== value) return `field ${field} differs`;
  if (JSON.stringify(normalize(parsed.beneficiary)) !== JSON.stringify(normalize(auth.beneficiary))) return 'beneficiary differs';
  return null;
}

const newDeviceKey = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { privateKey, publicKey, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
};
const signBytes = (key, bytes) => sign('sha256', bytes, { key: key.privateKey, dsaEncoding: 'der' }).toString('base64');

/** Device protocols v1 (docs/protocol/device-authentication-and-offline-confirmation.md). */
function deviceHeaders(device, method, path, rawBody) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString('base64url');
  const input = ['NEXUS-SIGN/DEVICE-REQUEST/v1', method, path, timestamp, nonce, device.credentialId,
    sha256hex(Buffer.from(rawBody, 'utf8'))].join('\n');
  return {
    'X-NEXUS-Credential': device.credentialId,
    'X-NEXUS-Timestamp': timestamp,
    'X-NEXUS-Nonce': nonce,
    'X-NEXUS-Signature': signBytes(device.authKey, Buffer.from(input, 'utf8')),
  };
}

function offlineCode(offlineKey, serverPublicKeyPem, credentialId, canonical) {
  const shared = diffieHellman({ privateKey: offlineKey.privateKey, publicKey: createPublicKey(serverPublicKeyPem) });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.from('NEXUS-SIGN/OFFLINE/v1'), Buffer.from(credentialId), 32));
  const tag = createHmac('sha256', key)
    .update(Buffer.concat([Buffer.from('NEXUS-SIGN/OFFLINE-CODE/v1'), Buffer.from([0]), createHash('sha256').update(canonical).digest()]))
    .digest();
  const offset = tag[31] & 0x0f;
  const bin = ((tag[offset] & 0x7f) << 24) | (tag[offset + 1] << 16) | (tag[offset + 2] << 8) | tag[offset + 3];
  return String(bin % 100000000).padStart(8, '0');
}

console.log(`NEXUS-SIGN end-to-end check against ${BASE_URL}\n`);

// --- Health ---
{
  const health = await call('GET', '/healthz');
  expect(health.status === 200 && health.json?.status === 'ok', 'liveness /healthz', health.text);
  const ready = await call('GET', '/readyz');
  expect(ready.status === 200 && ready.json?.status === 'ready', 'readiness /readyz (Postgres + Redis reachable)', ready.text);
}

// --- Bank backend authentication ---
const tokenResponse = await call('POST', '/oauth/token', { body: { grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET } });
const BANK = tokenResponse.json?.access_token;
expect(tokenResponse.status === 200 && BANK, 'OAuth client-credentials token', tokenResponse.text);

{
  const form = await fetch(`${BASE_URL}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET }),
  });
  expect(form.status === 200, 'OAuth token endpoint accepts the RFC 6749 form encoding', await form.text());
  const wrong = await call('POST', '/oauth/token', { body: { grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: 'wrong' } });
  expect(wrong.status === 401 && wrong.json?.error === 'invalid_client', 'wrong client secret → 401 invalid_client', wrong.text);
  const anonymous = await call('POST', '/v1/nexus-identities', { body: { bankCustomerRef: 'x' } });
  expect(anonymous.status === 401, 'bank API rejects requests without a token', anonymous.text);
}

// --- Identity ---
const bankCustomerRef = `e2e-${Date.now()}-${randomBytes(3).toString('hex')}`;
const identity = await call('POST', '/v1/nexus-identities', { token: BANK, body: { bankCustomerRef } });
const NEXUS_ID = identity.json?.nexusId;
expect(identity.status === 201 && /^\d{9}$/.test(NEXUS_ID ?? ''), `NEXUS ID issued (${NEXUS_ID})`, identity.text);

// --- Mobile bootstrap ---
// How the bank re-identified the customer before enrolling a replacement device.
const REPLACEMENT = { replacement: { method: 'OTHER', reference: `e2e-${randomBytes(4).toString('hex')}` } };
const bootstrapSession = await call('POST', '/v1/mobile/sessions', { token: BANK, body: { nexusId: NEXUS_ID } });
expect(bootstrapSession.status === 201 && bootstrapSession.json?.purpose === 'BOOTSTRAP', 'bank mints a customer-scoped bootstrap token', bootstrapSession.text);

{
  const bankTokenOnMobile = await call('GET', '/v1/mobile/recovery/setup', { token: BANK });
  expect(bankTokenOnMobile.status === 401, 'mobile endpoints refuse the bank-wide token', bankTokenOnMobile.text);
}

const device = newDeviceKey();
const deviceAuthKey = newDeviceKey();
const deviceOfflineKey = newDeviceKey();
const bootstrap = await call('POST', '/v1/mobile/bootstrap', {
  token: bootstrapSession.json.accessToken,
  body: {
    publicKeyPem: device.publicKeyPem, authPublicKeyPem: deviceAuthKey.publicKeyPem, offlinePublicKeyPem: deviceOfflineKey.publicKeyPem,
    platform: 'OTHER', securityLevel: 'SOFTWARE_TEST', deviceAttestation: {},
  },
});
const CREDENTIAL_ID = bootstrap.json?.credentialId;
const OFFLINE_SERVER_KEY = bootstrap.json?.offlineServerPublicKeyPem;
expect(bootstrap.status === 201 && CREDENTIAL_ID && bootstrap.json?.requestAuthentication === 'DEVICE_SIGNATURE' && !bootstrap.json?.accessToken,
  'device enrolled with signing, authentication and offline keys; no token issued', bootstrap.text);
// From here on the device signs its own requests; it holds no token.
const MOBILE = { credentialId: CREDENTIAL_ID, authKey: deviceAuthKey };
{
  const signed = await call('GET', '/v1/mobile/recovery/setup', { device: MOBILE });
  expect(signed.status === 200, 'a device-signed request is accepted without any token', signed.text);
  const headers = deviceHeaders(MOBILE, 'GET', '/v1/mobile/recovery/setup', '');
  const first = await call('GET', '/v1/mobile/recovery/setup', { headers });
  const replay = await call('GET', '/v1/mobile/recovery/setup', { headers });
  expect(first.status === 200 && replay.status === 401, 'a captured device-signed request cannot be replayed', replay.text);
  const otherPath = await call('GET', '/v1/mobile/authorizations/00000000-0000-4000-8000-000000000000', { headers: deviceHeaders(MOBILE, 'GET', '/v1/mobile/recovery/setup', '') });
  expect(otherPath.status === 401, 'a device signature is bound to its path', otherPath.text);
  const wrongKey = await call('GET', '/v1/mobile/recovery/setup', { device: { credentialId: CREDENTIAL_ID, authKey: device } });
  expect(wrongKey.status === 401, 'the signing key cannot stand in for the authentication key', wrongKey.text);
  const session = await call('POST', '/v1/mobile/sessions', { token: BANK, body: { nexusId: NEXUS_ID, purpose: 'SESSION' } });
  expect(session.status === 400, 'there are no session tokens: an enrolled device only signs its requests', session.text);
}

{
  // Every device enrols an authentication key; there is no token-based fallback.
  const otherIdentity = await call('POST', '/v1/nexus-identities', { token: BANK, body: { bankCustomerRef: `${bankCustomerRef}-other` } });
  const otherBootstrap = await call('POST', '/v1/mobile/sessions', { token: BANK, body: { nexusId: otherIdentity.json.nexusId } });
  const withoutAuthKey = await call('POST', '/v1/mobile/bootstrap', {
    token: otherBootstrap.json.accessToken,
    body: { publicKeyPem: newDeviceKey().publicKeyPem, platform: 'OTHER', securityLevel: 'SOFTWARE_TEST', deviceAttestation: {} },
  });
  expect(withoutAuthKey.status === 400, 'enrolment without a request authentication key is refused', withoutAuthKey.text);
  const nul = await call('POST', '/v1/mobile/bootstrap', {
    token: otherBootstrap.json.accessToken,
    body: { publicKeyPem: `${newDeviceKey().publicKeyPem}\u0000extra`, authPublicKeyPem: newDeviceKey().publicKeyPem, platform: 'OTHER', securityLevel: 'SOFTWARE_TEST', deviceAttestation: {} },
  });
  expect(nul.status === 400, 'a public key with trailing data is refused (the PEM text is attested)', nul.text);
}
{
  const again = await call('POST', '/v1/mobile/bootstrap', {
    token: bootstrapSession.json.accessToken,
    body: { publicKeyPem: newDeviceKey().publicKeyPem, authPublicKeyPem: newDeviceKey().publicKeyPem, platform: 'OTHER', securityLevel: 'SOFTWARE_TEST', deviceAttestation: {} },
  });
  expect(again.status === 401 || again.status === 409, 'a bootstrap token enrols exactly one key', again.text);
  const silent = await call('POST', '/v1/mobile/sessions', { token: BANK, body: { nexusId: NEXUS_ID } });
  expect(silent.status === 409 && silent.json?.code === 'ACTIVE_CREDENTIAL_EXISTS',
    'no enrolment token for a customer with an enrolled device unless the bank authorizes a replacement', silent.text);
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const fresh = await call('POST', '/v1/mobile/sessions', { token: BANK, body: { nexusId: NEXUS_ID, ...REPLACEMENT } });
  const rsaBootstrap = await call('POST', '/v1/mobile/bootstrap', {
    token: fresh.json.accessToken, body: { publicKeyPem: rsa, authPublicKeyPem: newDeviceKey().publicKeyPem, platform: 'OTHER', securityLevel: 'SOFTWARE_TEST', deviceAttestation: {} },
  });
  expect(rsaBootstrap.status === 400, 'a non-P-256 device key is rejected', rsaBootstrap.text);
}

// --- Authorization + idempotency ---
const beneficiary = { name: 'Jan Kowalski', iban: 'PL61109010140000071219812874' }; // not in sorted order
const idempotencyKey = `e2e-${randomBytes(8).toString('hex')}`;
const authorizationBody = {
  nexusId: NEXUS_ID, credentialId: CREDENTIAL_ID, transactionReference: `TX-${bankCustomerRef}`,
  operationType: 'transfer', amountMinor: '125000', currency: 'PLN', beneficiary,
  policyReference: 'TRANSFER-DEFAULT', policyVersion: '2026-09',
};
const created = await call('POST', '/v1/authorizations', { token: BANK, body: authorizationBody, headers: { 'Idempotency-Key': idempotencyKey } });
const AUTH_ID = created.json?.authorizationId;
expect(created.status === 201 && AUTH_ID, 'transaction authorization created', created.text);

{
  const replay = await call('POST', '/v1/authorizations', { token: BANK, body: authorizationBody, headers: { 'Idempotency-Key': idempotencyKey } });
  expect(replay.status === 200 && replay.json?.authorizationId === AUTH_ID, 'identical retry with the same Idempotency-Key returns the same authorization (200)', replay.text);
  const changed = await call('POST', '/v1/authorizations', { token: BANK, body: { ...authorizationBody, amountMinor: '999999' }, headers: { 'Idempotency-Key': idempotencyKey } });
  expect(changed.status === 409, 'reusing the Idempotency-Key for a different amount is refused (409)', changed.text);
  const badKey = await call('POST', '/v1/authorizations', { token: BANK, body: { ...authorizationBody, transactionReference: `TX2-${bankCustomerRef}`, beneficiary: { 0: 'x' } }, headers: { 'Idempotency-Key': `${idempotencyKey}-b` } });
  expect(badKey.status === 400, 'integer-like beneficiary key is rejected (keeps the signed form reproducible)', badKey.text);
}

// --- Device side: what you see is what you sign ---
const fetched = await call('GET', `/v1/mobile/authorizations/${AUTH_ID}`, { device: MOBILE });
expect(fetched.status === 200 && fetched.json?.canonicalPayloadBase64, 'device fetches the authorization', fetched.text);
{
  const problem = verifySignedPayload(fetched.json);
  expect(problem === null, 'signed bytes are canonical and match every displayed field', problem);
}
const canonical = Buffer.from(fetched.json.canonicalPayloadBase64, 'base64');
{
  const bootstrapOnly = await call('POST', '/v1/mobile/sessions', { token: BANK, body: { nexusId: NEXUS_ID, ...REPLACEMENT } });
  const withBootstrap = await call('GET', `/v1/mobile/authorizations/${AUTH_ID}`, { token: bootstrapOnly.json.accessToken });
  expect(withBootstrap.status === 403, 'a bootstrap token cannot read or sign authorizations', withBootstrap.text);
}

// --- Signature ---
{
  const tamperedBytes = Buffer.from(canonical.toString('utf8').replace('"amount_minor":"125000"', '"amount_minor":"100"'), 'utf8');
  const tampered = await call('POST', `/v1/mobile/authorizations/${AUTH_ID}/signature`, { device: MOBILE, body: { signature: signBytes(device, tamperedBytes), signatureFormat: 'der' } });
  expect(tampered.status === 200 && tampered.json?.status === 'FAILED', 'signature over a modified amount is rejected', tampered.text);

  const plan = await call('GET', `/v1/authorizations/${AUTH_ID}/verification-plan`, { token: BANK });
  expect(plan.status === 200 && plan.json?.status !== 'VERIFIED', 'a rejected signature does not mark the PUSH step as verified', plan.text);

  const valid = await call('POST', `/v1/mobile/authorizations/${AUTH_ID}/signature`, { device: MOBILE, body: { signature: signBytes(device, canonical), signatureFormat: 'der' } });
  expect(valid.status === 200 && valid.json?.status === 'VERIFIED', 'valid device signature verifies', valid.text);

  const replayed = await call('POST', `/v1/mobile/authorizations/${AUTH_ID}/signature`, { device: MOBILE, body: { signature: signBytes(device, canonical), signatureFormat: 'der' } });
  expect(replayed.json?.status !== 'VERIFIED', 'the same signature cannot be used twice', replayed.text);
}

// --- Evidence, verified without trusting Auth Core ---
{
  const evidence = await call('GET', `/v1/authorizations/${AUTH_ID}/evidence`, { token: BANK });
  expect(evidence.status === 200 && evidence.json?.sealedPayload?.canonicalPayloadHash === fetched.json.canonicalPayloadHash,
    'evidence binds the exact signed payload hash', evidence.text);
  const problems = verifyEvidenceRecord(evidence.json, evidence.json.evidencePublicKeys ?? evidence.json.evidencePublicKeyPem, { standalone: true });
  expect(problems.length === 0, 'evidence verifies offline: hash, HSM seal and the device signature over the signed bytes', problems);
  expect(evidence.json?.sealedPayload?.signedPayloadBase64 === fetched.json.canonicalPayloadBase64,
    'evidence carries the exact bytes shown and signed on the device', evidence.text);
}

// --- Bank commit ---
{
  const request = await call('POST', `/v1/authorizations/${AUTH_ID}/bank-commit-request`, { token: BANK, body: { bankTransactionReference: `CORE-${bankCustomerRef}` } });
  expect(request.status === 202, 'bank commit requested', request.text);
  const result = await call('POST', `/v1/authorizations/${AUTH_ID}/bank-commit-result`, { token: BANK, body: { state: 'COMMITTED' } });
  expect(result.status === 200 && result.json?.bankTransactionState === 'COMMITTED', 'bank commit recorded', result.text);
}

// --- Adaptive verification ---
const newAuthorization = async (suffix, verificationPolicy) => {
  const response = await call('POST', '/v1/authorizations', {
    token: BANK,
    body: { ...authorizationBody, transactionReference: `TX${suffix}-${bankCustomerRef}`, ...(verificationPolicy ? { verificationPolicy } : {}) },
    headers: { 'Idempotency-Key': `e2e-${suffix}-${randomBytes(6).toString('hex')}` },
  });
  if (response.status !== 201) fail(`authorization ${suffix} created`, response.text);
  const got = await call('GET', `/v1/mobile/authorizations/${response.json.authorizationId}`, { device: MOBILE });
  return { id: response.json.authorizationId, plan: response.json.verificationPlan, bytes: Buffer.from(got.json.canonicalPayloadBase64, 'base64') };
};
const openSession = (id, channel) => call('POST', `/v1/mobile/authorizations/${id}/verification-sessions`, { device: MOBILE, body: { channel } });
const completeSession = (id, session, result) => call('POST', `/v1/authorizations/${id}/verification-sessions/${session.sessionId}/complete`, {
  token: BANK, body: { sessionNonce: session.nonce, result, providerReference: `prov-${randomBytes(4).toString('hex')}`, assertion: `assertion-${result}` },
});
const signWith = (id, key, bytes) => call('POST', `/v1/mobile/authorizations/${id}/signature`, { device: MOBILE, body: { signature: signBytes(key, bytes), signatureFormat: 'der' } });

{
  const a = await newAuthorization('A', { requireAudio: true });
  expect(a.plan.requiredStep === 'AUDIO' && a.plan.currentStep === 'AUDIO', 'AUDIO policy: plan requires AUDIO', a.plan);
  const early = await signWith(a.id, device, a.bytes);
  expect(early.json?.status === 'FAILED', 'a valid signature is not accepted before the AUDIO check', early.text);
  const session = await openSession(a.id, 'AUDIO');
  expect(session.status === 201 && session.json?.nonce, 'AUDIO verification session opened', session.text);
  const done = await completeSession(a.id, session.json, 'VERIFIED');
  expect(done.status === 200 && done.json?.status === 'VERIFIED', 'provider result recorded, plan VERIFIED', done.text);
  const signed = await signWith(a.id, device, a.bytes);
  expect(signed.json?.status === 'VERIFIED', 'signature accepted after the AUDIO check', signed.text);
  const evidence = await call('GET', `/v1/authorizations/${a.id}/evidence`, { token: BANK });
  expect(evidence.json?.sealedPayload?.verificationFactors?.some((f) => f.channel === 'AUDIO' && f.status === 'VERIFIED'),
    'evidence records the AUDIO factor', evidence.text);
}

{
  const b = await newAuthorization('B');
  const escalated = await call('POST', `/v1/authorizations/${b.id}/verification/escalate`, { token: BANK, body: { reason: 'PUSH_TIMEOUT' } });
  expect(escalated.status === 200 && escalated.json?.requiredStep === 'AUDIO', 'push timeout escalates PUSH → AUDIO', escalated.text);
  const audio = await openSession(b.id, 'AUDIO');
  const failed = await completeSession(b.id, audio.json, 'FAILED');
  expect(failed.json?.requiredStep === 'VIDEO' && failed.json?.currentStep === 'VIDEO', 'a failed AUDIO check escalates to VIDEO, never down', failed.text);
  const downgrade = await call('POST', `/v1/authorizations/${b.id}/verification/escalate`, { token: BANK, body: { reason: 'RISK_POLICY', requestedStep: 'AUDIO' } });
  expect(downgrade.status === 409, 'requesting a weaker step is refused (409)', downgrade.text);
  const video = await openSession(b.id, 'VIDEO');
  const videoFailed = await completeSession(b.id, video.json, 'FAILED');
  expect(videoFailed.json?.status === 'FAILED', 'a failed VIDEO check fails the plan', videoFailed.text);
  const auth = await call('GET', `/v1/authorizations/${b.id}`, { token: BANK });
  expect(auth.json?.state === 'REJECTED', 'and rejects the authorization', auth.text);
  const late = await signWith(b.id, device, b.bytes);
  expect(late.json?.status === 'FAILED', 'a rejected authorization cannot be signed', late.text);
}

{
  const c = await newAuthorization('C');
  const client = await call('POST', `/v1/mobile/authorizations/${c.id}/verification/escalate`, { device: MOBILE });
  expect(client.status === 200 && client.json?.requiredStep === 'AUDIO', 'the customer can request a stronger check from the device', client.text);
}

{
  const key = `e2e-video-${randomBytes(8).toString('hex')}`;
  const body = { ...authorizationBody, transactionReference: `TXV-${bankCustomerRef}`, verificationPolicy: { requireVideo: true } };
  const first = await call('POST', '/v1/authorizations', { token: BANK, body, headers: { 'Idempotency-Key': key } });
  const weaker = await call('POST', '/v1/authorizations', { token: BANK, body: { ...body, verificationPolicy: {} }, headers: { 'Idempotency-Key': key } });
  expect(first.status === 201 && weaker.json?.verificationPlan?.requiredStep === 'VIDEO', 'a retry with a weaker policy keeps VIDEO verification', weaker.text);
}

// --- Offline confirmation ---
if (OFFLINE_SERVER_KEY) {
  const auth = await call('POST', '/v1/authorizations', {
    token: BANK,
    body: { ...authorizationBody, transactionReference: `TXF-${bankCustomerRef}` },
    headers: { 'Idempotency-Key': `e2e-off-${randomBytes(6).toString('hex')}` },
  });
  expect(auth.status === 201, 'authorization created for offline confirmation', auth.text);
  const id = auth.json.authorizationId;
  const challenge = await call('GET', `/v1/authorizations/${id}/offline-challenge`, { token: BANK });
  expect(challenge.status === 200 && challenge.json?.qrPayload?.startsWith('NXS1.'), 'bank gets the QR content for its screen', challenge.text);

  // The phone, without network: read the QR, check the bytes, derive the code.
  const canonical = Buffer.from(challenge.json.qrPayload.slice(5), 'base64url');
  const fields = JSON.parse(canonical.toString('utf8'));
  expect(Buffer.from(JSON.stringify(normalize(fields))).equals(canonical) && fields.credential_id === CREDENTIAL_ID && fields.amount_minor === '125000',
    'QR carries the canonical bytes for this device and amount', fields);
  const code = offlineCode(deviceOfflineKey, OFFLINE_SERVER_KEY, CREDENTIAL_ID, canonical);

  const wrongCode = String((Number(code) + 1) % 100000000).padStart(8, '0');
  const wrong = await call('POST', `/v1/authorizations/${id}/offline-confirmation`, { token: BANK, body: { code: wrongCode } });
  expect(wrong.json?.status === 'FAILED' && wrong.json?.attempts === 1, 'a wrong offline code is refused and counted', wrong.text);
  const right = await call('POST', `/v1/authorizations/${id}/offline-confirmation`, { token: BANK, body: { code } });
  expect(right.json?.status === 'VERIFIED', 'the code derived on the phone confirms the authorization', right.text);
  const again = await call('POST', `/v1/authorizations/${id}/offline-confirmation`, { token: BANK, body: { code } });
  expect(again.json?.status === 'FAILED', 'an offline code is single-use', again.text);

  const evidence = await call('GET', `/v1/authorizations/${id}/evidence`, { token: BANK });
  expect(evidence.json?.sealedPayload?.confirmationMethod === 'OFFLINE_CODE'
    && verifyEvidenceRecord(evidence.json, evidence.json.evidencePublicKeys ?? evidence.json.evidencePublicKeyPem, { standalone: true }).length === 0,
    'offline confirmation is sealed in the evidence chain as OFFLINE_CODE', evidence.text);
} else {
  console.log('SKIP  offline confirmation (OFFLINE_CONFIRMATION_ENABLED is not true on the server)');
}

// --- Recovery (protocol 2) ---
const phrase = 'legal winner thank year wave sausage worth useful legal winner thank yellow'.split(' ');

{
  const params = await call('GET', '/v1/mobile/recovery/setup', { device: MOBILE });
  expect(params.status === 200 && params.json?.protocol === 2 && params.json?.credentialId === CREDENTIAL_ID, 'recovery parameters issued to the enrolled device', params.text);
  const p = params.json;
  const key = createRecoveryKey(phrase, p.salt, p.iterations, p.nexusId);
  // Signed with the biometric signing key on a real device.
  const signature = signDerB64(device.privateKey, setupSigningInput({ nexusId: p.nexusId, credentialId: p.credentialId, saltB64: p.salt, recoveryPublicKey: key.publicKey, wrapped: key.wrapped }));
  const setup = await call('POST', '/v1/mobile/recovery/setup', {
    device: MOBILE, body: { protocol: 2, salt: p.salt, recoveryPublicKeyPem: key.publicKeyPem, wrappedRecoveryKey: key.wrapped.toString('base64'), signature },
  });
  expect(setup.status === 204, 'recovery key registered, wrapped under the phrase (the phrase never leaves the device)', setup.text);
}

const startRecovery = async () => {
  const session = await call('POST', '/v1/recovery/sessions', { token: BANK, body: { bankCustomerRef } });
  if (session.status !== 201) fail('recovery session created', session.text);
  return session.json;
};
/** The SDK's recoverIdentity(): opens the wrapped key with the phrase and
 * signs a proof bound to the session and the new signing key. */
const completeRecovery = (s, key, authKey = newDeviceKey(), { recoveryKey } = {}) => {
  const proof = signDerB64(recoveryKey ?? openRecoveryKey(phrase, s), proofSigningInput({ sessionId: s.sessionId, nonceB64: s.nonce, nexusId: s.nexusId, newSigningPublicKey: key.publicKey }));
  return call('POST', `/v1/recovery/sessions/${s.sessionId}/complete`, {
    token: s.accessToken,
    body: { proof, newPublicKeyPem: key.publicKeyPem, authPublicKeyPem: authKey.publicKeyPem, platform: 'OTHER', securityLevel: 'SOFTWARE_TEST', deviceAttestation: {} },
  });
};

{
  // Five proofs by a key other than the registered recovery key lock the session.
  const s = await startRecovery();
  for (let i = 1; i <= 5; i += 1) {
    const attempt = await completeRecovery(s, newDeviceKey(), undefined, { recoveryKey: newDeviceKey().privateKey });
    if (attempt.status !== 401) fail(`wrong recovery proof #${i} is rejected with 401`, attempt.text);
  }
  pass('five wrong recovery proofs are rejected');
  const afterLimit = await completeRecovery(s, newDeviceKey());
  expect(afterLimit.status === 404, 'after 5 failures the session is locked, even for the correct phrase', afterLimit.text);
}

const recoveredDevice = newDeviceKey();
const recoveredAuthKey = newDeviceKey();
let NEW_CREDENTIAL_ID;
{
  const s = await startRecovery();
  const recovered = await completeRecovery(s, recoveredDevice, recoveredAuthKey);
  NEW_CREDENTIAL_ID = recovered.json?.credentialId;
  expect(recovered.status === 200 && NEW_CREDENTIAL_ID && NEW_CREDENTIAL_ID !== CREDENTIAL_ID && recovered.json?.requestAuthentication === 'DEVICE_SIGNATURE',
    'recovery with the correct phrase rotates the credential and its authentication key', recovered.text);

  const reuse = await completeRecovery(s, newDeviceKey());
  expect(reuse.status === 404, 'a recovery session is single-use', reuse.text);

  const oldCredential = await call('GET', `/v1/credentials/${CREDENTIAL_ID}`, { token: BANK });
  expect(oldCredential.json?.state === 'REVOKED', 'the previous device credential is revoked', oldCredential.text);
  const oldDevice = await call('GET', '/v1/mobile/recovery/setup', { device: MOBILE });
  expect(oldDevice.status === 401, 'the old device authentication key stops working after recovery', oldDevice.text);
  const newDevice = await call('GET', '/v1/mobile/recovery/setup', { device: { credentialId: NEW_CREDENTIAL_ID, authKey: recoveredAuthKey } });
  expect(newDevice.status === 200, 'the recovered device signs its own requests with its new authentication key', newDevice.text);
}

{
  const staleAuth = await call('POST', '/v1/authorizations', { token: BANK, body: { ...authorizationBody, transactionReference: `TXO-${bankCustomerRef}` }, headers: { 'Idempotency-Key': `e2e-old-${randomBytes(6).toString('hex')}` } });
  expect(staleAuth.status === 409, 'authorizations can no longer be bound to the revoked credential (409)', staleAuth.text);

  const RECOVERED = { credentialId: NEW_CREDENTIAL_ID, authKey: recoveredAuthKey };
  const auth = await call('POST', '/v1/authorizations', { token: BANK, body: { ...authorizationBody, credentialId: NEW_CREDENTIAL_ID, transactionReference: `TXN-${bankCustomerRef}` }, headers: { 'Idempotency-Key': `e2e-new-${randomBytes(6).toString('hex')}` } });
  expect(auth.status === 201, 'authorization created for the recovered credential', auth.text);
  const got = await call('GET', `/v1/mobile/authorizations/${auth.json.authorizationId}`, { device: RECOVERED });
  const bytes = Buffer.from(got.json.canonicalPayloadBase64, 'base64');
  const withOldKey = await call('POST', `/v1/mobile/authorizations/${auth.json.authorizationId}/signature`, { device: RECOVERED, body: { signature: signBytes(device, bytes), signatureFormat: 'der' } });
  expect(withOldKey.json?.status === 'FAILED', 'the old device key can no longer sign', withOldKey.text);
  const withNewKey = await call('POST', `/v1/mobile/authorizations/${auth.json.authorizationId}/signature`, { device: RECOVERED, body: { signature: signBytes(recoveredDevice, bytes), signatureFormat: 'der' } });
  expect(withNewKey.json?.status === 'VERIFIED', 'the recovered device key signs successfully', withNewKey.text);

  const chain = await call('GET', `/v1/nexus-identities/${NEXUS_ID}/evidence`, { token: BANK });
  const problems = verifyEvidenceChain(chain.json?.records ?? [], chain.json?.evidencePublicKeys ?? chain.json?.evidencePublicKeyPem,
    chain.json?.head ? { expectedHead: chain.json.head } : {});
  expect(chain.status === 200 && chain.json.records.length >= 3 && problems.length === 0,
    `the NEXUS ID evidence chain (${chain.json?.records?.length} records) is linked and every seal verifies`, problems);
}

console.log(`\nALL ${passed} END-TO-END CHECKS PASSED`);
