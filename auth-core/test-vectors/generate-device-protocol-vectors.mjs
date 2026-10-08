// Generates the shared vectors for device protocols v1:
//
//  - device request signing: the exact bytes a device signs for a request,
//    plus one sample signature made with a fixed key;
//  - offline confirmation: ECDH shared secret, derived key, HMAC tag and the
//    8-digit code for a fixed pair of keys and a canonical payload.
//
// Written independently of src/services/deviceProtocol.ts; Auth Core
// (test/device-protocol.test.mjs) and both SDKs reproduce every value.
// ECDSA signatures are randomized, so an existing sample signature is kept as
// long as it still verifies for the same input; re-running is then a no-op.
//
// Usage: node test-vectors/generate-device-protocol-vectors.mjs
import { createECDH, createHash, createHmac, createPrivateKey, hkdfSync, sign, verify } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { writeVectors } from './vector-files.mjs';

const here = dirname(new URL(import.meta.url).pathname);

/** A P-256 key pair from a fixed private scalar, so the vectors are stable. */
function fixedKey(dHex) {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(dHex, 'hex'));
  const point = ecdh.getPublicKey();
  const privateKey = createPrivateKey({
    format: 'jwk',
    key: {
      kty: 'EC', crv: 'P-256',
      d: Buffer.from(dHex, 'hex').toString('base64url'),
      x: point.subarray(1, 33).toString('base64url'),
      y: point.subarray(33).toString('base64url'),
    },
  });
  return { privateScalarHex: dHex, privateKey, ecdh, publicKeyPem: publicPem(point) };
}

/** SubjectPublicKeyInfo PEM of an uncompressed P-256 point. */
function publicPem(point) {
  const prefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  const body = Buffer.concat([prefix, point]).toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;
}

const sha256 = (b) => createHash('sha256').update(b).digest();

// --- Device request signing ---

const authKey = fixedKey('4b1e0e8a2f8d6c3b9a7e5d4c3b2a19087f6e5d4c3b2a190807f6e5d4c3b2a191');
const credentialId = '00000000-0000-4000-8000-000000000002';

function requestInput(r) {
  return [
    'NEXUS-SIGN/DEVICE-REQUEST/v1',
    r.method.toUpperCase(),
    r.path,
    r.timestamp,
    r.nonce,
    r.credential_id,
    sha256(Buffer.from(r.body, 'utf8')).toString('hex'),
  ].join('\n');
}

const requests = [
  { name: 'GET without body', method: 'GET', path: '/v1/mobile/authorizations/00000000-0000-4000-8000-000000000001',
    timestamp: '1790000000', nonce: 'qD5lW7mN0pR2tV4xZ6bC8e', credential_id: credentialId, body: '' },
  { name: 'POST signature', method: 'POST', path: '/v1/mobile/authorizations/00000000-0000-4000-8000-000000000001/signature',
    timestamp: '1790000030', nonce: 'Hk3Jm5Np7Qr9St1Uv3Wx5Y', credential_id: credentialId,
    body: '{"signature":"MEUCIQ==","signatureFormat":"der"}' },
  { name: 'path with query', method: 'get', path: '/v1/mobile/recovery/setup?probe=1',
    timestamp: '1790000060', nonce: 'aaaaaaaaaaaaaaaaaaaaaa', credential_id: credentialId, body: '' },
  { name: 'gateway prefix and percent-encoding, signed exactly as sent', method: 'GET',
    path: '/nexus-sign/v1/mobile/authorizations/a%20b?x=a%2Fb', timestamp: '1790000090', nonce: 'Zz-_0123456789abcdefgh',
    credential_id: credentialId, body: '' },
];

const previous = existsSync(join(here, 'device-protocols-v1.json'))
  ? JSON.parse(readFileSync(join(here, 'device-protocols-v1.json'), 'utf8')).device_request?.requests ?? []
  : [];
const signedRequests = requests.map((r) => {
  const input = Buffer.from(requestInput(r), 'utf8');
  const kept = previous.find((p) => p.name === r.name)?.sample_signature_der_base64;
  const keep = kept && verify('sha256', input, { key: authKey.publicKeyPem, dsaEncoding: 'der' }, Buffer.from(kept, 'base64'));
  return {
    ...r,
    signing_input_base64: input.toString('base64'),
    sample_signature_der_base64: keep ? kept : sign('sha256', input, { key: authKey.privateKey, dsaEncoding: 'der' }).toString('base64'),
  };
});

// --- Offline confirmation ---

const deviceOffline = fixedKey('1f2e3d4c5b6a79881726354453627180918273645546372819aabbccddeeff00');
const serverOffline = fixedKey('00ffeeddccbbaa99887766554433221100112233445566778899aabbccddeeff');
const shared = deviceOffline.ecdh.computeSecret(serverOffline.ecdh.getPublicKey());
if (!shared.equals(serverOffline.ecdh.computeSecret(deviceOffline.ecdh.getPublicKey()))) throw new Error('ECDH mismatch');
const offlineKey = Buffer.from(hkdfSync('sha256', shared, Buffer.from('NEXUS-SIGN/OFFLINE/v1'), Buffer.from(credentialId), 32));

function code(tag) {
  const offset = tag[31] & 0x0f;
  const bin = ((tag[offset] & 0x7f) << 24) | (tag[offset + 1] << 16) | (tag[offset + 2] << 8) | tag[offset + 3];
  return String(bin % 100000000).padStart(8, '0');
}

const payloadVectors = JSON.parse(readFileSync(join(here, 'signed-payload-v1.json'), 'utf8')).valid.slice(0, 2);
const offline = payloadVectors.map((v) => {
  const canonical = Buffer.from(v.canonical_base64, 'base64');
  const tag = createHmac('sha256', offlineKey)
    .update(Buffer.concat([Buffer.from('NEXUS-SIGN/OFFLINE-CODE/v1'), Buffer.from([0]), sha256(canonical)]))
    .digest();
  return {
    name: v.name,
    canonical_base64: v.canonical_base64,
    qr_payload: `NXS1.${canonical.toString('base64url')}`,
    tag_base64: tag.toString('base64'),
    code: code(tag),
  };
});

const vectors = {
  description: 'Device protocols v1 vectors. Generated by generate-device-protocol-vectors.mjs - do not edit by hand.',
  device_request: {
    auth_public_key_pem: authKey.publicKeyPem,
    requests: signedRequests,
  },
  offline: {
    credential_id: credentialId,
    device_private_scalar_hex: deviceOffline.privateScalarHex,
    device_public_key_pem: deviceOffline.publicKeyPem,
    server_private_scalar_hex: serverOffline.privateScalarHex,
    server_public_key_pem: serverOffline.publicKeyPem,
    shared_secret_hex: shared.toString('hex'),
    offline_key_hex: offlineKey.toString('hex'),
    confirmations: offline,
  },
  // Keystore attestation challenge of each key an Android device enrols
  // (androidKeyAttestation.ts, AttestationProvider.keyAttestationChallenge).
  key_attestation: {
    bootstrap_token: 'ms_example-bootstrap-token',
    enrolment_challenge_hex: createHash('sha256').update('ms_example-bootstrap-token', 'utf8').digest('hex'),
    key_attestation_challenge_hex: createHash('sha256').update(Buffer.concat([
      Buffer.from('NEXUS-SIGN/KEY-ATTESTATION/v1', 'utf8'), Buffer.from([0]),
      createHash('sha256').update('ms_example-bootstrap-token', 'utf8').digest(),
    ])).digest('hex'),
  },
};

writeVectors('device-protocols-v1.json', `${JSON.stringify(vectors, null, 2)}\n`);
console.log(`wrote device protocol vectors (requests=${signedRequests.length}, offline=${offline.length})`);
