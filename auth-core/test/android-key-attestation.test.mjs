import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import { loadTs } from './support/load-ts.mjs';

const { verifyAndroidKeyAttestation, keyAttestationChallenge, loadRevocationList } = loadTs('services/androidKeyAttestation.ts');
const fixture = (name) => new URL(`./fixtures/android-key-attestation/${name}`, import.meta.url);

function sample(name) {
  const certs = readFileSync(fixture(`${name}.pem`), 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  const expected = JSON.parse(readFileSync(fixture(`${name}.expected.json`), 'utf8'));
  const leaf = new X509Certificate(certs[0]);
  return {
    chain: certs.map((c) => new X509Certificate(c).raw.toString('base64')),
    expectation: {
      chain: certs.map((c) => new X509Certificate(c).raw.toString('base64')),
      challenge: Buffer.from(expected.attestationChallenge, 'base64'),
      publicKeyPem: leaf.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      packageName: 'com.google.android.attestation',
      signingCertificateDigests: [Buffer.from(expected.softwareEnforced.attestationApplicationId.signatures[0], 'base64')],
      policy: 'REQUIRE_HARDWARE_BACKED',
      requireLockedBootloader: true,
      requireUserAuthentication: false,
      revocations: new Map(),
      at: new Date(Number(expected.softwareEnforced.creationDateTime)),
    },
  };
}

const TEE = 'frankel_sdk37_TEE_EC_2026';
const STRONGBOX = 'tegu_sdk36_SB_EC_2026_ROOT';
const RKP = 'caiman_sdk36_TEE_EC_RKP';

test('real device chains verify and report their security level', () => {
  assert.equal(verifyAndroidKeyAttestation(sample(TEE).expectation).securityLevel, 'TEE');
  assert.equal(verifyAndroidKeyAttestation(sample(STRONGBOX).expectation).securityLevel, 'STRONGBOX');
  const rkp = verifyAndroidKeyAttestation(sample(RKP).expectation);
  assert.equal(rkp.securityLevel, 'TEE');
  assert.equal(rkp.verifiedBootState, 'VERIFIED');
  assert.equal(rkp.deviceLocked, true);
});

test('the StrongBox policy refuses a TEE key and accepts a StrongBox key', () => {
  assert.throws(() => verifyAndroidKeyAttestation({ ...sample(TEE).expectation, policy: 'REQUIRE_STRONGBOX' }), /StrongBox is required/);
  assert.equal(verifyAndroidKeyAttestation({ ...sample(STRONGBOX).expectation, policy: 'REQUIRE_STRONGBOX' }).securityLevel, 'STRONGBOX');
});

test('ALLOW_TEE accepts TEE and StrongBox keys, like REQUIRE_HARDWARE_BACKED', () => {
  for (const name of [TEE, STRONGBOX, RKP]) {
    const policy = 'ALLOW_TEE';
    assert.equal(verifyAndroidKeyAttestation({ ...sample(name).expectation, policy }).securityLevel,
      verifyAndroidKeyAttestation(sample(name).expectation).securityLevel, name);
  }
});

test('a chain is refused when it does not attest this enrolment', () => {
  const { expectation } = sample(TEE);
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const cases = [
    [{ challenge: Buffer.from('another challenge') }, /challenge/],
    [{ publicKeyPem: other }, /not the enrolled key/],
    [{ packageName: 'com.bank.app' }, /another application/],
    [{ signingCertificateDigests: [Buffer.alloc(32, 1)] }, /accepted certificate/],
    [{ requireUserAuthentication: true }, /without biometric/],
  ];
  for (const [override, message] of cases) assert.throws(() => verifyAndroidKeyAttestation({ ...expectation, ...override }), message);
});

test('a broken, foreign, expired or revoked chain is refused', () => {
  const tee = sample(TEE).expectation;
  const strongbox = sample(STRONGBOX).expectation;
  const rkp = sample(RKP).expectation;
  assert.throws(() => verifyAndroidKeyAttestation({ ...tee, chain: [strongbox.chain[0], ...tee.chain.slice(1)] }), /not signed by the next/);
  assert.throws(() => verifyAndroidKeyAttestation({ ...tee, chain: tee.chain.slice(0, -1) }), /Google attestation root/);
  assert.throws(() => verifyAndroidKeyAttestation({ ...rkp, at: new Date('2030-01-01T00:00:00Z') }), /validity/);
  const intermediateSerial = BigInt(`0x${new X509Certificate(Buffer.from(tee.chain[1], 'base64')).serialNumber}`).toString(16);
  assert.throws(() => verifyAndroidKeyAttestation({ ...tee, revocations: new Map([[intermediateSerial, 'REVOKED']]) }), /REVOKED/);
});

test('the revocation list is read in Google status list format', () => {
  const { entries } = loadRevocationList(new URL('./fixtures/android-key-attestation/status-example.json', import.meta.url).pathname);
  assert.equal(entries.get('a1b2c3d4e5f60718293a4b5c6d7e8f9'), 'SUSPENDED', 'leading zeros are removed');
  assert.throws(() => verifyAndroidKeyAttestation({ ...sample(TEE).expectation, revocations: entries }), /REVOKED/);
});

test('the key attestation challenge is bound to the enrolment challenge', () => {
  const a = keyAttestationChallenge(Buffer.from('enrolment-a'));
  assert.equal(a.length, 32);
  assert.notDeepEqual(a, keyAttestationChallenge(Buffer.from('enrolment-b')));
});

test('the key attestation challenge matches the shared device protocol vector', () => {
  const vectors = JSON.parse(readFileSync(new URL('../test-vectors/device-protocols-v1.json', import.meta.url), 'utf8')).key_attestation;
  assert.equal(keyAttestationChallenge(Buffer.from(vectors.enrolment_challenge_hex, 'hex')).toString('hex'), vectors.key_attestation_challenge_hex);
});

// Red-team RT-11: the chain must be a valid certification path, not only a
// sequence of signatures. A genuine attestation leaf's key can be used by the
// device owner to sign a forged leaf claiming any KeyDescription.
test('only CA certificates allowed to sign certificates may issue in the chain (RT-11)', () => {
  const synthetic = JSON.parse(readFileSync(fixture('synthetic-path-chains.json'), 'utf8'));
  const expectation = (chain) => ({
    chain,
    challenge: Buffer.alloc(32, 7),
    publicKeyPem: new X509Certificate(Buffer.from(chain[0], 'base64')).publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    packageName: 'com.bank.app',
    signingCertificateDigests: [Buffer.alloc(32, 0xab)],
    policy: 'REQUIRE_STRONGBOX',
    requireLockedBootloader: true,
    requireUserAuthentication: true,
    revocations: new Map(),
    roots: [synthetic.root],
  });
  // The control chain passes the path checks, so the refusals below are due to them.
  assert.equal(verifyAndroidKeyAttestation(expectation(synthetic.chains.well_formed_control)).securityLevel, 'STRONGBOX');
  assert.throws(() => verifyAndroidKeyAttestation(expectation(synthetic.chains.attested_key_as_issuer)), /is not a CA/);
  assert.throws(() => verifyAndroidKeyAttestation(expectation(synthetic.chains.issuer_without_keyCertSign)), /not allowed to sign certificates/);
  assert.throws(() => verifyAndroidKeyAttestation(expectation(synthetic.chains.path_length_exceeded)), /path length/);
});
