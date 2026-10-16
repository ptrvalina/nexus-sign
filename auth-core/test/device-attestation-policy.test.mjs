import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './support/load-ts.mjs';

// Play Integrity and the chain verifier are stubbed: these tests cover the
// decision made from their results (androidKeyAttestation.test.mjs covers
// the chain verification itself with real device chains).
function service({ policy = 'REQUIRE_HARDWARE_BACKED', levels = {}, statusFile, loadStatus } = {}) {
  class AndroidKeyAttestationError extends Error {}
  return loadTs('services/attestationVerificationService.ts', {
    stubs: {
      '../config/env': { env: { NODE_ENV: 'test', ANDROID_REQUIRED_DEVICE_VERDICT: 'MEETS_DEVICE_INTEGRITY', ANDROID_KEY_SECURITY_POLICY: policy, ANDROID_REQUIRE_LOCKED_BOOTLOADER: true, ANDROID_APP_CERT_SHA256: [], ANDROID_PACKAGE_NAME: 'com.bank.app', ANDROID_ATTESTATION_STATUS_FILE: statusFile } },
      './playIntegrityService': { verifyPlayIntegrityToken: async () => ({ appRecognized: true, deviceIntegrityVerdicts: ['MEETS_DEVICE_INTEGRITY'] }), PlayIntegrityNotConfiguredError: class extends Error {} },
      './appAttestService': { verifyAppAttestAttestation: async () => ({ environment: 'production' }), AppAttestNotConfiguredError: class extends Error {} },
      './androidKeyAttestation': {
        AndroidKeyAttestationError,
        keyAttestationChallenge: (c) => c,
        loadRevocationList: loadStatus ?? (() => ({ entries: new Map(), modifiedAt: null })),
        verifyAndroidKeyAttestation: ({ publicKeyPem }) => {
          const level = levels[publicKeyPem];
          if (!level) throw new AndroidKeyAttestationError('chain does not verify');
          return { securityLevel: level };
        },
      },
    },
  });
}

const keys = { challenge: Buffer.from('challenge'), signingPublicKeyPem: 'signing', authPublicKeyPem: 'auth' };
const android = (keyAttestation) => ({ integrityToken: 'token', keyAttestation });

test('Android enrolment without Keystore attestation chains is refused', async () => {
  const { verifyDeviceAttestation } = service({ levels: { signing: 'TEE', auth: 'TEE' } });
  const noChains = await verifyDeviceAttestation(android(undefined), Buffer.from('b'), keys);
  assert.equal(noChains.verified, false);
  assert.match(noChains.reason, /signing key has no Keystore attestation/);
  const noAuthChain = await verifyDeviceAttestation(android({ signingKeyChain: ['x'] }), Buffer.from('b'), keys);
  assert.equal(noAuthChain.verified, false);
});

test('the security level is the weaker key of the two, taken from the attestation', async () => {
  const { verifyDeviceAttestation } = service({ levels: { signing: 'STRONGBOX', auth: 'TEE' } });
  const verdict = await verifyDeviceAttestation(android({ signingKeyChain: ['x'], authenticationKeyChain: ['y'] }), Buffer.from('b'), keys);
  assert.equal(verdict.verified, true);
  assert.equal(verdict.securityLevel, 'TEE');
});

test('a chain that fails verification fails the enrolment', async () => {
  const { verifyDeviceAttestation } = service({ levels: { signing: 'TEE' } });
  const verdict = await verifyDeviceAttestation(android({ signingKeyChain: ['x'], authenticationKeyChain: ['y'] }), Buffer.from('b'), keys);
  assert.equal(verdict.verified, false);
  assert.match(verdict.reason, /key attestation/);
});

test('evidence from one platform cannot enrol a credential claimed for the other', () => {
  const { platformMatches } = service();
  assert.equal(platformMatches({ platform: 'android' }, 'IOS'), false);
  assert.equal(platformMatches({ platform: 'ios' }, 'IOS'), true);
});

test('iOS attestation reports the Secure Enclave', async () => {
  const { verifyDeviceAttestation } = service();
  const verdict = await verifyDeviceAttestation({ attestationObject: 'o', keyId: 'k' }, Buffer.from('b'), keys);
  assert.equal(verdict.securityLevel, 'SECURE_ENCLAVE');
});

test('a missing or unreadable attestation status list refuses the enrolment cleanly', async () => {
  const { verifyDeviceAttestation } = service({
    levels: { signing: 'TEE', auth: 'TEE' }, statusFile: '/nonexistent/status.json',
    loadStatus: () => { throw new Error("ENOENT: no such file or directory, open '/nonexistent/status.json'"); },
  });
  const verdict = await verifyDeviceAttestation(android({ signingKeyChain: ['x'], authenticationKeyChain: ['y'] }), Buffer.from('b'), keys);
  assert.equal(verdict.verified, false);
  assert.match(verdict.reason, /status list is unavailable/);
});
