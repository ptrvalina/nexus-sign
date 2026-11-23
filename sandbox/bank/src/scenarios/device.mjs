// Software test device for demonstration scenarios (TEST-ONLY).
//
// It is the simulated device of Auth Core's own integration tests
// (auth-core/test/integration/support/actors.mjs, imported unchanged): keys
// from node:crypto, request signing exactly as in the SDKs. It talks to Auth
// Core through the bank's device port, like a phone. It is used only for the
// scenario customer (device kind SOFTWARE_TEST_DEVICE) and is shown as such in
// the console; real customers use the iOS and Android apps with keys in the
// Secure Enclave or Android Keystore.
//
// Its keys are sandbox test keys, kept in SANDBOX_DATA_DIR so the scenario
// customer stays enrolled across restarts of the sandbox bank.
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import * as actors from '../../../../auth-core/test/integration/support/actors.mjs';

const keyFromPem = (pem) => {
  const privateKey = createPrivateKey(pem);
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
};
const pemOf = (key) => key.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

export function createSoftwareDevice({ dataDir, deviceBaseUrl }) {
  const file = join(dataDir, 'scenario-test-device.json');
  const server = { baseUrl: deviceBaseUrl };
  let device = null;

  function load() {
    if (device || !existsSync(file)) return device;
    const saved = JSON.parse(readFileSync(file, 'utf8'));
    device = {
      nexusId: saved.nexusId, credentialId: saved.credentialId, offlineServerPublicKeyPem: saved.offlineServerPublicKeyPem,
      signingKey: keyFromPem(saved.signingKey), authKey: keyFromPem(saved.authKey), offlineKey: keyFromPem(saved.offlineKey),
    };
    return device;
  }

  function save(d) {
    writeFileSync(file, JSON.stringify({
      note: 'Sandbox software test device: test keys only, never used outside the sandbox.',
      nexusId: d.nexusId, credentialId: d.credentialId, offlineServerPublicKeyPem: d.offlineServerPublicKeyPem,
      signingKey: pemOf(d.signingKey), authKey: pemOf(d.authKey), offlineKey: pemOf(d.offlineKey),
    }), { mode: 0o600 });
    chmodSync(file, 0o600);
  }

  return {
    current: load,
    async enrol(nexusId, bootstrapToken) {
      // Declared honestly: platform OTHER, a software key. No hardware claim.
      const declared = { platform: 'OTHER', securityLevel: 'SOFTWARE_TEST_KEY', deviceAttestation: { supported: false } };
      const d = await actors.enrolWithToken(server, nexusId, bootstrapToken, { extraBody: { ...declared, offlineKeyAgreement: 'PER_AUTHORIZATION' } });
      device = d;
      save(d);
      return d;
    },
    /** Fetches the authorization with its signed bytes (as the SDK does). */
    fetch: (authorizationId) => actors.call(server.baseUrl, 'GET', `/v1/mobile/authorizations/${authorizationId}`, { device: load() }),
    async approve(authorizationId) {
      const { signature } = await actors.deviceSignature(server, load(), authorizationId);
      return actors.submitSignature(server, load(), authorizationId, signature);
    },
    /** Signs with a key Auth Core does not know: must be refused. */
    async signWithForeignKey(authorizationId) {
      const { canonical } = await actors.deviceSignature(server, load(), authorizationId);
      return actors.submitSignature(server, load(), authorizationId, actors.signDer(actors.newKey(), canonical));
    },
    /** Signs bytes whose amount was changed: must be refused. */
    async signAlteredTerms(authorizationId) {
      const { canonical } = await actors.deviceSignature(server, load(), authorizationId);
      const terms = JSON.parse(canonical.toString('utf8'));
      terms.amount_minor = String(Number(terms.amount_minor) * 10);
      return actors.submitSignature(server, load(), authorizationId, actors.signDer(load().signingKey, Buffer.from(JSON.stringify(terms), 'utf8')));
    },
    decline: (authorizationId, reason = 'NOT_ME') => actors.call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${authorizationId}/decline`, { device: load(), body: { reason } }),
    /** Offline code from the QR content, without network (offline v3, or v2 for a STATIC agreement). */
    offlineCode(qrPayload) {
      if (qrPayload.startsWith('NXS3.')) return actors.offlineCodeV3(load(), qrPayload);
      const canonical = Buffer.from(qrPayload.split('.')[1], 'base64url');
      return { code: actors.offlineCode(load(), canonical), canonical };
    },
    uploadDeferredSignature(authorizationId, canonical) {
      return actors.call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${authorizationId}/deferred-signature`, {
        device: load(), body: { signature: actors.signDer(load().signingKey, canonical), signatureFormat: 'der' },
      });
    },
  };
}
