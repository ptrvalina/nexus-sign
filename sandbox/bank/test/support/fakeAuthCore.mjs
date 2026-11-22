// TEST-ONLY stand-in for the Auth Core client, for the bank's unit tests.
// Evidence comes from Auth Core's own test fixture
// (auth-core/test/integration/support/syntheticEvidence.mjs): software keys,
// not Auth Core output. The end-to-end tests run the real Auth Core
// (sandbox/tests/e2e.test.mjs). Never imported by the bank's source.
import { randomUUID } from 'node:crypto';
import { evidenceMaker } from '../../../../auth-core/test/integration/support/syntheticEvidence.mjs';

export function fakeAuthCore() {
  const maker = evidenceMaker();
  const identities = new Map(); // nexusId → device
  const authorizations = new Map();
  const ok = (status, json) => ({ status, json, text: JSON.stringify(json) });
  const fake = {
    maker,
    calls: [],
    health: async () => ({ ok: true, status: 200 }),
    async createIdentity() {
      const nexusId = String(100000000 + identities.size + 1);
      identities.set(nexusId, maker.device(nexusId));
      return ok(201, { nexusId });
    },
    async bootstrapToken() { return ok(201, { accessToken: 'bootstrap' }); },
    async devices(nexusId) {
      const d = identities.get(nexusId);
      return ok(200, { devices: d ? [{ credentialId: d.credentialId, platform: 'OTHER', securityLevel: 'SOFTWARE_TEST_KEY', attestationStatus: 'UNKNOWN', state: 'ACTIVE' }] : [] });
    },
    deviceOf: (nexusId) => identities.get(nexusId),
    /** Next authorization's evidence will carry these changes to the signed terms. */
    alterNextSignedTerms: null,
    async createAuthorization(body) {
      fake.calls.push(['createAuthorization', body]);
      const authorizationId = randomUUID();
      const device = identities.get(body.nexusId);
      const record = maker.confirm(device, {
        authorizationId,
        terms: { transactionReference: body.transactionReference, operationType: body.operationType, amountMinor: body.amountMinor, currency: body.currency, beneficiary: body.beneficiary },
        signedOverride: fake.alterNextSignedTerms ?? {},
      });
      fake.alterNextSignedTerms = null;
      const a = { authorizationId, state: 'PENDING_USER', confirmed: false, expiresAt: new Date(Date.now() + 120_000).toISOString(), record: { ...record, evidencePublicKeys: maker.evidenceKeys } };
      authorizations.set(authorizationId, a);
      return ok(201, { authorizationId, canonicalPayloadHash: record.sealedPayload.canonicalPayloadHash, expiresAt: a.expiresAt });
    },
    /** Test control: what the customer did on the device. */
    setState(authorizationId, state, extra = {}) { Object.assign(authorizations.get(authorizationId), { state, ...extra }); },
    confirm(authorizationId) { fake.setState(authorizationId, 'VERIFIED', { confirmed: true, confirmationMethod: 'DEVICE_SIGNATURE', verifiedAt: new Date().toISOString() }); },
    async authorization(id) {
      const a = authorizations.get(id);
      return a ? ok(200, { authorizationId: id, state: a.state, confirmed: a.confirmed, confirmationMethod: a.confirmationMethod ?? null, expiresAt: a.expiresAt, verifiedAt: a.verifiedAt ?? null }) : ok(404, { code: 'NOT_FOUND' });
    },
    async evidence(id) {
      const a = authorizations.get(id);
      return a?.state === 'VERIFIED' ? ok(200, a.record) : ok(404, { code: 'NOT_FOUND' });
    },
    replaceEvidence(id, record) { authorizations.get(id).record = record; },
    async cancel(id) {
      const a = authorizations.get(id);
      if (a.state !== 'PENDING_USER') return ok(409, { code: 'AUTHORIZATION_NOT_PENDING' });
      a.state = 'CANCELLED';
      return ok(200, { authorizationId: id, state: 'CANCELLED' });
    },
    async commitRequest(id, ref) { fake.calls.push(['commitRequest', id, ref]); return ok(202, { state: 'COMMIT_REQUESTED' }); },
    async commitResult(id, state) { fake.calls.push(['commitResult', id, state]); return ok(200, { state }); },
    async offlineChallenge() { return ok(404, { code: 'NOT_IMPLEMENTED_IN_FAKE' }); },
    async offlineConfirmation() { return ok(404, { code: 'NOT_IMPLEMENTED_IN_FAKE' }); },
    async chain() { return ok(404, {}); },
  };
  return fake;
}
