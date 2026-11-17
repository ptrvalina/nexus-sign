// Test fixture: confirmation evidence in the export format (schema 3), made
// with a software stand-in for the evidence key and a software device key.
// It is not Auth Core output and proves nothing about Auth Core; it lets the
// bank database tests drive the boundary's and the gateway's checks without
// running Auth Core. The end-to-end tests with Auth Core and SoftHSM are in
// bank-execution-boundary.test.mjs and bank-execution-processes.test.mjs.
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { canonicalJson, evidenceKeyId } from '../../../scripts/lib/evidence.mjs';
import { signingKeyFingerprint } from '../../../scripts/lib/bankTrust.mjs';

const sha256hex = (b) => createHash('sha256').update(b).digest('hex');
const pemOf = (k) => k.publicKey.export({ type: 'spki', format: 'pem' }).toString();

export function evidenceMaker() {
  const sealKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const sealPem = pemOf(sealKey);
  const sealKeyId = evidenceKeyId(sealPem);
  const seal = (sealedPayload, extra) => {
    const evidenceHash = sha256hex(canonicalJson(sealedPayload));
    return {
      schemaVersion: '3', recordType: sealedPayload.recordType, chainSequence: sealedPayload.chainSequence, nexusId: sealedPayload.nexusId,
      credentialId: sealedPayload.credentialId, sealKeyId, previousEvidenceHash: sealedPayload.previousEvidenceHash ?? null,
      evidenceHash, hsmSignature: sign('sha256', Buffer.from(evidenceHash, 'hex'), { key: sealKey.privateKey, dsaEncoding: 'der' }).toString('base64'),
      sealedPayload, ...extra,
    };
  };
  return {
    evidenceKeys: [sealPem],
    /** A device enrolled for a customer: its credential and key fingerprint (for the bank's approval). */
    device(nexusId) {
      const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const credentialId = randomUUID();
      const enrolment = seal({ schemaVersion: '3', recordType: 'CREDENTIAL_ENROLLED', chainSequence: 1, nexusId, credentialId, sealKeyId,
        previousEvidenceHash: null, keys: { signingPublicKeyPem: pemOf(key) } });
      return { nexusId, credentialId, key, publicKeyPem: pemOf(key), fingerprint: signingKeyFingerprint(pemOf(key)), enrolment };
    },
    /** The device signs a payment mandate (payment mandates v1); `termsOverride` changes what it signed. */
    mandate(device, { mandateId, payee, currency, perPaymentLimitMinor, totalLimitMinor = null, frequency = 'MONTHLY', validFrom, validUntil, termsOverride = {} }) {
      const now = Date.now();
      const terms = canonicalJson({
        protocol_version: '1', domain: 'NEXUS-SIGN/MANDATE', mandate_id: mandateId, nexus_id: device.nexusId, credential_id: device.credentialId,
        mandate_reference: `M-${mandateId.slice(0, 8)}`, payee, currency, per_payment_limit_minor: perPaymentLimitMinor, total_limit_minor: totalLimitMinor,
        frequency, valid_from: validFrom ?? new Date(now - 60_000).toISOString(), valid_until: validUntil ?? new Date(now + 365 * 864e5).toISOString(),
        terms_version: '1', issued_at: new Date(now - 60_000).toISOString(), offer_expires_at: new Date(now + 864e5).toISOString(),
        nonce: randomBytes(32).toString('hex'), ...termsOverride,
      });
      const sealedPayload = {
        schemaVersion: '3', recordType: 'MANDATE', chainSequence: 2, nexusId: device.nexusId, credentialId: device.credentialId, sealKeyId,
        previousEvidenceHash: device.enrolment.evidenceHash, enrolmentEvidenceHash: device.enrolment.evidenceHash,
        mandateId, event: 'SIGNED', termsHash: sha256hex(terms), mandateReference: `M-${mandateId.slice(0, 8)}`, reason: 'SIGNED_BY_CUSTOMER',
        occurredAt: new Date(now).toISOString(), signedTermsBase64: terms.toString('base64'), credentialPublicKeyPem: device.publicKeyPem,
        signatureFormat: 'der', signatureAlgorithm: 'ES256', signature: sign('sha256', terms, { key: device.key.privateKey, dsaEncoding: 'der' }).toString('base64'),
      };
      return seal(sealedPayload, { mandateId, credentialEnrolment: device.enrolment });
    },
    /** The device confirms these terms for this authorization. `signedOverride` changes what it signed. */
    confirm(device, { authorizationId, terms, signedOverride = {} }) {
      // A complete authorization object v1 (docs/protocol/authorization-protocol-v1.md), valid for two minutes from now.
      const issuedAt = new Date();
      const fields = {
        protocol_version: '1', domain: 'NEXUS-SIGN/TRANSACTION-AUTH', policy_reference: 'synthetic', policy_version: '1',
        issued_at: issuedAt.toISOString(), expires_at: new Date(issuedAt.getTime() + 120_000).toISOString(), nonce: randomBytes(32).toString('hex'),
        authorization_id: authorizationId, nexus_id: device.nexusId, credential_id: device.credentialId, transaction_reference: terms.transactionReference,
        operation_type: terms.operationType, amount_minor: String(terms.amountMinor), currency: terms.currency, beneficiary: terms.beneficiary, ...signedOverride,
      };
      const signed = canonicalJson(fields);
      const sealedPayload = {
        schemaVersion: '3', recordType: 'AUTHORIZATION', chainSequence: 2, nexusId: device.nexusId, credentialId: device.credentialId, sealKeyId,
        previousEvidenceHash: device.enrolment.evidenceHash, enrolmentEvidenceHash: device.enrolment.evidenceHash,
        authorizationId, transactionReference: terms.transactionReference, confirmationMethod: 'DEVICE_SIGNATURE',
        signedPayloadBase64: signed.toString('base64'), canonicalPayloadHash: sha256hex(signed), credentialPublicKeyPem: device.publicKeyPem,
        signatureFormat: 'der', signature: sign('sha256', signed, { key: device.key.privateKey, dsaEncoding: 'der' }).toString('base64'),
      };
      return seal(sealedPayload, { authorizationId, credentialEnrolment: device.enrolment });
    },
  };
}
