import { createHash, X509Certificate } from 'node:crypto';
import { decodeFirst } from 'cbor';
import { parseDerElement, encodeObjectIdentifier } from '../crypto/der';
import { getAppleAppAttestRootCertPem } from '../crypto/appleRootCert';
import { env } from '../config/env';

/**
 * Verifies an Apple App Attest attestation object following Apple's
 * published procedure; the step numbers below refer to:
 * https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
 *
 * Verification is local, against the certificate chain and the App Attest
 * root CA (appleRootCert.ts).
 */

export class AppAttestNotConfiguredError extends Error {
  constructor() {
    super('APPLE_APP_ID is not configured — App Attest verification is unavailable');
    this.name = 'AppAttestNotConfiguredError';
  }
}

export class AppAttestVerificationFailedError extends Error {
  constructor(reason: string) {
    super(`App Attest verification failed: ${reason}`);
    this.name = 'AppAttestVerificationFailedError';
  }
}

const NONCE_EXTENSION_OID = '1.2.840.113635.100.8.2';

export interface AppAttestVerificationResult {
  environment: 'production' | 'development';
}

export interface VerifyAppAttestInput {
  /** Base64-encoded CBOR attestation object, exactly as produced by
   * `DCAppAttestService.attestKey` on the device. */
  attestationObjectBase64: string;
  /** The App Attest key identifier generated with the attestation, base64-encoded. */
  keyId: string;
  /** The session attestation binding, SHA-256(challenge || 0x00 || public
   * key) (see attestationBinding.ts), so an attestation cannot be replayed in
   * another session or for another key. */
  clientDataHash: Buffer;
}

/** The 'cbor' package decodes CBOR maps to a `Map` by default; accepts either
 * a `Map` or a plain object. */
function mapGet(value: unknown, key: string): unknown {
  if (value instanceof Map) {
    return value.get(key);
  }
  if (value && typeof value === 'object') {
    return (value as Record<string, unknown>)[key];
  }
  return undefined;
}

export async function verifyAppAttestAttestation(input: VerifyAppAttestInput): Promise<AppAttestVerificationResult> {
  if (!env.APPLE_APP_ID) {
    throw new AppAttestNotConfiguredError();
  }

  const attestationObject = Buffer.from(input.attestationObjectBase64, 'base64');
  const decoded: unknown = await decodeFirst(attestationObject);

  const fmt = mapGet(decoded, 'fmt');
  const attStmt = mapGet(decoded, 'attStmt');
  const authData = mapGet(decoded, 'authData');

  if (fmt !== 'apple-appattest') {
    throw new AppAttestVerificationFailedError(`Unexpected attestation format: ${String(fmt)}`);
  }
  if (!Buffer.isBuffer(authData)) {
    throw new AppAttestVerificationFailedError('authData was missing or not a byte string');
  }
  const authDataBuffer = authData as Buffer;

  const x5c = mapGet(attStmt, 'x5c');
  if (!Array.isArray(x5c) || x5c.length < 2 || !Buffer.isBuffer(x5c[0]) || !Buffer.isBuffer(x5c[1])) {
    throw new AppAttestVerificationFailedError('attStmt.x5c did not contain a leaf and intermediate certificate');
  }
  const leafDer = x5c[0] as Buffer;
  const intermediateDer = x5c[1] as Buffer;

  // --- Step 1: verify the certificate chain up to Apple's root ---
  const rootPem = await getAppleAppAttestRootCertPem();
  const leaf = new X509Certificate(leafDer);
  const intermediate = new X509Certificate(intermediateDer);
  const root = new X509Certificate(rootPem);

  if (!leaf.checkIssued(intermediate) || !leaf.verify(intermediate.publicKey)) {
    throw new AppAttestVerificationFailedError('Leaf certificate was not validly issued by the intermediate certificate');
  }
  if (!intermediate.checkIssued(root) || !intermediate.verify(root.publicKey)) {
    throw new AppAttestVerificationFailedError('Intermediate certificate was not validly issued by the Apple App Attest root');
  }

  const now = new Date();
  for (const cert of [leaf, intermediate, root]) {
    if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
      throw new AppAttestVerificationFailedError('A certificate in the chain is outside its validity window');
    }
  }

  // --- Step 2/3: nonce = SHA-256(authenticatorData || clientDataHash) ---
  const nonce = createHash('sha256').update(Buffer.concat([authDataBuffer, input.clientDataHash])).digest();

  // --- Step 4: the leaf certificate's nonce extension must match ---
  const extensionNonce = extractNonceExtension(leafDer);
  if (!extensionNonce || !extensionNonce.equals(nonce)) {
    throw new AppAttestVerificationFailedError('Certificate nonce extension did not match the computed nonce');
  }

  // --- Step 5: SHA-256 of the leaf's public key must equal keyId ---
  const spki = leaf.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const rawPoint = spki.subarray(spki.length - 65); // last 65 bytes = uncompressed P-256 point (0x04 || X || Y)
  const computedKeyId = createHash('sha256').update(rawPoint).digest();
  const providedKeyId = Buffer.from(input.keyId, 'base64');
  if (!computedKeyId.equals(providedKeyId)) {
    throw new AppAttestVerificationFailedError('keyId did not match the leaf certificate public key');
  }

  // --- Steps 6-9: rpIdHash, counter, aaguid and credentialId from authData ---
  // rpIdHash (32) | flags (1) | counter (4) | aaguid (16) | credentialIdLength (2) | credentialId
  if (authDataBuffer.length < 55) {
    throw new AppAttestVerificationFailedError('authData is shorter than the attested credential header');
  }
  const rpIdHash = authDataBuffer.subarray(0, 32);
  const counter = authDataBuffer.readUInt32BE(33);
  const aaguid = authDataBuffer.subarray(37, 53);
  const credentialIdLength = authDataBuffer.readUInt16BE(53);
  if (authDataBuffer.length < 55 + credentialIdLength) {
    throw new AppAttestVerificationFailedError('authData credentialId is truncated');
  }
  const credentialId = authDataBuffer.subarray(55, 55 + credentialIdLength);

  const expectedRpIdHash = createHash('sha256').update(Buffer.from(env.APPLE_APP_ID, 'utf8')).digest();
  if (!rpIdHash.equals(expectedRpIdHash)) {
    throw new AppAttestVerificationFailedError('authData rpIdHash did not match the configured Apple App ID');
  }
  if (counter !== 0) {
    throw new AppAttestVerificationFailedError('Initial attestation must have counter == 0');
  }
  if (!credentialId.equals(providedKeyId)) {
    throw new AppAttestVerificationFailedError('authData credentialId did not match the provided keyId');
  }

  const aaguidString = aaguid.toString('utf8').replace(/\0+$/, '');
  if (aaguidString === 'appattestdevelop') {
    return { environment: 'development' };
  }
  if (aaguidString === 'appattest') {
    return { environment: 'production' };
  }
  throw new AppAttestVerificationFailedError(`Unrecognized aaguid: ${aaguid.toString('hex')}`);
}

/**
 * Finds the App Attest nonce extension (OID 1.2.840.113635.100.8.2) in the
 * leaf certificate and unwraps it: `extnValue` is an OCTET STRING containing
 * `SEQUENCE { [1] EXPLICIT OCTET STRING }` around the 32-byte nonce.
 */
function extractNonceExtension(leafCertDer: Buffer): Buffer | null {
  const certificate = parseDerElement(leafCertDer);
  const tbsCertificate = certificate.children[0];
  if (!tbsCertificate) return null;

  // X.509 `[3] EXPLICIT extensions`: context class (0x80) | constructed (0x20) | 3 = 0xA3.
  const extensionsWrapper = tbsCertificate.children.find((el) => el.rawTag === 0xa3);
  const extensionsSeq = extensionsWrapper?.children[0];
  if (!extensionsSeq) return null;

  const targetOid = encodeObjectIdentifier(NONCE_EXTENSION_OID);

  for (const extension of extensionsSeq.children) {
    const oidElement = extension.children[0];
    if (!oidElement || !oidElement.content.equals(targetOid)) {
      continue;
    }
    const octetStringElement = extension.children[extension.children.length - 1];
    if (!octetStringElement) return null;

    const inner = parseDerElement(octetStringElement.content);
    const explicitWrapper = inner.children[0]; // `[1] EXPLICIT`
    const innerOctetString = explicitWrapper?.children[0];
    return innerOctetString ? Buffer.from(innerOctetString.content) : null;
  }

  return null;
}
