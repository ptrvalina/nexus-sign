import { createHash, createPublicKey, X509Certificate } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { parseDerElement, type DerElement, UNIVERSAL_TAG, encodeObjectIdentifier } from '../crypto/der';
import { GOOGLE_KEY_ATTESTATION_ROOTS } from '../crypto/androidAttestationRoots';

/**
 * Android Keystore hardware key attestation
 * (https://source.android.com/docs/security/features/keystore/attestation).
 *
 * When the SDK generates a key with setAttestationChallenge(), Keystore
 * returns a certificate chain whose leaf describes the key (KeyDescription
 * extension) and which ends at a Google root. Verifying it proves, for this
 * one key, what Play Integrity does not: that it was generated inside TEE or
 * StrongBox (origin GENERATED, security level), that it carries the
 * challenge of this enrolment, that it belongs to the bank's app (package and
 * signing certificate), the state of the bootloader, and for the signing key
 * that it cannot be used without biometric authentication.
 *
 * Checks, in order: chain signatures up to a Google root public key;
 * certificate validity (strict for Remote Key Provisioning chains, whose
 * intermediates are short-lived; factory-provisioned chains are accepted
 * after expiry, as Google's guidance states); the Google revocation status
 * list; the leaf public key; and the KeyDescription fields.
 */
export type AndroidKeyPolicy = 'REQUIRE_STRONGBOX' | 'REQUIRE_HARDWARE_BACKED' | 'ALLOW_TEE' | 'ALLOW_SOFTWARE';
export type KeystoreSecurityLevel = 'SOFTWARE' | 'TEE' | 'STRONGBOX';

export interface AndroidKeyExpectation {
  /** Leaf certificates, leaf first, as base64 DER. */
  chain: string[];
  challenge: Buffer;
  publicKeyPem: string;
  packageName: string;
  /** SHA-256 digests of the app signing certificates accepted (empty: not checked). */
  signingCertificateDigests: Buffer[];
  policy: AndroidKeyPolicy;
  requireLockedBootloader: boolean;
  /** The signing key must need biometric authentication for every use. */
  requireUserAuthentication: boolean;
  revocations: Map<string, string>;
  at?: Date;
  roots?: readonly string[];
}

export interface AndroidKeyVerdict {
  securityLevel: KeystoreSecurityLevel;
  attestationVersion: number;
  deviceLocked: boolean | null;
  verifiedBootState: string | null;
  certificateSerials: string[];
}

export class AndroidKeyAttestationError extends Error {
  constructor(message: string) { super(message); this.name = 'AndroidKeyAttestationError'; }
}

const KEY_DESCRIPTION_OID = encodeObjectIdentifier('1.3.6.1.4.1.11129.2.1.17');
const SECURITY_LEVELS: KeystoreSecurityLevel[] = ['SOFTWARE', 'TEE', 'STRONGBOX'];
const BOOT_STATES = ['VERIFIED', 'SELF_SIGNED', 'UNVERIFIED', 'FAILED'];
const TAG = { PURPOSE: 1, ALGORITHM: 2, EC_CURVE: 10, NO_AUTH_REQUIRED: 503, USER_AUTH_TYPE: 504, ORIGIN: 702, ROOT_OF_TRUST: 704, APPLICATION_ID: 709 };
const PURPOSE_SIGN = 2;
const ALGORITHM_EC = 3;
const CURVE_P256 = 1;
const ORIGIN_GENERATED = 0;
const AUTH_TYPE_BIOMETRIC = 2;

/** Challenge the SDK passes to setAttestationChallenge() for each key it
 * enrols: binds the key to this enrolment or recovery session. */
export function keyAttestationChallenge(enrolmentChallenge: Buffer): Buffer {
  return createHash('sha256').update(Buffer.concat([Buffer.from('NEXUS-SIGN/KEY-ATTESTATION/v1', 'utf8'), Buffer.from([0]), enrolmentChallenge])).digest();
}

export function verifyAndroidKeyAttestation(expected: AndroidKeyExpectation): AndroidKeyVerdict {
  const fail = (message: string): never => { throw new AndroidKeyAttestationError(message); };
  if (expected.chain.length < 2 || expected.chain.length > 10) fail('the attestation chain must have 2 to 10 certificates');
  let certificates: X509Certificate[] = [];
  try {
    certificates = expected.chain.map((der) => new X509Certificate(Buffer.from(der, 'base64')));
  } catch {
    fail('the attestation chain does not parse');
  }

  // Signatures up to a trusted root public key, and a valid certification
  // path: every issuing certificate is a CA allowed to sign certificates at
  // its depth, names chain, and no issuer is itself a Keystore key. Without
  // this, a genuine attestation leaf (whose key the device owner can use)
  // could sign a forged leaf claiming any KeyDescription.
  for (let i = 0; i < certificates.length - 1; i += 1) {
    const subject = certificates[i];
    const issuer = certificates[i + 1];
    if (!subject.verify(issuer.publicKey)) fail(`certificate ${i} is not signed by the next one`);
    const constraints = basicConstraints(issuer);
    if (!constraints?.ca) fail(`certificate ${i + 1} issues a certificate but is not a CA`);
    // Certificates between this issuer and the leaf that are themselves CAs.
    if (constraints!.pathLength !== null && i > constraints!.pathLength) fail(`certificate ${i + 1} exceeds its path length constraint`);
    const usage = keyUsage(issuer);
    if (usage !== null && !usage.keyCertSign) fail(`certificate ${i + 1} is not allowed to sign certificates`);
    if (extensionValue(issuer, KEY_DESCRIPTION_OID)) fail(`certificate ${i + 1} is an attested Keystore key, not a CA`);
    // Names, key identifiers and key usage as OpenSSL checks them for an issuer.
    if (!subject.checkIssued(issuer)) fail(`certificate ${i} does not name the next one as its issuer`);
  }
  if (basicConstraints(certificates[0])?.ca) fail('the attested key certificate is a CA certificate');
  const rootKeys = (expected.roots ?? GOOGLE_KEY_ATTESTATION_ROOTS).map((pem) => spki(new X509Certificate(pem)));
  const top = certificates[certificates.length - 1];
  if (!rootKeys.some((key) => key.equals(spki(top)))) fail('the chain does not end at a Google attestation root');
  if (!top.verify(top.publicKey)) fail('the root certificate is not self-signed');

  // Validity: strict for Remote Key Provisioning chains.
  const at = expected.at ?? new Date();
  const remotelyProvisioned = certificates.some((c) => /CN=Droid CA/i.test(c.subject.replace(/\n/g, ',')));
  if (remotelyProvisioned) {
    for (const c of certificates) {
      if (at < new Date(c.validFrom) || at > new Date(c.validTo)) fail('a certificate of the attestation chain is outside its validity period');
    }
  }

  const serials = certificates.map((c) => BigInt(`0x${c.serialNumber}`).toString(16));
  for (const serial of serials) {
    const status = expected.revocations.get(serial);
    if (status) fail(`certificate ${serial} of the attestation chain is ${status}`);
  }

  if (!spki(certificates[0]).equals(spkiFromPem(expected.publicKeyPem))) fail('the attested key is not the enrolled key');

  const description = keyDescription(certificates[0]) ?? fail('the leaf certificate has no key attestation extension');
  if (!description.challenge.equals(expected.challenge)) fail('the attestation challenge does not match this enrolment');
  const level = Math.min(description.attestationSecurityLevel, description.keyMintSecurityLevel);
  const securityLevel = SECURITY_LEVELS[level] ?? fail('unknown security level');
  if (expected.policy === 'REQUIRE_STRONGBOX' && securityLevel !== 'STRONGBOX') fail(`the key is in ${securityLevel}; StrongBox is required`);
  if ((expected.policy === 'REQUIRE_HARDWARE_BACKED' || expected.policy === 'ALLOW_TEE') && securityLevel === 'SOFTWARE') fail('the key is not hardware-backed');

  const hw = description.hardwareEnforced;
  if (expected.policy !== 'ALLOW_SOFTWARE') {
    if (hw.origin !== ORIGIN_GENERATED) fail('the key was not generated inside the secure hardware');
    if (hw.algorithm !== ALGORITHM_EC || hw.ecCurve !== CURVE_P256) fail('the attested key is not a hardware P-256 key');
    if (!hw.purposes.includes(PURPOSE_SIGN)) fail('the attested key is not a signing key');
  }
  if (expected.requireUserAuthentication && (hw.noAuthRequired || hw.userAuthType === null || (hw.userAuthType & AUTH_TYPE_BIOMETRIC) === 0)) {
    fail('the signing key can be used without biometric authentication');
  }
  if (expected.requireLockedBootloader && (hw.deviceLocked !== true || hw.verifiedBootState !== 'VERIFIED')) {
    fail('the device bootloader is unlocked or the boot state is not verified');
  }
  const application = description.softwareEnforced.applicationId ?? hw.applicationId ?? fail('the attestation has no application identity');
  if (!application.packageNames.includes(expected.packageName)) fail('the key belongs to another application package');
  if (expected.signingCertificateDigests.length > 0
    && !application.signatureDigests.some((d) => expected.signingCertificateDigests.some((e) => e.equals(d)))) {
    fail('the application is not signed with an accepted certificate');
  }
  return {
    securityLevel,
    attestationVersion: description.attestationVersion,
    deviceLocked: hw.deviceLocked,
    verifiedBootState: hw.verifiedBootState,
    certificateSerials: serials,
  };
}

/** Google's attestation status list (https://android.googleapis.com/attestation/status),
 * as downloaded by operations: serial (lowercase hex) to status. */
export function loadRevocationList(path: string | undefined): { entries: Map<string, string>; modifiedAt: Date | null } {
  if (!path) return { entries: new Map(), modifiedAt: null };
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as { entries?: Record<string, { status?: string }> };
  const entries = new Map<string, string>();
  for (const [serial, entry] of Object.entries(parsed.entries ?? {})) {
    entries.set(serial.toLowerCase().replace(/^0+(?=.)/, ''), entry.status ?? 'REVOKED');
  }
  return { entries, modifiedAt: statSync(path).mtime };
}

function spki(certificate: X509Certificate): Buffer {
  return certificate.publicKey.export({ type: 'spki', format: 'der' });
}

function spkiFromPem(pem: string): Buffer {
  return createPublicKey(pem).export({ type: 'spki', format: 'der' });
}

interface AuthorizationList {
  purposes: number[];
  algorithm: number | null;
  ecCurve: number | null;
  noAuthRequired: boolean;
  userAuthType: number | null;
  origin: number | null;
  deviceLocked: boolean | null;
  verifiedBootState: string | null;
  applicationId: { packageNames: string[]; signatureDigests: Buffer[] } | null;
}

interface KeyDescription {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keyMintSecurityLevel: number;
  challenge: Buffer;
  softwareEnforced: AuthorizationList;
  hardwareEnforced: AuthorizationList;
}

/** The DER content of an extension's extnValue OCTET STRING, or null. */
function extensionValue(certificate: X509Certificate, oidBytes: Buffer): Buffer | null {
  const tbs = parseDerElement(certificate.raw).children[0];
  const extensionsWrapper = tbs?.children.find((c) => !isUniversal(c) && c.tagNumber === 3);
  const extensions = extensionsWrapper?.children[0]?.children ?? [];
  for (const extension of extensions) {
    const [oid, ...rest] = extension.children;
    if (oid?.tagNumber === UNIVERSAL_TAG.OBJECT_IDENTIFIER && oid.content.equals(oidBytes)) {
      const value = rest[rest.length - 1];
      if (!value || value.tagNumber !== UNIVERSAL_TAG.OCTET_STRING) throw new AndroidKeyAttestationError('malformed certificate extension');
      return Buffer.from(value.content);
    }
  }
  return null;
}

const BASIC_CONSTRAINTS_OID = encodeObjectIdentifier('2.5.29.19');
const KEY_USAGE_OID = encodeObjectIdentifier('2.5.29.15');

/** RFC 5280 basicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }. */
function basicConstraints(certificate: X509Certificate): { ca: boolean; pathLength: number | null } | null {
  const value = extensionValue(certificate, BASIC_CONSTRAINTS_OID);
  if (!value) return null;
  const sequence = parseDerElement(value);
  let ca = false; let pathLength: number | null = null;
  for (const element of sequence.children) {
    if (element.tagNumber === UNIVERSAL_TAG.BOOLEAN && isUniversal(element)) ca = element.content[0] !== 0;
    else if (element.tagNumber === UNIVERSAL_TAG.INTEGER && isUniversal(element)) pathLength = integer(element);
  }
  return { ca, pathLength };
}

/** RFC 5280 keyUsage BIT STRING; keyCertSign is bit 5. Null when absent. */
function keyUsage(certificate: X509Certificate): { keyCertSign: boolean } | null {
  const value = extensionValue(certificate, KEY_USAGE_OID);
  if (!value) return null;
  const bits = parseDerElement(value).content; // first byte: unused bit count
  return { keyCertSign: bits.length > 1 && (bits[1]! & 0x04) !== 0 };
}

function keyDescription(certificate: X509Certificate): KeyDescription | null {
  const content = extensionValue(certificate, KEY_DESCRIPTION_OID);
  if (!content) return null;
  const description = parseDerElement(content);
  if (description.children.length < 8) throw new AndroidKeyAttestationError('malformed KeyDescription');
  const [version, attestationLevel, , keyMintLevel, challenge, , software, hardware] = description.children;
  return {
    attestationVersion: integer(version),
    attestationSecurityLevel: integer(attestationLevel),
    keyMintSecurityLevel: integer(keyMintLevel),
    challenge: Buffer.from(challenge.content),
    softwareEnforced: authorizationList(software),
    hardwareEnforced: authorizationList(hardware),
  };
}

function authorizationList(list: DerElement): AuthorizationList {
  const result: AuthorizationList = {
    purposes: [], algorithm: null, ecCurve: null, noAuthRequired: false, userAuthType: null, origin: null,
    deviceLocked: null, verifiedBootState: null, applicationId: null,
  };
  for (const tagged of list.children) {
    if (isUniversal(tagged)) continue;
    const value = tagged.children[0];
    switch (tagged.tagNumber) {
      case TAG.PURPOSE: result.purposes = (value?.children ?? []).map(integer); break;
      case TAG.ALGORITHM: result.algorithm = integer(value); break;
      case TAG.EC_CURVE: result.ecCurve = integer(value); break;
      case TAG.NO_AUTH_REQUIRED: result.noAuthRequired = true; break;
      case TAG.USER_AUTH_TYPE: result.userAuthType = integer(value); break;
      case TAG.ORIGIN: result.origin = integer(value); break;
      case TAG.ROOT_OF_TRUST: {
        const [, locked, state] = value?.children ?? [];
        result.deviceLocked = locked ? locked.content[0] !== 0 : null;
        result.verifiedBootState = state ? BOOT_STATES[integer(state)] ?? 'UNKNOWN' : null;
        break;
      }
      case TAG.APPLICATION_ID: {
        const id = parseDerElement(value.content);
        const [packages, digests] = id.children;
        result.applicationId = {
          packageNames: (packages?.children ?? []).map((p) => p.children[0]?.content.toString('utf8') ?? ''),
          signatureDigests: (digests?.children ?? []).map((d) => Buffer.from(d.content)),
        };
        break;
      }
      default: break; // other tags are not needed, and tolerated for forward compatibility
    }
  }
  return result;
}

function isUniversal(element: DerElement): boolean {
  return (element.rawTag & 0xc0) === 0;
}

function integer(element: DerElement | undefined): number {
  if (!element) throw new AndroidKeyAttestationError('missing INTEGER in KeyDescription');
  if (element.content.length > 6) throw new AndroidKeyAttestationError('INTEGER in KeyDescription is too large');
  let value = 0;
  for (const byte of element.content) value = value * 256 + byte;
  return value;
}
