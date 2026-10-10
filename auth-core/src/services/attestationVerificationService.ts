import { createHash } from 'node:crypto';
import { verifyAppAttestAttestation, AppAttestNotConfiguredError } from './appAttestService';
import { verifyPlayIntegrityToken, PlayIntegrityNotConfiguredError } from './playIntegrityService';
import { AndroidKeyAttestationError, keyAttestationChallenge, loadRevocationList, verifyAndroidKeyAttestation, type KeystoreSecurityLevel } from './androidKeyAttestation';
import { env } from '../config/env';
import type { EnrolmentAttestation } from './evidenceService';

export interface AttestationVerdict {
  verified: boolean;
  platform: 'ios' | 'android' | 'unknown';
  reason?: string;
  environment?: string;
  /** Where the keys live, as proven by the attestation (never the client's claim). */
  securityLevel?: 'SECURE_ENCLAVE' | KeystoreSecurityLevel;
}

/** The keys an enrolment registers and the challenge it was issued. */
export interface AttestedKeys {
  /** BOOTSTRAP token challenge or recovery session nonce. */
  challenge: Buffer;
  signingPublicKeyPem: string;
  authPublicKeyPem?: string;
}

/**
 * Routes the `deviceAttestation` object to the verifier matching its shape:
 * iOS sends `attestationObject` and `keyId`; Android sends `integrityToken`
 * and, for each hardware key, its Keystore attestation chain (`keyAttestation`).
 */
export async function verifyDeviceAttestation(
  deviceAttestation: Record<string, unknown>,
  binding: Buffer,
  keys: AttestedKeys,
): Promise<AttestationVerdict> {
  const attestationObject = deviceAttestation.attestationObject;
  const keyId = deviceAttestation.keyId;
  if (typeof attestationObject === 'string' && typeof keyId === 'string') {
    return verifyIos(attestationObject, keyId, binding);
  }

  const integrityToken = deviceAttestation.integrityToken;
  if (typeof integrityToken === 'string') {
    return verifyAndroid(integrityToken, binding, deviceAttestation.keyAttestation, keys);
  }

  // The SDKs report why no evidence is attached instead of failing the
  // enrolment on the device; the policy decision is made here.
  if (deviceAttestation.supported === false) {
    return { verified: false, platform: 'unknown', reason: 'device reported that attestation is not supported' };
  }
  if (typeof deviceAttestation.attestationError === 'string') {
    return { verified: false, platform: 'unknown', reason: `device reported an attestation error: ${deviceAttestation.attestationError.slice(0, 64)}` };
  }
  return {
    verified: false,
    platform: 'unknown',
    reason: "deviceAttestation did not match either SDK's expected shape (missing attestationObject/keyId or integrityToken)",
  };
}

async function verifyIos(attestationObjectBase64: string, keyId: string, binding: Buffer): Promise<AttestationVerdict> {
  try {
    // Same binding the iOS NEXUSSignSDK.bootstrap() attests
    // (AttestationProvider.swift).
    const clientDataHash = createHash('sha256').update(binding).digest();
    const result = await verifyAppAttestAttestation({ attestationObjectBase64, keyId, clientDataHash });
    if (env.NODE_ENV === 'production' && result.environment !== 'production') {
      return { verified: false, platform: 'ios', environment: result.environment, reason: 'development App Attest environment is not accepted in production' };
    }
    // App Attest proves a genuine instance of the bank's app on a genuine
    // device; that app generates its keys only in the Secure Enclave.
    return { verified: true, platform: 'ios', environment: result.environment, securityLevel: 'SECURE_ENCLAVE' };
  } catch (error) {
    if (error instanceof AppAttestNotConfiguredError) {
      return { verified: false, platform: 'ios', reason: error.message };
    }
    return { verified: false, platform: 'ios', reason: error instanceof Error ? error.message : String(error) };
  }
}

async function verifyAndroid(integrityToken: string, binding: Buffer, keyAttestation: unknown, keys: AttestedKeys): Promise<AttestationVerdict> {
  let environment: string | undefined;
  try {
    // Same binding the Android NEXUSSignSDK.bootstrap() uses for the token
    // request (AttestationProvider.kt).
    const expectedNonce = createHash('sha256').update(binding).digest('base64url');
    const result = await verifyPlayIntegrityToken(integrityToken, expectedNonce);
    environment = result.deviceIntegrityVerdicts.join(',');
    if (!result.appRecognized || !result.deviceIntegrityVerdicts.includes(env.ANDROID_REQUIRED_DEVICE_VERDICT)) {
      return { verified: false, platform: 'android', environment, reason: 'Play Integrity app/device verdict did not satisfy policy' };
    }
  } catch (error) {
    if (error instanceof PlayIntegrityNotConfiguredError) return { verified: false, platform: 'android', reason: error.message };
    return { verified: false, platform: 'android', reason: error instanceof Error ? error.message : String(error) };
  }
  try {
    const securityLevel = verifyKeyAttestation(keyAttestation, keys);
    return { verified: true, platform: 'android', environment, securityLevel };
  } catch (error) {
    if (error instanceof AndroidKeyAttestationError) return { verified: false, platform: 'android', environment, reason: `key attestation: ${error.message}` };
    throw error;
  }
}

let revocationCache: { path: string; loadedAt: number; entries: Map<string, string> } | null = null;

/** The status list is re-read when the file changes (operations refresh it). */
function revocations(): Map<string, string> {
  const path = env.ANDROID_ATTESTATION_STATUS_FILE;
  if (!path) return new Map();
  let loaded: { entries: Map<string, string>; modifiedAt: Date | null };
  try {
    loaded = revocationCache?.path === path && revocationCache.loadedAt >= Date.now() - 60_000
      ? { entries: revocationCache.entries, modifiedAt: null }
      : loadRevocationList(path);
  } catch (error) {
    // Without the list a revoked attestation key cannot be told apart: the
    // enrolment is refused (fail closed) and operations restore the file.
    throw new AndroidKeyAttestationError(`the attestation status list is unavailable (${error instanceof Error ? error.message.slice(0, 120) : 'unreadable'})`);
  }
  const { entries, modifiedAt } = loaded;
  if (modifiedAt) revocationCache = { path, loadedAt: Date.now(), entries };
  return entries;
}

/** Verifies the Keystore attestation of the signing key and, when enrolled,
 * the authentication key; returns the weaker of their security levels. */
function verifyKeyAttestation(keyAttestation: unknown, keys: AttestedKeys): KeystoreSecurityLevel {
  const chains = (keyAttestation ?? {}) as { signingKeyChain?: unknown; authenticationKeyChain?: unknown };
  const asChain = (value: unknown): string[] | null => (Array.isArray(value) && value.every((c) => typeof c === 'string' && c.length < 8192) ? value as string[] : null);
  const signingChain = asChain(chains.signingKeyChain);
  const authChain = asChain(chains.authenticationKeyChain);
  if (env.ANDROID_KEY_SECURITY_POLICY === 'ALLOW_SOFTWARE' && !signingChain) return 'SOFTWARE';
  if (!signingChain) throw new AndroidKeyAttestationError('the signing key has no Keystore attestation chain');
  if (keys.authPublicKeyPem && !authChain) throw new AndroidKeyAttestationError('the authentication key has no Keystore attestation chain');
  const common = {
    challenge: keyAttestationChallenge(keys.challenge),
    packageName: env.ANDROID_PACKAGE_NAME ?? '',
    signingCertificateDigests: env.ANDROID_APP_CERT_SHA256.map((hex) => Buffer.from(hex, 'hex')),
    policy: env.ANDROID_KEY_SECURITY_POLICY,
    requireLockedBootloader: env.ANDROID_REQUIRE_LOCKED_BOOTLOADER,
    revocations: revocations(),
  };
  const levels: KeystoreSecurityLevel[] = [
    verifyAndroidKeyAttestation({ ...common, chain: signingChain, publicKeyPem: keys.signingPublicKeyPem, requireUserAuthentication: true }).securityLevel,
  ];
  if (keys.authPublicKeyPem && authChain) {
    levels.push(verifyAndroidKeyAttestation({ ...common, chain: authChain, publicKeyPem: keys.authPublicKeyPem, requireUserAuthentication: false }).securityLevel);
  }
  const order: KeystoreSecurityLevel[] = ['SOFTWARE', 'TEE', 'STRONGBOX'];
  return levels.reduce((weakest, level) => (order.indexOf(level) < order.indexOf(weakest) ? level : weakest));
}

/** True when the verified evidence comes from the platform the client claims. */
export function platformMatches(verdict: AttestationVerdict, claimed: string): boolean {
  return verdict.platform === 'unknown' || verdict.platform === claimed.toLowerCase();
}

const sha256hex = (value: Buffer | string): string => createHash('sha256').update(value).digest('hex');

/**
 * What the sealed CREDENTIAL_ENROLLED record keeps about the attestation that
 * admitted a credential: the App Attest object and the Android Keystore
 * attestation chains themselves (a third party can re-check them against
 * Apple's and Google's roots), and only a digest and the decoded verdict of a
 * Play Integrity token (Google decodes those tokens).
 */
export function enrolmentAttestation(deviceAttestation: Record<string, unknown>, binding: Buffer, verdict: AttestationVerdict): EnrolmentAttestation {
  let material: Record<string, unknown> = { format: 'none', reason: verdict.reason ?? null };
  if (typeof deviceAttestation.attestationObject === 'string' && typeof deviceAttestation.keyId === 'string') {
    material = { format: 'apple-app-attest', attestationObject: deviceAttestation.attestationObject, keyId: deviceAttestation.keyId, environment: verdict.environment ?? null };
  } else if (typeof deviceAttestation.integrityToken === 'string') {
    material = {
      format: 'android-play-integrity+key-attestation',
      integrityTokenSha256: sha256hex(deviceAttestation.integrityToken),
      deviceVerdicts: verdict.environment ?? null,
      keyAttestation: deviceAttestation.keyAttestation ?? null,
      securityLevel: verdict.securityLevel ?? null,
    };
  }
  return { status: verdict.verified ? 'VERIFIED' : 'UNKNOWN', bindingSha256: sha256hex(binding), material };
}
