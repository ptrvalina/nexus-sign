import { env } from '../config/env';
import { getGoogleAccessToken, parseServiceAccountJson } from '../crypto/googleServiceAccount';

/**
 * Verifies an Android Play Integrity token server-side, per Google's
 * documented flow: exchange a service-account-signed JWT for a Google
 * OAuth2 access token, then call the Play Integrity decode endpoint
 * with it.
 *
 * https://developer.android.com/google/play/integrity/verdicts#decrypt-verify
 */

const PLAY_INTEGRITY_SCOPE = 'https://www.googleapis.com/auth/playintegrity';

export class PlayIntegrityNotConfiguredError extends Error {
  constructor() {
    super('GOOGLE_SERVICE_ACCOUNT_JSON / ANDROID_PACKAGE_NAME are not configured — Play Integrity verification is unavailable');
    this.name = 'PlayIntegrityNotConfiguredError';
  }
}

export class PlayIntegrityVerificationFailedError extends Error {
  constructor(reason: string) {
    super(`Play Integrity verification failed: ${reason}`);
    this.name = 'PlayIntegrityVerificationFailedError';
  }
}

interface DecodedIntegrityPayload {
  requestDetails?: { requestPackageName?: string; nonce?: string; timestampMillis?: string };
  appIntegrity?: { appRecognitionVerdict?: string; packageName?: string; certificateSha256Digest?: string[] };
  deviceIntegrity?: { deviceRecognitionVerdict?: string[] };
  accountDetails?: { appLicensingVerdict?: string };
}

export interface PlayIntegrityResult {
  appRecognized: boolean;
  deviceIntegrityVerdicts: string[];
  raw: DecodedIntegrityPayload;
}

/**
 * Decodes and validates a Play Integrity token. `expectedNonce` is the
 * session attestation binding, SHA-256(challenge || 0x00 || public key)
 * (see attestationBinding.ts), so a token cannot be replayed in another
 * session or for another key.
 */
export async function verifyPlayIntegrityToken(integrityToken: string, expectedNonce: string): Promise<PlayIntegrityResult> {
  if (!env.GOOGLE_SERVICE_ACCOUNT_JSON || !env.ANDROID_PACKAGE_NAME) {
    throw new PlayIntegrityNotConfiguredError();
  }

  const serviceAccount = parseServiceAccountJson(env.GOOGLE_SERVICE_ACCOUNT_JSON);
  const accessToken = await getGoogleAccessToken(serviceAccount, PLAY_INTEGRITY_SCOPE);
  const url = `https://playintegrity.googleapis.com/v1/${encodeURIComponent(env.ANDROID_PACKAGE_NAME)}:decodeIntegrityToken`;

  const response = await fetch(url, {
    method: 'POST',
    signal: AbortSignal.timeout(10_000),
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ integrityToken }),
  });

  if (!response.ok) {
    throw new PlayIntegrityVerificationFailedError(`decodeIntegrityToken returned HTTP ${response.status}`);
  }

  const body = (await response.json()) as { tokenPayloadExternal?: DecodedIntegrityPayload };
  const payload = body.tokenPayloadExternal;
  if (!payload) {
    throw new PlayIntegrityVerificationFailedError('Response had no tokenPayloadExternal');
  }

  if (payload.requestDetails?.requestPackageName !== env.ANDROID_PACKAGE_NAME) {
    throw new PlayIntegrityVerificationFailedError('requestPackageName did not match the configured Android package name');
  }
  if (payload.requestDetails?.nonce !== expectedNonce) {
    throw new PlayIntegrityVerificationFailedError('nonce did not match the expected value — possible token replay');
  }

  if (payload.appIntegrity?.packageName !== undefined && payload.appIntegrity.packageName !== env.ANDROID_PACKAGE_NAME) {
    throw new PlayIntegrityVerificationFailedError('appIntegrity.packageName did not match the configured Android package name');
  }
  if (env.ANDROID_APP_CERT_SHA256.length > 0) {
    // Play Integrity reports the digests as unpadded base64url.
    const digests = (payload.appIntegrity?.certificateSha256Digest ?? []).map((d) => Buffer.from(d, 'base64url').toString('hex'));
    if (!digests.some((d) => env.ANDROID_APP_CERT_SHA256.includes(d))) {
      throw new PlayIntegrityVerificationFailedError('the app is not signed with an accepted certificate');
    }
  }
  const appRecognized = payload.appIntegrity?.appRecognitionVerdict === 'PLAY_RECOGNIZED';
  const deviceIntegrityVerdicts = payload.deviceIntegrity?.deviceRecognitionVerdict ?? [];
  const timestamp = Number(payload.requestDetails?.timestampMillis ?? 0);
  if (!Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp) > env.ATTESTATION_MAX_AGE_SECONDS * 1000) {
    throw new PlayIntegrityVerificationFailedError('attestation token is outside the accepted freshness window');
  }

  return { appRecognized, deviceIntegrityVerdicts, raw: payload };
}
