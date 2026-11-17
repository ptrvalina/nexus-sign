import { createPublicKey, diffieHellman, generateKeyPairSync } from 'node:crypto';
import { env } from '../config/env';
import { parseP256PublicKey } from '../crypto/p256PublicKey';
import { encryptSecret } from '../crypto/secretBox';
import { deriveOfflineKey } from './deviceProtocol';
import { ValidationError } from './errors';

/**
 * The two optional device keys registered next to the signing key:
 *
 * - the authentication key signs every request of the enrolled device
 *   (no bearer token needed after enrolment);
 * - the offline key agrees a per-credential secret with Auth Core, used to
 *   confirm transactions offline.
 *
 * All three are generated in the Secure Enclave or Android Keystore and never
 * leave the device.
 */
export interface DeviceKeysInput {
  authPublicKeyPem?: string;
  offlinePublicKeyPem?: string;
  /**
   * STATIC (default): one key agreed at enrolment, as Android keeps it in the
   * Keystore. PER_AUTHORIZATION: no key is agreed now; Auth Core generates a
   * key for each offline confirmation and puts it in the QR code (offline v3,
   * finding D-01). The iOS SDK asks for it: the Secure Enclave returns the
   * ECDH secret to the app process, so it must serve one authorization only.
   */
  offlineKeyAgreement?: OfflineKeyAgreement;
}

export type OfflineKeyAgreement = 'STATIC' | 'PER_AUTHORIZATION';

export interface DeviceKeyColumns {
  authPublicKeyPem: string | null;
  offlinePublicKeyPem: string | null;
  offlineServerPublicKeyPem: string | null;
  offlineSecretEncrypted: string | null;
  offlineKeyAgreement: OfflineKeyAgreement;
}

/** Validates the optional device keys and derives the credential columns stored for them. */
export function prepareDeviceKeys(credentialId: string, signingKeyPem: string, input: DeviceKeysInput): DeviceKeyColumns {
  const auth = input.authPublicKeyPem ? parseP256PublicKey(input.authPublicKeyPem) : null;
  const offline = input.offlinePublicKeyPem && env.OFFLINE_CONFIRMATION_ENABLED ? parseP256PublicKey(input.offlinePublicKeyPem) : null;

  const points = [parseP256PublicKey(signingKeyPem).point, auth?.point, offline?.point].filter((p): p is Buffer => Boolean(p));
  if (new Set(points.map((p) => p.toString('hex'))).size !== points.length) {
    throw new ValidationError('Signing, authentication and offline keys must be distinct keys');
  }

  let offlineServerPublicKeyPem: string | null = null;
  let offlineSecretEncrypted: string | null = null;
  const offlineKeyAgreement: OfflineKeyAgreement = input.offlineKeyAgreement ?? 'STATIC';
  if (offline && offlineKeyAgreement === 'STATIC') {
    // A fresh server key per credential. Its private half is used once, here,
    // and discarded; only the derived key is kept, encrypted.
    const server = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const shared = diffieHellman({ privateKey: server.privateKey, publicKey: createPublicKey(offline.pem) });
    offlineSecretEncrypted = encryptSecret(deriveOfflineKey(shared, credentialId), 'device', credentialId);
    offlineServerPublicKeyPem = server.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  }

  return {
    authPublicKeyPem: auth?.pem ?? null,
    offlinePublicKeyPem: offline?.pem ?? null,
    offlineServerPublicKeyPem,
    offlineSecretEncrypted,
    offlineKeyAgreement,
  };
}
