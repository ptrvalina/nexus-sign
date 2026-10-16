import { createHash } from 'node:crypto';
import type { DeviceKeysInput } from './deviceKeysService';

/**
 * The exact bytes both mobile SDKs attest:
 *
 *   challenge || 0x00 || signing key PEM                                    (signing key only)
 *   challenge || 0x00 || signing key PEM || 0x00 || auth PEM || 0x00 || offline PEM
 *
 * The second form is used as soon as the device enrols an authentication or
 * offline key; a missing one is the empty string. PEM text never contains a
 * NUL byte, so the concatenation is unambiguous and one attestation covers
 * every key the device registers.
 */
export function buildAttestationBinding(challenge: Buffer, publicKeyPem: string, deviceKeys: DeviceKeysInput = {}): Buffer {
  const parts = [challenge, Buffer.from([0]), Buffer.from(publicKeyPem, 'utf8')];
  if (deviceKeys.authPublicKeyPem || deviceKeys.offlinePublicKeyPem) {
    parts.push(Buffer.from([0]), Buffer.from(deviceKeys.authPublicKeyPem ?? '', 'utf8'),
      Buffer.from([0]), Buffer.from(deviceKeys.offlinePublicKeyPem ?? '', 'utf8'));
  }
  return Buffer.concat(parts);
}

export function hashAttestationBinding(binding: Buffer): Buffer {
  return createHash('sha256').update(binding).digest();
}
