import type { HsmAdapter } from './hsmAdapter';
import { SoftwareHsmAdapter } from './softwareHsmAdapter';
import { env } from '../config/env';

/** The configured HSM adapter: PKCS#11 (SoftHSM2 in tests, the bank's HSM in
 * production) or the in-memory development adapter. */
export async function selectHsmAdapter(): Promise<HsmAdapter> {
  if (env.HSM_ADAPTER === 'pkcs11') {
    // Loaded lazily: pkcs11js is a native addon development does not need.
    const { Pkcs11HsmAdapter } = await import('./pkcs11HsmAdapter');
    return new Pkcs11HsmAdapter();
  }
  return new SoftwareHsmAdapter();
}
