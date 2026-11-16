import type { HsmAdapter } from './hsmAdapter';
import { SoftwareHsmAdapter } from './softwareHsmAdapter';
import { env } from '../config/env';

/** The configured HSM adapter: PKCS#11 (SoftHSM2 in tests, the bank's HSM in
 * production) or the in-memory development adapter.
 *
 * The development adapter generates a throw-away evidence key in memory.
 * Seals made with it can never be verified again and evidence records are
 * permanent, so it is refused unless the process runs outside production
 * with ALLOW_INSECURE_DEVELOPMENT=true (audit finding B-03). This applies to
 * every caller, including the CLIs that seal (sealCredentialBaseline), which
 * do not run the server's posture checks. */
export async function selectHsmAdapter(config: Pick<typeof env, 'HSM_ADAPTER' | 'NODE_ENV' | 'ALLOW_INSECURE_DEVELOPMENT'> = env): Promise<HsmAdapter> {
  if (config.HSM_ADAPTER === 'pkcs11') {
    // Loaded lazily: pkcs11js is a native addon development does not need.
    const { Pkcs11HsmAdapter } = await import('./pkcs11HsmAdapter');
    return new Pkcs11HsmAdapter();
  }
  if (config.NODE_ENV === 'production' || !config.ALLOW_INSECURE_DEVELOPMENT) {
    throw new Error('HSM_ADAPTER=software keeps the evidence key in memory and is refused here: set HSM_ADAPTER=pkcs11, or ALLOW_INSECURE_DEVELOPMENT=true outside production');
  }
  return new SoftwareHsmAdapter();
}
