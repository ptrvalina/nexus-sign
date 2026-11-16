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
    // The PKCS#11 module runs in a worker thread (audit finding B-01); the
    // options are read here so a configuration error stops the start.
    const { pkcs11OptionsFromEnv } = await import('./pkcs11HsmAdapter');
    const { Worker } = await import('node:worker_threads');
    const { join } = await import('node:path');
    const { HsmWorkerHost } = await import('./hsmWorkerHost');
    const options = pkcs11OptionsFromEnv();
    return new HsmWorkerHost(() => new Worker(join(__dirname, 'pkcs11Worker.js'), { workerData: { options } }), {
      name: 'pkcs11',
      timeoutMs: env.HSM_OPERATION_TIMEOUT_MS,
      queueLimit: env.HSM_QUEUE_LIMIT,
      breakerThreshold: env.HSM_BREAKER_THRESHOLD,
      breakerCooldownMs: env.HSM_BREAKER_COOLDOWN_MS,
    });
  }
  if (config.NODE_ENV === 'production' || !config.ALLOW_INSECURE_DEVELOPMENT) {
    throw new Error('HSM_ADAPTER=software keeps the evidence key in memory and is refused here: set HSM_ADAPTER=pkcs11, or ALLOW_INSECURE_DEVELOPMENT=true outside production');
  }
  return new SoftwareHsmAdapter();
}
