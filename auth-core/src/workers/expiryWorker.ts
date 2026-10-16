import type { Logger } from 'pino';
import { env } from '../config/env';
import { expireOverdueAuthorizations, expireOverdueVerificationSessions } from '../services/authorizationExpiry';

export interface ExpiryWorkerHandle {
  stop: () => void;
}

/**
 * Sweeps authorizations whose expiry has passed (FI-013), and verification
 * sessions nobody completed, every
 * AUTHORIZATION_EXPIRY_SWEEP_MS. Several Auth Core instances can run it at
 * once: rows are claimed with FOR UPDATE SKIP LOCKED.
 */
export function startExpiryWorker(logger: Logger): ExpiryWorkerHandle {
  let stopped = false;
  let inFlight = false;
  const timer = setInterval(() => {
    if (stopped || inFlight) return;
    inFlight = true;
    expireOverdueAuthorizations()
      .then(async (count) => {
        if (count > 0) logger.info({ count }, 'Expired overdue authorizations');
        const sessions = await expireOverdueVerificationSessions();
        if (sessions > 0) logger.info({ count: sessions }, 'Expired unanswered verification sessions');
      })
      .catch((error: unknown) => { logger.error({ err: error }, 'Authorization expiry sweep failed'); })
      .finally(() => { inFlight = false; });
  }, env.AUTHORIZATION_EXPIRY_SWEEP_MS);
  return { stop: () => { stopped = true; clearInterval(timer); } };
}
