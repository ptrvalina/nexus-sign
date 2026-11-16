import type { Logger } from 'pino';
import { env } from '../config/env';
import { expireOverdueAuthorizations, expireOverdueVerificationSessions, purgeExpiredDeviceNonces } from '../services/authorizationExpiry';
import { expireUnsignedOfflineConfirmations } from '../services/authorizationConfirmation';
import { sealPendingOutcomes, unsealedOutcomes } from '../services/evidenceService';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { expireMandates } from '../services/mandateService';
import { expireCustomerCalls } from '../services/customerCallService';

/** An outcome not sealed after this long is reported on every sweep. */
const UNSEALED_WARNING_SECONDS = 300;

export interface ExpiryWorkerHandle {
  stop: () => void;
}

/**
 * Sweeps authorizations whose expiry has passed, verification
 * sessions nobody completed, offline confirmations whose device signature can
 * no longer arrive and expired device request nonces, every
 * AUTHORIZATION_EXPIRY_SWEEP_MS, and seals recorded outcomes into the
 * evidence chains. Several Auth Core instances can run it at
 * once: rows are claimed with FOR UPDATE SKIP LOCKED.
 */
export function startExpiryWorker(logger: Logger, hsm: HsmAdapter): ExpiryWorkerHandle {
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
        const unsigned = await expireUnsignedOfflineConfirmations();
        if (unsigned > 0) logger.warn({ count: unsigned }, 'Offline confirmations without a device signature (OFFLINE_UNSIGNED)');
        if (env.DEVICE_NONCE_STORE === 'postgres') await purgeExpiredDeviceNonces();
        // Mandate offers nobody signed and mandates past their validity.
        const mandates = await expireMandates(hsm);
        if (mandates > 0) logger.info({ count: mandates }, 'Expired payment mandates');
        // Calls nobody answered, calls past their longest duration, and calls of a revoked device or suspended identity.
        const calls = await expireCustomerCalls();
        if (calls > 0) logger.info({ count: calls }, 'Closed customer calls');
        // Outcomes the state changes above (and every other path) recorded
        // are sealed into the evidence chains (audit finding B-04).
        const outcomes = await sealPendingOutcomes(hsm);
        if (outcomes > 0) logger.info({ count: outcomes }, 'Sealed authorization and credential outcomes');
        const backlog = await unsealedOutcomes();
        if (backlog.count > 0 && backlog.oldestSeconds > UNSEALED_WARNING_SECONDS) {
          logger.error({ count: backlog.count, oldestSeconds: backlog.oldestSeconds }, 'Outcomes are waiting to be sealed (HSM unavailable?)');
        }
      })
      .catch((error: unknown) => { logger.error({ err: error }, 'Authorization expiry sweep failed'); })
      .finally(() => { inFlight = false; });
  }, env.AUTHORIZATION_EXPIRY_SWEEP_MS);
  return { stop: () => { stopped = true; clearInterval(timer); } };
}
