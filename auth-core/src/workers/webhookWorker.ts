import type { Logger } from 'pino';
import { deliverPendingWebhooks } from '../services/webhookService';

const POLL_INTERVAL_MS = 2000;

export interface WebhookWorkerHandle {
  stop: () => void;
}

/**
 * Runs deliverPendingWebhooks() on a fixed interval. The `tick` flag keeps
 * batches from overlapping: if a batch outlasts the poll interval (a slow
 * bank endpoint), the next tick waits for it to finish.
 */
export function startWebhookWorker(logger: Logger): WebhookWorkerHandle {
  let stopped = false;
  let inFlight = false;

  const timer = setInterval(() => {
    if (stopped || inFlight) return;
    inFlight = true;
    deliverPendingWebhooks()
      .catch((error: unknown) => {
        logger.error({ err: error }, 'Webhook delivery batch failed');
      })
      .finally(() => {
        inFlight = false;
      });
  }, POLL_INTERVAL_MS);

  return {
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}
