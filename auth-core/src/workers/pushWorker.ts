import type { Logger } from 'pino';
import { env } from '../config/env';
import { ApnsSender, FcmSender, type PushSender } from '../services/pushProviders';
import { deliverPendingPushMessages, reportPushTimeouts, type PushSenders } from '../services/pushService';

const POLL_INTERVAL_MS = 1000;

export interface PushWorkerHandle {
  stop: () => void;
}

/** The providers configured in the environment (see productionPosture.configurationErrors). */
export function configuredPushSenders(): PushSenders {
  const senders: PushSenders = {};
  if (env.APNS_TEAM_ID && env.APNS_KEY_ID && env.APNS_PRIVATE_KEY_PEM && env.APNS_TOPIC) {
    senders.APNS = new ApnsSender(env.APNS_TEAM_ID, env.APNS_KEY_ID, env.APNS_PRIVATE_KEY_PEM, env.APNS_TOPIC,
      { title: env.PUSH_ALERT_TITLE, body: env.PUSH_ALERT_BODY });
  }
  if (env.FCM_PROJECT_ID && env.FCM_SERVICE_ACCOUNT_JSON) {
    senders.FCM = new FcmSender(env.FCM_PROJECT_ID, env.FCM_SERVICE_ACCOUNT_JSON);
  }
  return senders;
}

/**
 * Delivers queued push messages and reports authorization pushes that were
 * not received in time. Polls more often than the webhook worker: an
 * authorization request is useful only within its short validity. Batches
 * never overlap, as in webhookWorker.ts.
 */
export function startPushWorker(logger: Logger): PushWorkerHandle | null {
  if (!env.PUSH_DELIVERY_ENABLED) return null;
  const senders = configuredPushSenders();
  logger.info({ providers: Object.keys(senders) }, 'Secure push delivery enabled');
  let stopped = false;
  let inFlight = false;

  const timer = setInterval(() => {
    if (stopped || inFlight) return;
    inFlight = true;
    deliverPendingPushMessages(senders)
      .then(() => reportPushTimeouts())
      .catch((error: unknown) => {
        logger.error({ err: error }, 'Push delivery batch failed');
      })
      .finally(() => {
        inFlight = false;
      });
  }, POLL_INTERVAL_MS);

  return {
    stop: () => {
      stopped = true;
      clearInterval(timer);
      for (const sender of Object.values(senders) as PushSender[]) sender.close();
    },
  };
}
