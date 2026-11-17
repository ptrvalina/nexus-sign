import { Registry, collectDefaultMetrics, Histogram, Counter, Gauge } from 'prom-client';
import type { NextFunction, Request, Response } from 'express';

export const registry = new Registry();
collectDefaultMetrics({ register: registry });

const httpRequestDuration = new Histogram({
  name: 'nexus_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status_code'] as const,
  buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  registers: [registry],
});

const httpRequestsTotal = new Counter({
  name: 'nexus_http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status_code'] as const,
  registers: [registry],
});

export const webhookDeliveryOutcomes = new Counter({
  name: 'nexus_webhook_delivery_outcomes_total',
  help: 'Webhook delivery attempt outcomes',
  labelNames: ['outcome'] as const, // 'delivered' | 'retried' | 'failed'
  registers: [registry],
});

export const pushDeliveryOutcomes = new Counter({
  name: 'nexus_push_delivery_outcomes_total',
  help: 'Secure push message outcomes by provider',
  labelNames: ['provider', 'outcome'] as const, // provider 'APNS' | 'FCM' | 'none'; outcome 'sent' | 'retried' | 'delivered' | 'failed' | 'expired'
  registers: [registry],
});

/** Confirmed authorizations by method, counted in the confirming
 * transaction (a transaction that then rolls back is still counted). */
export const authorizationConfirmations = new Counter({
  name: 'nexus_authorization_confirmations_total',
  help: 'Authorizations confirmed (VERIFIED), by confirmation method',
  labelNames: ['method'] as const, // 'DEVICE_SIGNATURE' | 'OFFLINE_CODE' | 'OFFLINE_SIGNED'
  registers: [registry],
});

/** Every other end of an authorization, and credential revocations, counted
 * when the outcome is sealed into the evidence chain (once per outcome). */
export const sealedOutcomes = new Counter({
  name: 'nexus_sealed_outcomes_total',
  help: 'Outcomes sealed into the evidence chain: authorization outcomes (REJECTED, CANCELLED, EXPIRED, OFFLINE_UNSIGNED, ...) and credential revocations',
  labelNames: ['subject', 'outcome'] as const,
  registers: [registry],
});

export const unsealedOutcomesGauge = new Gauge({
  name: 'nexus_evidence_unsealed_outcomes',
  help: 'Outcomes recorded but not yet sealed (the HSM was unavailable); set by the expiry sweep',
  registers: [registry],
});

let hsmState: (() => { breaker: 'CLOSED' | 'OPEN' | 'HALF_OPEN'; inFlight: number }) | null = null;

/** The HSM worker host reports its circuit breaker and queue here (selectHsmAdapter). */
export function observeHsm(state: () => { breaker: 'CLOSED' | 'OPEN' | 'HALF_OPEN'; inFlight: number }): void {
  hsmState = state;
}

new Gauge({
  name: 'nexus_hsm_breaker_state',
  help: 'HSM circuit breaker: 0 closed, 1 half-open (probing), 2 open (calls fail closed). Absent with the development adapter',
  registers: [registry],
  collect() {
    if (hsmState) this.set({ CLOSED: 0, HALF_OPEN: 1, OPEN: 2 }[hsmState().breaker]);
  },
});

new Gauge({
  name: 'nexus_hsm_in_flight',
  help: 'PKCS#11 operations queued or running in the HSM worker',
  registers: [registry],
  collect() {
    if (hsmState) this.set(hsmState().inFlight);
  },
});

/**
 * Records duration and count for every request, labeled by route pattern
 * rather than the concrete URL so metric cardinality stays bounded. Requests
 * that matched no route share the single label "unmatched"; labeling them
 * by raw path would let any caller create unlimited series.
 */
export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const start = process.hrtime.bigint();

  res.on('finish', () => {
    const elapsedSeconds = Number(process.hrtime.bigint() - start) / 1e9;
    const route = (req.route as { path?: string } | undefined)?.path ?? 'unmatched';
    const labels = { method: req.method, route, status_code: String(res.statusCode) };
    httpRequestDuration.observe(labels, elapsedSeconds);
    httpRequestsTotal.inc(labels);
  });

  next();
}
