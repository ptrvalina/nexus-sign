import { Registry, collectDefaultMetrics, Histogram, Counter } from 'prom-client';
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
