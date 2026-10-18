import express, { type Express } from 'express';
import path from 'node:path';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import helmet from 'helmet';
import pinoHttp from 'pino-http';
import type { Logger } from 'pino';
import type { HsmAdapter } from './crypto/hsmAdapter';
import { authenticateBankClient } from './middleware/auth';
import { normalizeIp, requireGatewayMtls } from './middleware/mtlsGateway';
import { errorHandler } from './middleware/errorHandler';
import { buildRecoveryRouter } from './routes/recovery';
import { buildNexusV1Router } from './routes/nexusV1';
import { buildMobileV1Router } from './routes/mobileV1';
import { buildOAuthRouter } from './routes/oauth';
import { buildAdminRouter } from './routes/admin';
import { env } from './config/env';
import { pool } from './db/pool';
import { redis } from './db/redis';
import { registry, metricsMiddleware } from './observability/metrics';
import { configureEvidenceKeyring } from './services/credentialIntegrity';
import { requestContextMiddleware } from './services/requestContext';

const HSM_READINESS_INTERVAL_MS = 30_000;

/** Runs `check` at most once per interval; a failure is not cached. */
function cachedCheck(check: () => Promise<void>, intervalMs: number): () => Promise<void> {
  let passedAt = 0;
  return async () => {
    if (Date.now() - passedAt < intervalMs) return;
    await check();
    passedAt = Date.now();
  };
}

export function buildApp(hsmAdapter: HsmAdapter, logger: Logger): Express {
  configureEvidenceKeyring(hsmAdapter);
  const app = express();

  app.disable('x-powered-by');
  if (env.TRUSTED_PROXY_IPS.length > 0) {
    // Dual-stack sockets report IPv4 peers as ::ffff:a.b.c.d; without
    // normalising, the gateway would not be trusted and every client would
    // share the gateway's address (and its rate limits) (NXS-029).
    const trusted = env.TRUSTED_PROXY_IPS.map(normalizeIp);
    app.set('trust proxy', (ip: string) => trusted.includes(normalizeIp(ip) ?? ''));
  }
  app.use(helmet());
  // The raw bytes are kept for device-signed mobile requests, whose signature
  // covers the body exactly as sent.
  app.use(express.json({
    limit: '32kb',
    verify: (req, _res, buf) => { (req as { rawBody?: Buffer }).rawBody = Buffer.from(buf); },
  }));

  // Reuses a caller-supplied correlation ID (a bank backend tracing one
  // operation across both systems) or mints one, and echoes it back.
  app.use(pinoHttp({
    logger,
    genReqId: (req, res) => {
      const existing = req.headers['x-correlation-id'] ?? req.headers['x-request-id'];
      const id = (Array.isArray(existing) ? existing[0] : existing) ?? randomUUID();
      res.setHeader('X-Correlation-Id', id);
      return id;
    },
  }));
  // Source address and user agent for audit records. Registered after body
  // parsing, whose stream callbacks would not carry the async context.
  app.use(requestContextMiddleware);

  // Liveness: the process is up. Touches no dependency and must stay fast and
  // unauthenticated for load balancer and Kubernetes probes.
  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // Readiness: the dependencies a request needs are reachable. Separate from
  // liveness so a transient outage takes the pod out of routing without
  // restarting it. The HSM self-test signs a probe, so its result is reused
  // for HSM_READINESS_INTERVAL_MS.
  const hsmReadiness = cachedCheck(() => hsmAdapter.healthCheck(), HSM_READINESS_INTERVAL_MS);
  app.get('/readyz', async (_req, res) => {
    try {
      await pool.query('SELECT 1');
      await redis.ping();
      await hsmReadiness();
      res.status(200).json({ status: 'ready' });
    } catch (error) {
      logger.warn({ err: error }, 'Readiness check failed');
      res.status(503).json({ status: 'not ready' });
    }
  });

  app.use(requireGatewayMtls);

  app.get('/metrics', async (req, res) => {
    // FI-030: with METRICS_BEARER_TOKEN set, only the monitoring system reads
    // metrics, not every client behind the gateway.
    if (env.METRICS_BEARER_TOKEN) {
      const given = Buffer.from(req.header('authorization') ?? '', 'utf8');
      const expected = Buffer.from(`Bearer ${env.METRICS_BEARER_TOKEN}`, 'utf8');
      if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
        res.status(401).json({ error: 'Metrics need the monitoring token' });
        return;
      }
    }
    res.setHeader('Content-Type', registry.contentType);
    res.send(await registry.metrics());
  });

  // Administrative interface uses its own session cookie. The trusted gateway
  // protects the route in production; administrative API methods enforce the
  // session and role checks independently.
  app.use('/admin', express.static(path.join(process.cwd(), 'public', 'admin')));
  app.use(buildAdminRouter({ cookieSecure: env.ADMIN_COOKIE_SECURE }));

  app.use(metricsMiddleware);

  // OAuth client-credentials issuance is authenticated at the gateway and rate-limited at the application layer.
  app.use(buildOAuthRouter());

  app.use(buildMobileV1Router(hsmAdapter));
  app.use(buildRecoveryRouter(hsmAdapter));
  app.use(authenticateBankClient);
  app.use(buildNexusV1Router(hsmAdapter));

  app.use(errorHandler(logger));

  return app;
}
