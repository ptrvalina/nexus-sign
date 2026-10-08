import pino from 'pino';
import { env } from './config/env';
import { configurationErrors, insecureDevelopmentSettings, productionBlockers } from './config/productionPosture';
import { buildApp } from './app';
import { pool } from './db/pool';
import { redis } from './db/redis';
import { selectHsmAdapter } from './crypto/selectHsmAdapter';
import { startWebhookWorker } from './workers/webhookWorker';
import { startPushWorker } from './workers/pushWorker';

const logger = pino({
  level: env.NODE_ENV === 'production' ? 'info' : 'debug',
  // Bodies are not logged. Credentials in headers (bank and mobile bearer
  // tokens, Basic client secrets, the admin cookie) are removed from the
  // request log entries written by pino-http.
  redact: {
    paths: [
      'req.body',
      'res.body',
      'req.headers.authorization',
      'req.headers.cookie',
      'req.headers["x-nexus-signature"]',
      'res.headers["set-cookie"]',
    ],
    censor: '[redacted]',
  },
});

function assertStartupConfiguration(): void {
  const errors = configurationErrors(env);
  if (errors.length > 0) throw new Error(errors.join('; '));
  const blockers = productionBlockers(env);
  if (blockers.length > 0) {
    throw new Error(`Production security posture is not acceptable:\n- ${blockers.join('\n- ')}`);
  }
  const insecure = insecureDevelopmentSettings(env);
  if (insecure.length > 0) {
    logger.warn({ insecureSettings: insecure, env: env.NODE_ENV },
      'Running WITHOUT production security controls (ALLOW_INSECURE_DEVELOPMENT=true); never use this configuration with real customers');
  }
}

// A failed promise outside the request pipeline is logged instead of
// terminating the process for all clients.
process.on('unhandledRejection', (reason: unknown) => {
  logger.error({ err: reason }, 'Unhandled promise rejection');
});

async function main(): Promise<void> {
  assertStartupConfiguration();
  const hsmAdapter = await selectHsmAdapter();
  await hsmAdapter.healthCheck();
  logger.info({ hsmAdapter: hsmAdapter.name, env: env.NODE_ENV }, 'Starting NEXUS-SIGN Auth Core');

  await pool.query('SELECT 1'); // fail fast if Postgres is unreachable
  await redis.ping(); // fail fast if Redis is unreachable

  const app = buildApp(hsmAdapter, logger);
  const server = app.listen(env.PORT, () => {
    logger.info({ port: env.PORT }, 'Auth Core listening');
  });

  const webhookWorker = startWebhookWorker(logger);
  const pushWorker = startPushWorker(logger);

  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, 'Shutting down');
    webhookWorker.stop();
    pushWorker?.stop();
    server.close();
    await hsmAdapter.close?.();
    await pool.end();
    redis.disconnect();
    process.exit(0);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((error: unknown) => {
  logger.fatal({ err: error }, 'Fatal error during startup');
  process.exit(1);
});
