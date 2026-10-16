import Redis from 'ioredis';
import { env } from '../config/env';

const tlsRequired = env.REDIS_TLS_REQUIRED || env.NODE_ENV === 'production';

export const redis = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: 2,
  enableReadyCheck: true,
  ...(tlsRequired ? { tls: { rejectUnauthorized: true } } : {}),
});
