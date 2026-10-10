import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { redis } from '../db/redis';

/**
 * Throttles credential guessing. Only failed attempts count, so a legitimate
 * backend requesting many tokens is never locked out, and a successful login
 * clears the counter. Each throttle keys on one property of the request
 * (source IP, client_id, username); a route applies several so that neither a
 * single source nor a distributed attack on one account gets far.
 */
export interface ThrottleOptions {
  keyPrefix: string;
  extractKey: (req: Request) => string | null;
  maxFailures: number;
  windowSeconds: number;
  lockoutSeconds: number;
}

export interface LoginThrottle {
  /** Middleware: answers 429 while any key of the request is locked. */
  guard: RequestHandler;
  recordFailure(req: Request): Promise<void>;
  reset(req: Request): Promise<void>;
}

export function loginThrottle(...throttles: ThrottleOptions[]): LoginThrottle {
  const keysOf = (req: Request) => throttles
    .map((t) => ({ t, id: t.extractKey(req) }))
    .filter((k): k is { t: ThrottleOptions; id: string } => k.id !== null)
    .map(({ t, id }) => ({ t, countKey: `${t.keyPrefix}:${id}`, lockKey: `${t.keyPrefix}:${id}:locked` }));

  return {
    guard: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        for (const { t, lockKey } of keysOf(req)) {
          const ttl = await redis.ttl(lockKey);
          if (ttl > 0) {
            res.setHeader('Retry-After', String(ttl));
            res.status(429).json({ error: 'too_many_attempts', retryAfterSeconds: ttl || t.lockoutSeconds });
            return;
          }
        }
        next();
      } catch (error) {
        next(error);
      }
    },
    async recordFailure(req: Request): Promise<void> {
      for (const { t, countKey, lockKey } of keysOf(req)) {
        const result = await redis.multi().incr(countKey).expire(countKey, t.windowSeconds).exec();
        const count = Number(result?.[0]?.[1] ?? 0);
        if (count >= t.maxFailures) await redis.set(lockKey, '1', 'EX', t.lockoutSeconds);
      }
    },
    async reset(req: Request): Promise<void> {
      const keys = keysOf(req).map((k) => k.countKey);
      if (keys.length > 0) await redis.del(...keys);
    },
  };
}

export function byIp(req: Request): string | null { return req.ip ?? null; }

export function byBodyField(field: string) {
  return (req: Request): string | null => {
    const value: unknown = req.body?.[field];
    return typeof value === 'string' && value.length > 0 && value.length <= 256 ? value : null;
  };
}
