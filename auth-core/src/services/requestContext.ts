import { AsyncLocalStorage } from 'node:async_hooks';
import type { NextFunction, Request, Response } from 'express';

/**
 * Who is behind the current HTTP request, for audit records. Set once per
 * request and refined by the authentication middleware, so every audit event
 * written while handling the request carries the source address, user agent,
 * acting party and bank without each call site passing them.
 */
export interface RequestContext {
  ipAddress?: string;
  userAgent?: string;
  /** `bank:<clientId>`, `device:<credentialId>` or `admin:<username>`. */
  actor?: string;
  /** The bank client the request is made for, when known. */
  clientId?: string;
}

const storage = new AsyncLocalStorage<RequestContext>();

export function requestContextMiddleware(req: Request, _res: Response, next: NextFunction): void {
  storage.run({ ipAddress: req.ip, userAgent: req.header('user-agent')?.slice(0, 512) }, next);
}

export function currentRequestContext(): RequestContext | undefined {
  return storage.getStore();
}

/** Records the authenticated party for the rest of the request. */
export function setRequestActor(actor: string, clientId?: string): void {
  const context = storage.getStore();
  if (!context) return;
  context.actor = actor;
  if (clientId) context.clientId = clientId;
}
