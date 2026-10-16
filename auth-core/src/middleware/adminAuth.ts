import type { NextFunction, Request, Response } from 'express';
import { resolveSession, roleAtLeast, type AdminRole, type AdminSession } from '../services/adminAuthService';

export const ADMIN_SESSION_COOKIE = 'nexus_admin_session';

export interface AdminRequest extends Request {
  adminSession?: AdminSession;
}

/** Minimal parser for the one cookie this service sets, avoiding a
 * `cookie-parser` dependency. Request cookie headers are `key=value` pairs
 * separated by `; `. A Map keeps cookie names out of object properties. */
function parseCookies(header: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!header) return cookies;
  for (const pair of header.split(';')) {
    const separatorIndex = pair.indexOf('=');
    if (separatorIndex === -1) continue;
    const key = pair.slice(0, separatorIndex).trim();
    const value = pair.slice(separatorIndex + 1).trim();
    if (!key) continue;
    try {
      cookies.set(key, decodeURIComponent(value));
    } catch {
      // A malformed escape is ignored like an absent cookie.
    }
  }
  return cookies;
}

export function getSessionTokenFromRequest(req: Request): string | null {
  return parseCookies(req.header('cookie')).get(ADMIN_SESSION_COOKIE) ?? null;
}

/** Requires a valid admin session and attaches it to `req.adminSession`.
 * Does not check the role; combine with `requireRole`. */
export async function requireAdminSession(req: AdminRequest, res: Response, next: NextFunction): Promise<void> {
  try {
    const token = getSessionTokenFromRequest(req);
    const session = token ? await resolveSession(token) : null;
    if (!session) {
      res.status(401).json({ error: 'Not logged in, or session expired' });
      return;
    }
    req.adminSession = session;
    next();
  } catch (error) {
    next(error);
  }
}

/** Requires the session (already attached by requireAdminSession) to
 * carry at least the given role. Must run after requireAdminSession in
 * the middleware chain. */
export function requireRole(minimum: AdminRole) {
  return (req: AdminRequest, res: Response, next: NextFunction): void => {
    if (!req.adminSession || !roleAtLeast(req.adminSession.role, minimum)) {
      res.status(403).json({ error: `This action requires the '${minimum}' role or higher` });
      return;
    }
    next();
  };
}
