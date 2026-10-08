import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { login, logout, InvalidAdminCredentialsError } from '../services/adminAuthService';
import { ADMIN_SESSION_COOKIE, getSessionTokenFromRequest, requireAdminSession, requireRole, type AdminRequest } from '../middleware/adminAuth';
import { listBankClients } from '../services/clientService';
import { listAuditLogs, listWebhookDeliveries, getDashboardStats } from '../services/adminService';
import { suspendNexusIdentity } from '../services/nexusIdentityService';
import { decideApproval, identityInScope, listApprovals, requestApproval, type AdminApproval } from '../services/adminApprovalService';
import { recordAuditEvent } from '../services/auditService';
import { setRequestActor } from '../services/requestContext';
import type { AdminSession } from '../services/adminAuthService';
import { byBodyField, byIp, loginThrottle } from '../middleware/bruteForceProtection';

const loginSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(256),
  totp: z.string().regex(/^\d{6}$/).optional(),
});

const auditLogQuerySchema = z.object({
  nexusId: z.string().regex(/^\d{9}$/).optional(),
  eventType: z.string().optional(),
  limit: z.coerce.number().int().positive().max(500).default(100),
  before: z.coerce.date().optional(),
});

const webhookQuerySchema = z.object({
  status: z.enum(['PENDING', 'DELIVERED', 'FAILED']).optional(),
  limit: z.coerce.number().int().positive().max(500).default(100),
});

const reasonSchema = z.object({ reason: z.string().min(1).max(256) });
const approvalQuerySchema = z.object({ status: z.enum(['PENDING', 'EXECUTED', 'REJECTED', 'EXPIRED']).default('PENDING') });
const uuidSchema = z.string().uuid();

const sessionOf = (req: AdminRequest): AdminSession => req.adminSession!;

function approvalJson(a: AdminApproval) {
  return { ...a, requestedAt: a.requestedAt.toISOString(), expiresAt: a.expiresAt.toISOString(), decidedAt: a.decidedAt?.toISOString() ?? null };
}

// Admin passwords are human-chosen. Failures are throttled per source address
// and per username from that address; the account-wide limit is high enough
// that a stranger cannot lock an operator out with a few wrong passwords, and
// still stops guessing spread across many addresses.
const byUsername = byBodyField('username');
const throttle = loginThrottle(
  { keyPrefix: 'admin_login_failures_ip', extractKey: byIp, maxFailures: 8, windowSeconds: 300, lockoutSeconds: 900 },
  { keyPrefix: 'admin_login_failures_user_ip', extractKey: (req) => { const user = byUsername(req); return user && req.ip ? `${user}|${req.ip}` : null; }, maxFailures: 8, windowSeconds: 300, lockoutSeconds: 900 },
  { keyPrefix: 'admin_login_failures_user', extractKey: byUsername, maxFailures: 50, windowSeconds: 3600, lockoutSeconds: 900 },
);

/** Admin session cookie. `Secure` follows ADMIN_COOKIE_SECURE (env.ts),
 * which is on by default and turned off only for local HTTP development. */
function sessionCookieHeader(token: string, maxAgeSeconds: number, secure: boolean): string {
  const attributes = [`${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}`, 'Path=/admin', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSeconds}`];
  if (secure) attributes.push('Secure');
  return attributes.join('; ');
}

/** Refuses cross-site state changes: a browser always sends Origin on a
 * cross-origin POST, and it must name this host (NXS-032). SameSite=Strict
 * on the cookie is the first layer. */
function sameOrigin(req: Request, res: Response, next: NextFunction): void {
  const origin = req.header('origin');
  if (req.method !== 'GET' && req.method !== 'HEAD' && origin !== undefined) {
    let host: string | null = null;
    try { host = new URL(origin).host; } catch { host = null; }
    if (host === null || host !== req.header('host')) {
      res.status(403).json({ error: 'Cross-origin request refused' });
      return;
    }
  }
  next();
}

export function buildAdminRouter(options: { cookieSecure: boolean }): Router {
  const router = Router();
  router.use('/admin/api', sameOrigin);

  router.post('/admin/api/login', throttle.guard, async (req, res, next) => {
    try {
      const body = loginSchema.parse(req.body);
      const { sessionToken, session } = await login(body.username, body.password, body.totp);
      await throttle.reset(req);
      res.setHeader('Set-Cookie', sessionCookieHeader(sessionToken, 8 * 60 * 60, options.cookieSecure));
      res.status(200).json({ username: session.username, role: session.role });
    } catch (error) {
      if (error instanceof InvalidAdminCredentialsError) {
        await throttle.recordFailure(req).catch(() => undefined);
        res.status(401).json({ error: error.message });
        return;
      }
      next(error);
    }
  });

  router.post('/admin/api/logout', async (req, res, next) => {
    try {
      const token = getSessionTokenFromRequest(req);
      if (token) {
        await logout(token);
        await recordAuditEvent('admin_logout', {});
      }
      res.setHeader('Set-Cookie', sessionCookieHeader('', 0, options.cookieSecure));
      res.status(200).json({ ok: true });
    } catch (error) {
      next(error);
    }
  });

  // Everything below requires a valid session.
  router.use('/admin/api', requireAdminSession, (req: AdminRequest, _res, next) => {
    setRequestActor(`admin:${sessionOf(req).username}`);
    next();
  });

  router.get('/admin/api/me', (req: AdminRequest, res) => {
    res.status(200).json(req.adminSession);
  });

  // A bank-scoped admin sees only that bank's data in every listing below.
  router.get('/admin/api/stats', async (req: AdminRequest, res, next) => {
    try {
      res.status(200).json(await getDashboardStats(sessionOf(req).clientId));
    } catch (error) {
      next(error);
    }
  });

  router.get('/admin/api/clients', async (req: AdminRequest, res, next) => {
    try {
      const scope = sessionOf(req).clientId;
      const clients = (await listBankClients()).filter((c) => scope === null || c.clientId === scope);
      res.status(200).json(clients.map((c) => ({ ...c, createdAt: c.createdAt.toISOString(), updatedAt: c.updatedAt.toISOString() })));
    } catch (error) {
      next(error);
    }
  });

  router.get('/admin/api/audit-logs', async (req, res, next) => {
    try {
      const query = auditLogQuerySchema.parse(req.query);
      const logs = await listAuditLogs({ ...query, clientId: sessionOf(req as AdminRequest).clientId });
      // Audit records carry bank customer references (personal data).
      await recordAuditEvent('admin_audit_log_viewed', { nexusId: query.nexusId }, { eventType: query.eventType ?? null, returned: logs.length });
      res.status(200).json(logs.map((log) => ({ ...log, timestamp: log.timestamp.toISOString() })));
    } catch (error) {
      next(error);
    }
  });

  router.get('/admin/api/webhook-deliveries', async (req, res, next) => {
    try {
      const query = webhookQuerySchema.parse(req.query);
      const deliveries = await listWebhookDeliveries(query.limit, query.status, sessionOf(req as AdminRequest).clientId);
      res.status(200).json(
        deliveries.map((d) => ({
          ...d,
          createdAt: d.createdAt.toISOString(),
          deliveredAt: d.deliveredAt?.toISOString() ?? null,
        })),
      );
    } catch (error) {
      next(error);
    }
  });

  router.get('/admin/api/identities/:nexusId', async (req, res, next) => {
    try {
      const nexusId = z.string().regex(/^\d{9}$/).parse(req.params.nexusId);
      const identity = await identityInScope(sessionOf(req as AdminRequest), nexusId);
      await recordAuditEvent('admin_identity_viewed', { nexusId });
      res.status(200).json({
        nexusId: identity.nexusId,
        clientId: identity.clientId,
        bankCustomerRef: identity.bankCustomerRef,
        status: identity.status,
        createdAt: identity.createdAt.toISOString(),
        lastUsedAt: identity.lastUsedAt?.toISOString() ?? null,
      });
    } catch (error) {
      next(error);
    }
  });

  // State changes require at least the 'operator' role; auditors are read-only.
  // Revocation and reactivation wait for a second admin (adminApprovalService.ts).
  for (const [path, action] of [['revoke', 'REVOKE'], ['reactivate', 'REACTIVATE']] as const) {
    router.post(`/admin/api/identities/:nexusId/${path}`, requireRole('operator'), async (req, res, next) => {
      try {
        const nexusId = z.string().regex(/^\d{9}$/).parse(req.params.nexusId);
        const body = reasonSchema.parse(req.body);
        const approval = await requestApproval(sessionOf(req as AdminRequest), action, nexusId, body.reason);
        res.status(202).json(approvalJson(approval));
      } catch (error) {
        next(error);
      }
    });
  }

  router.post('/admin/api/identities/:nexusId/suspend', requireRole('operator'), async (req, res, next) => {
    try {
      const nexusId = z.string().regex(/^\d{9}$/).parse(req.params.nexusId);
      const body = reasonSchema.parse(req.body);
      await identityInScope(sessionOf(req as AdminRequest), nexusId);
      await suspendNexusIdentity(nexusId, body.reason, `admin:${sessionOf(req as AdminRequest).username}`);
      res.status(200).json({ nexusId, status: 'SUSPENDED' });
    } catch (error) {
      next(error);
    }
  });

  router.get('/admin/api/approvals', async (req: AdminRequest, res, next) => {
    try {
      const query = approvalQuerySchema.parse(req.query);
      res.status(200).json((await listApprovals(sessionOf(req), query.status)).map(approvalJson));
    } catch (error) {
      next(error);
    }
  });

  for (const [path, decision] of [['approve', 'APPROVE'], ['reject', 'REJECT']] as const) {
    router.post(`/admin/api/approvals/:approvalId/${path}`, requireRole('operator'), async (req, res, next) => {
      try {
        const approvalId = uuidSchema.parse(req.params.approvalId);
        res.status(200).json(approvalJson(await decideApproval(sessionOf(req as AdminRequest), approvalId, decision)));
      } catch (error) {
        next(error);
      }
    });
  }

  return router;
}
