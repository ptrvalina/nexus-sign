import { Router, type NextFunction, type Request, type Response } from 'express';
import { operatorClaim as claimConversation, operatorClose as closeConversation, operatorMessages as conversationMessages, operatorQueue as conversationQueue, operatorRelease as releaseConversation, operatorSend as answerConversation } from '../services/conversationService';
import { z } from 'zod';
import { login, logout, resolveSession, InvalidAdminCredentialsError } from '../services/adminAuthService';
import { ADMIN_SESSION_COOKIE, getSessionTokenFromRequest, requireAdminSession, requireRole, type AdminRequest } from '../middleware/adminAuth';
import { listBankClients } from '../services/clientService';
import { listAuditLogs, listWebhookDeliveries, getDashboardStats } from '../services/adminService';
import { suspendNexusIdentity } from '../services/nexusIdentityService';
import { decideApproval, identityInScope, listApprovals, requestApproval, type AdminApproval } from '../services/adminApprovalService';
import { recordAuditEvent } from '../services/auditService';
import { setRequestActor } from '../services/requestContext';
import type { AdminSession } from '../services/adminAuthService';
import { byBodyField, byIp, loginThrottle } from '../middleware/bruteForceProtection';
import { assertClaimedBy, claimCall, closeAs, listCalls, operatorSignal, operatorSignals, operatorRelease } from '../services/verificationCall';
import { recordOperatorDecision } from '../services/adaptiveVerificationService';
import { consoleAuthorizations, consoleCancelDeviceRequest, consoleDevices, consoleMandate, consoleMandateAction, consoleMandates, consoleRevokeDevice } from '../services/bankConsoleService';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import * as customerCalls from '../services/customerCallService';

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
// and per username from that address. The account-wide limit stops guessing
// spread across many addresses; while it is hit, only a login that also proves
// TOTP gets through, so strangers cannot lock the operator out (A2-06).
const byUsername = byBodyField('username');
const throttle = loginThrottle(
  { keyPrefix: 'admin_login_failures_ip', extractKey: byIp, maxFailures: 8, windowSeconds: 300, lockoutSeconds: 900 },
  { keyPrefix: 'admin_login_failures_user_ip', extractKey: (req) => { const user = byUsername(req); return user && req.ip ? `${user}|${req.ip}` : null; }, maxFailures: 8, windowSeconds: 300, lockoutSeconds: 900 },
  { keyPrefix: 'admin_login_failures_user', extractKey: byUsername, maxFailures: 50, windowSeconds: 3600, lockoutSeconds: 900, passWithSecondFactor: true },
);

/** Counting failures is part of the protection: if Redis cannot record one,
 * the error is logged and the request fails instead of passing silently (A2-10). */
async function recordThrottleFailure(req: Request): Promise<void> {
  try {
    await throttle.recordFailure(req);
  } catch (error) {
    req.log?.error({ err: error }, 'admin login failure could not be counted');
    throw error;
  }
}

/** Admin session cookie. `Secure` follows ADMIN_COOKIE_SECURE (env.ts),
 * which is on by default and turned off only for local HTTP development. */
function sessionCookieHeader(token: string, maxAgeSeconds: number, secure: boolean): string {
  const attributes = [`${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}`, 'Path=/admin', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSeconds}`];
  if (secure) attributes.push('Secure');
  return attributes.join('; ');
}

/** Refuses cross-site state changes: a browser always sends Origin on a
 * cross-origin POST, and it must name this host. SameSite=Strict
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

export function buildAdminRouter(options: { cookieSecure: boolean; hsm: HsmAdapter }): Router {
  const router = Router();
  router.use('/admin/api', sameOrigin);

  router.post('/admin/api/login', throttle.guard, async (req, res, next) => {
    try {
      const body = loginSchema.parse(req.body);
      const accountLock = await throttle.secondFactorLock(req);
      const outcome = await login(body.username, body.password, body.totp, { requireSecondFactor: accountLock > 0 })
        .catch((error: unknown) => {
          if (error instanceof InvalidAdminCredentialsError) return error;
          throw error;
        });
      if (outcome instanceof InvalidAdminCredentialsError) {
        await recordThrottleFailure(req);
        if (accountLock > 0) {
          res.setHeader('Retry-After', String(accountLock));
          res.status(429).json({ error: 'too_many_attempts', retryAfterSeconds: accountLock });
        } else {
          res.status(401).json({ error: outcome.message });
        }
        return;
      }
      await throttle.reset(req);
      res.setHeader('Set-Cookie', sessionCookieHeader(outcome.sessionToken, 8 * 60 * 60, options.cookieSecure));
      res.status(200).json({ username: outcome.session.username, role: outcome.session.role });
    } catch (error) {
      next(error);
    }
  });

  router.post('/admin/api/logout', async (req, res, next) => {
    try {
      const token = getSessionTokenFromRequest(req);
      if (token) {
        // Logout runs before the session middleware: resolve the session
        // first so the record names who logged out (finding A2-07).
        const session = await resolveSession(token);
        await logout(token);
        if (session) await recordAuditEvent('admin_logout', { actor: `admin:${session.username}`, clientId: session.clientId ?? undefined });
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

  // --- Mandates and devices of one customer (bank staff) ---
  // Auditors and platform operators read; the bank's own operators act.
  const nexusParam = z.string().regex(/^\d{9}$/);
  router.get('/admin/api/identities/:nexusId/authorizations', async (req, res, next) => {
    try {
      const query = z.object({ filter: z.enum(['all', 'confirmed', 'declined', 'open']).default('all'), before: z.string().datetime().optional() }).parse(req.query);
      res.status(200).json({ authorizations: await consoleAuthorizations(sessionOf(req as AdminRequest), nexusParam.parse(req.params.nexusId), query) });
    } catch (error) { next(error); }
  });
  router.get('/admin/api/identities/:nexusId/mandates', async (req, res, next) => {
    try {
      res.status(200).json({ mandates: await consoleMandates(sessionOf(req as AdminRequest), nexusParam.parse(req.params.nexusId)) });
    } catch (error) { next(error); }
  });
  router.get('/admin/api/mandates/:mandateId', async (req, res, next) => {
    try {
      res.status(200).json(await consoleMandate(sessionOf(req as AdminRequest), uuidSchema.parse(req.params.mandateId)));
    } catch (error) { next(error); }
  });
  for (const [path, action] of [['hold', 'HOLD'], ['release', 'RELEASE'], ['withdraw', 'WITHDRAW']] as const) {
    router.post(`/admin/api/mandates/:mandateId/${path}`, requireRole('operator'), async (req, res, next) => {
      try {
        const reason = action === 'RELEASE' ? '' : z.object({ reason: z.string().min(1).max(48) }).parse(req.body).reason;
        res.status(200).json(await consoleMandateAction(options.hsm, sessionOf(req as AdminRequest), uuidSchema.parse(req.params.mandateId), action, reason));
      } catch (error) { next(error); }
    });
  }
  router.get('/admin/api/identities/:nexusId/devices', async (req, res, next) => {
    try {
      res.status(200).json(await consoleDevices(sessionOf(req as AdminRequest), nexusParam.parse(req.params.nexusId)));
    } catch (error) { next(error); }
  });
  router.post('/admin/api/identities/:nexusId/devices/:credentialId/revoke', requireRole('operator'), async (req, res, next) => {
    try {
      const body = z.object({ reason: z.string().min(1).max(48) }).parse(req.body);
      const nexusId = nexusParam.parse(req.params.nexusId); const credentialId = uuidSchema.parse(req.params.credentialId);
      await consoleRevokeDevice(sessionOf(req as AdminRequest), nexusId, credentialId, body.reason);
      res.status(200).json({ nexusId, credentialId, state: 'REVOKED' });
    } catch (error) { next(error); }
  });
  router.post('/admin/api/identities/:nexusId/device-requests/:requestId/cancel', requireRole('operator'), async (req, res, next) => {
    try {
      res.status(200).json(await consoleCancelDeviceRequest(sessionOf(req as AdminRequest), nexusParam.parse(req.params.nexusId), uuidSchema.parse(req.params.requestId)));
    } catch (error) { next(error); }
  });

  // --- Calls the customer started (operators of the bank) ---
  const callOperator = (req: Request) => ({ username: sessionOf(req as AdminRequest).username, clientId: sessionOf(req as AdminRequest).clientId });
  router.get('/admin/api/customer-calls', requireRole('operator'), async (req, res, next) => {
    try { res.status(200).json({ calls: await customerCalls.operatorCallQueue(callOperator(req)) }); } catch (error) { next(error); }
  });
  router.post('/admin/api/customer-calls/:callId/answer', requireRole('operator'), async (req, res, next) => {
    try { res.status(200).json(await customerCalls.operatorAnswer(callOperator(req), uuidSchema.parse(req.params.callId))); } catch (error) { next(error); }
  });
  router.post('/admin/api/customer-calls/:callId/signals', requireRole('operator'), async (req, res, next) => {
    try {
      const body = z.object({ type: z.string(), payload: z.unknown().optional(), messageId: z.string().uuid().optional() }).strict().parse(req.body);
      const sent = await customerCalls.operatorSignal(callOperator(req), uuidSchema.parse(req.params.callId), body.type, body.payload ?? null, body.messageId);
      res.status(sent.duplicate ? 200 : 201).json(sent);
    } catch (error) { next(error); }
  });
  router.get('/admin/api/customer-calls/:callId/signals', requireRole('operator'), async (req, res, next) => {
    try {
      const query = z.object({ after: z.coerce.number().int().nonnegative().default(0), waitMs: z.coerce.number().int().min(0).max(20_000).default(0) }).parse(req.query);
      res.status(200).json(await customerCalls.operatorSignals(callOperator(req), uuidSchema.parse(req.params.callId), query.after, query.waitMs));
    } catch (error) { next(error); }
  });
  router.post('/admin/api/customer-calls/:callId/end', requireRole('operator'), async (req, res, next) => {
    try { res.status(200).json(await customerCalls.operatorEnd(callOperator(req), uuidSchema.parse(req.params.callId))); } catch (error) { next(error); }
  });

  // --- Conversations handed over to a person (operators of the bank) ---
  const conversationOperator = (req: Request) => ({ username: sessionOf(req as AdminRequest).username, clientId: sessionOf(req as AdminRequest).clientId });
  const conversationParam = z.string().uuid();

  router.get('/admin/api/conversations', requireRole('operator'), async (req, res, next) => {
    try { res.json({ conversations: await conversationQueue(conversationOperator(req)) }); } catch (error) { next(error); }
  });
  router.post('/admin/api/conversations/:conversationId/claim', requireRole('operator'), async (req, res, next) => {
    try { res.json(await claimConversation(conversationOperator(req), conversationParam.parse(req.params.conversationId))); } catch (error) { next(error); }
  });
  router.get('/admin/api/conversations/:conversationId/messages', requireRole('operator'), async (req, res, next) => {
    try {
      const after = z.coerce.number().int().min(0).default(0).parse(req.query.after);
      res.json(await conversationMessages(conversationOperator(req), conversationParam.parse(req.params.conversationId), after));
    } catch (error) { next(error); }
  });
  router.post('/admin/api/conversations/:conversationId/messages', requireRole('operator'), async (req, res, next) => {
    try {
      const body = z.object({ body: z.string().min(1).max(4000), clientMessageId: z.string().min(1).max(64).nullable().optional() }).strict().parse(req.body);
      const sent = await answerConversation(conversationOperator(req), conversationParam.parse(req.params.conversationId), body);
      res.status(sent.replayed ? 200 : 201).json(sent);
    } catch (error) { next(error); }
  });
  router.post('/admin/api/conversations/:conversationId/release', requireRole('operator'), async (req, res, next) => {
    try { res.json(await releaseConversation(conversationOperator(req), conversationParam.parse(req.params.conversationId))); } catch (error) { next(error); }
  });
  router.post('/admin/api/conversations/:conversationId/close', requireRole('operator'), async (req, res, next) => {
    try { res.json(await closeConversation(conversationOperator(req), conversationParam.parse(req.params.conversationId))); } catch (error) { next(error); }
  });

  // --- In-app verification calls (ADR 0017) ---
  // An operator of the bank answers the customer's audio or video call in the
  // browser, checks the transaction with the customer and records the result.
  const operatorOf = (req: Request) => ({ username: sessionOf(req as AdminRequest).username, clientId: sessionOf(req as AdminRequest).clientId });
  const callParam = z.string().uuid();

  router.get('/admin/api/verification-calls', requireRole('operator'), async (req, res, next) => {
    try {
      res.status(200).json(await listCalls(operatorOf(req)));
    } catch (error) { next(error); }
  });

  router.post('/admin/api/verification-calls/:sessionId/claim', requireRole('operator'), async (req, res, next) => {
    try {
      res.status(200).json(await claimCall(callParam.parse(req.params.sessionId), operatorOf(req)));
    } catch (error) { next(error); }
  });

  router.post('/admin/api/verification-calls/:sessionId/signals', requireRole('operator'), async (req, res, next) => {
    try {
      const body = z.object({ type: z.string(), payload: z.unknown().optional(), messageId: z.string().uuid().optional() }).strict().parse(req.body);
      const sent = await operatorSignal(callParam.parse(req.params.sessionId), operatorOf(req), body.type, body.payload ?? null, body.messageId);
      res.status(sent.duplicate ? 200 : 201).json(sent);
    } catch (error) { next(error); }
  });

  router.get('/admin/api/verification-calls/:sessionId/signals', requireRole('operator'), async (req, res, next) => {
    try {
      const query = z.object({ after: z.coerce.number().int().nonnegative().default(0), waitMs: z.coerce.number().int().min(0).max(20_000).default(0) }).parse(req.query);
      res.status(200).json(await operatorSignals(callParam.parse(req.params.sessionId), operatorOf(req), query.after, query.waitMs));
    } catch (error) { next(error); }
  });

  /** The operator hangs up without a result: the session is closed, nothing
   * is verified or failed, and the customer is told. */
  router.post('/admin/api/verification-calls/:sessionId/release', requireRole('operator'), async (req, res, next) => {
    try {
      await operatorRelease(callParam.parse(req.params.sessionId), operatorOf(req));
      res.status(204).send();
    } catch (error) { next(error); }
  });

  /** The operator's result. Only the operator who claimed the call decides. */
  router.post('/admin/api/verification-calls/:sessionId/decision', requireRole('operator'), async (req, res, next) => {
    try {
      const sessionId = callParam.parse(req.params.sessionId);
      const body = z.object({ result: z.enum(['VERIFIED', 'FAILED']) }).strict().parse(req.body);
      await assertClaimedBy(sessionId, operatorOf(req));
      let plan: Awaited<ReturnType<typeof recordOperatorDecision>> | undefined;
      await closeAs(sessionId, 'operator', `decided:${body.result}`, async () => { plan = await recordOperatorDecision(sessionId, operatorOf(req), body.result); });
      res.status(200).json(plan);
    } catch (error) { next(error); }
  });

  return router;
}
