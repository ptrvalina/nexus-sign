import express, { Router, type Response } from 'express';
import { z } from 'zod';
import { certificateMatches, getClientRecord, verifyClientCredentials, InvalidClientSecretError } from '../services/clientService';
import { env } from '../config/env';
import { recordAuditEvent } from '../services/auditService';
import type { GatewayRequest } from '../middleware/mtlsGateway';
import { issueToken } from '../services/tokenService';
import { byIp, loginThrottle } from '../middleware/bruteForceProtection';

const tokenRequestSchema = z.object({
  grant_type: z.literal('client_credentials'),
  client_id: z.string().min(1).max(128),
  client_secret: z.string().min(1).max(256),
});

// Client secrets are 256-bit random values, so online guessing is not a
// realistic threat; the throttle limits abuse per source address. No
// per-client_id lockout: anyone could otherwise lock a bank out of token
// issuance by sending bad secrets for its client_id.
const throttle = loginThrottle({
  keyPrefix: 'oauth_token_failures_ip',
  extractKey: byIp,
  maxFailures: 20,
  windowSeconds: 300,
  lockoutSeconds: 900,
});

/** RFC 6749 §5.2 error response. */
function oauthError(res: Response, status: number, error: 'invalid_request' | 'invalid_client' | 'unsupported_grant_type', description?: string): void {
  res.setHeader('Cache-Control', 'no-store');
  res.status(status).json({ error, ...(description ? { error_description: description } : {}) });
}

export function buildOAuthRouter(): Router {
  const router = Router();

  /**
   * OAuth 2.0 client credentials grant (RFC 6749 §4.4). Accepts the standard
   * application/x-www-form-urlencoded body, and JSON with the same field
   * names. Credentials may also be sent with HTTP Basic authentication.
   */
  router.post('/oauth/token', express.urlencoded({ extended: false, limit: '4kb' }), throttle.guard, async (req, res, next) => {
    try {
      const basic = /^Basic\s+(.+)$/i.exec(req.header('authorization') ?? '')?.[1];
      const fromBasic = basic ? decodeBasicCredentials(basic) : null;
      const input = {
        ...req.body,
        ...(fromBasic && fromBasic.length >= 2
          ? { client_id: fromBasic[0], client_secret: fromBasic.slice(1).join(':') }
          : {}),
      };
      if (input.grant_type !== undefined && input.grant_type !== 'client_credentials') {
        oauthError(res, 400, 'unsupported_grant_type');
        return;
      }
      const parsed = tokenRequestSchema.safeParse(input);
      if (!parsed.success) {
        oauthError(res, 400, 'invalid_request', 'grant_type, client_id and client_secret are required');
        return;
      }
      const clientId = parsed.data.client_id;
      await verifyClientCredentials(clientId, parsed.data.client_secret);
      // The secret alone is not enough: the request must come over the
      // gateway connection authenticated with one of this bank's certificates.
      const certificate = (req as GatewayRequest).clientCertificateSha256 ?? null;
      if (env.REQUIRE_MTLS_HEADER && !certificateMatches(await getClientRecord(clientId), certificate)) {
        await recordAuditEvent('bank_certificate_mismatch', { clientId, actor: `bank:${clientId}` }, { stage: 'token', certificateSha256: certificate });
        oauthError(res, 401, 'invalid_client');
        return;
      }
      await throttle.reset(req);
      const token = await issueToken(clientId);
      await recordAuditEvent('oauth_token_issued', { clientId, actor: `bank:${clientId}` }, { expiresIn: token.expiresIn, certificateSha256: certificate });
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json({
        access_token: token.accessToken,
        token_type: token.tokenType,
        expires_in: token.expiresIn,
      });
    } catch (error) {
      if (error instanceof InvalidClientSecretError) {
        await throttle.recordFailure(req).catch(() => undefined);
        // The claimed client_id is unverified: details only, not the client column.
        await recordAuditEvent('oauth_token_rejected', {}, { claimedClientId: String(req.body?.client_id ?? '').slice(0, 128) }).catch(() => undefined);
        oauthError(res, 401, 'invalid_client');
        return;
      }
      next(error);
    }
  });

  return router;
}

/** RFC 6749 section 2.3.1: both parts are form-urlencoded. A malformed escape
 * yields no credentials, which is answered as invalid_client. */
function decodeBasicCredentials(encoded: string): string[] | null {
  try {
    return Buffer.from(encoded, 'base64').toString('utf8').split(':').map((part) => decodeURIComponent(part));
  } catch {
    return null;
  }
}
