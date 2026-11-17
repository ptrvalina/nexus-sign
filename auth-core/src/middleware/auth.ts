import type { NextFunction, Response } from 'express';
import { resolveToken } from '../services/tokenService';
import { env } from '../config/env';
import type { GatewayRequest } from './mtlsGateway';
import { recordAuditEvent } from '../services/auditService';
import { setRequestActor } from '../services/requestContext';

/**
 * Authenticates the calling bank backend with an OAuth 2.0 Client Credentials
 * access token issued by POST /oauth/token (src/routes/oauth.ts). The token is
 * opaque and meaningful only to this Auth Core deployment (tokenService.ts).
 */
export interface AuthenticatedRequest extends GatewayRequest {
  bankClientId?: string;
}

/**
 * With REQUIRE_MTLS_HEADER the token must also match the client certificate
 * the gateway verified.
 */
export async function authenticateBankClient(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
  try {
    const match = /^Bearer (?<token>.+)$/.exec(req.header('authorization') ?? '');
    const resolution = match?.groups?.token
      ? await resolveToken(match.groups.token, env.REQUIRE_MTLS_HEADER ? (req.clientCertificateSha256 ?? null) : undefined)
      : { clientId: null, outcome: 'invalid' as const };

    if (resolution.outcome === 'certificate_mismatch') {
      await recordAuditEvent('bank_certificate_mismatch', { clientId: resolution.clientId, actor: `bank:${resolution.clientId}` },
        { stage: 'api', certificateSha256: req.clientCertificateSha256 ?? null, path: req.path });
    }
    if (resolution.outcome !== 'ok') {
      res.status(401).json({ error: 'Missing, expired, or invalid access token' });
      return;
    }

    req.bankClientId = resolution.clientId;
    setRequestActor(`bank:${resolution.clientId}`, resolution.clientId);
    next();
  } catch (error) {
    // Express does not await middleware, so a rejected promise would become an
    // unhandled rejection instead of a 500; pass it to the error pipeline.
    next(error);
  }
}
