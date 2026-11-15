import type { NextFunction, Request, Response } from 'express';
import { env } from '../config/env';

/**
 * The bank's API gateway normally terminates client mTLS. Auth Core verifies
 * the gateway's verified-client-certificate header, and accepts it only from
 * a configured trusted proxy address, so an Internet caller cannot spoof it.
 *
 * Endpoints called directly by the embedded mobile SDK are exempt: a
 * customer's phone never holds the bank's gateway client certificate, so
 * those endpoints are authenticated by device request signatures instead
 * (or, for enrolment, a single-use BOOTSTRAP token). The exemption is an explicit allow-list of
 * device routes, matched case-insensitively because Express routing is
 * case-insensitive; the bank-facing /v1/mobile/sessions is never exempt.
 */
const DEVICE_ROUTES: ReadonlyArray<{ method: string; pattern: RegExp }> = [
  { method: 'POST', pattern: /^\/v1\/mobile\/bootstrap\/?$/i },
  { method: 'GET', pattern: /^\/v1\/mobile\/recovery\/setup\/?$/i },
  { method: 'POST', pattern: /^\/v1\/mobile\/recovery\/setup\/?$/i },
  { method: 'GET', pattern: /^\/v1\/mobile\/authorizations\/[^/]+\/?$/i },
  { method: 'GET', pattern: /^\/v1\/mobile\/authorizations\/[^/]+\/verification-plan\/?$/i },
  { method: 'POST', pattern: /^\/v1\/mobile\/authorizations\/[^/]+\/verification\/escalate\/?$/i },
  { method: 'POST', pattern: /^\/v1\/mobile\/authorizations\/[^/]+\/verification-sessions\/?$/i },
  { method: 'POST', pattern: /^\/v1\/mobile\/authorizations\/[^/]+\/signature\/?$/i },
  { method: 'POST', pattern: /^\/v1\/mobile\/authorizations\/[^/]+\/deferred-signature\/?$/i },
  { method: 'GET', pattern: /^\/v1\/mobile\/verification-sessions\/[^/]+\/call\/?$/i },
  { method: 'GET', pattern: /^\/v1\/mobile\/verification-sessions\/[^/]+\/signals\/?$/i },
  { method: 'POST', pattern: /^\/v1\/mobile\/verification-sessions\/[^/]+\/signals\/?$/i },
  { method: 'POST', pattern: /^\/v1\/mobile\/verification-sessions\/[^/]+\/cancel\/?$/i },
  { method: 'POST', pattern: /^\/v1\/mobile\/push-registration\/?$/i },
  { method: 'DELETE', pattern: /^\/v1\/mobile\/push-registration\/?$/i },
  { method: 'GET', pattern: /^\/v1\/mobile\/push-messages\/[^/]+\/?$/i },
  { method: 'POST', pattern: /^\/v1\/push-receipts\/[^/]+\/?$/i },
  { method: 'POST', pattern: /^\/v1\/recovery\/sessions\/[^/]+\/complete\/?$/i },
];

export function isDeviceFacingRequest(req: Pick<Request, 'path' | 'method'>): boolean {
  const method = req.method === 'HEAD' ? 'GET' : req.method;
  return DEVICE_ROUTES.some((route) => route.method === method && route.pattern.test(req.path));
}

/** SHA-256 (lowercase hex) of the client certificate the gateway verified
 * for this request; set by requireGatewayMtls when REQUIRE_MTLS_HEADER is on. */
export interface GatewayRequest extends Request {
  clientCertificateSha256?: string;
}

/** Accepts hex with or without colons, in either case. */
export function normalizeFingerprint(value: string | undefined): string | null {
  const hex = (value ?? '').replace(/:/g, '').trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}

export function requireGatewayMtls(req: GatewayRequest, res: Response, next: NextFunction): void {
  if (!env.REQUIRE_MTLS_HEADER || isDeviceFacingRequest(req)) {
    next();
    return;
  }

  const remote = normalizeIp(req.socket.remoteAddress);
  if (env.TRUSTED_PROXY_IPS.length === 0 || !remote || !env.TRUSTED_PROXY_IPS.map(normalizeIp).includes(remote)) {
    res.status(403).json({ error: 'mTLS gateway required' });
    return;
  }

  if (req.header(env.MTLS_VERIFIED_HEADER) !== 'SUCCESS') {
    res.status(403).json({ error: 'Verified client certificate required' });
    return;
  }
  // Bank tokens are bound to the registered certificate fingerprints
  // (tokenService.ts); without a fingerprint no bank call can succeed.
  const fingerprint = normalizeFingerprint(req.header(env.MTLS_CERT_SHA256_HEADER));
  if (!fingerprint) {
    res.status(403).json({ error: 'Verified client certificate fingerprint required' });
    return;
  }
  req.clientCertificateSha256 = fingerprint;

  next();
}

/** IPv4-mapped IPv6 addresses compare as their IPv4 form. */
export function normalizeIp(value: string | undefined): string | undefined {
  if (!value) return undefined;
  return value.startsWith('::ffff:') ? value.slice(7) : value;
}
