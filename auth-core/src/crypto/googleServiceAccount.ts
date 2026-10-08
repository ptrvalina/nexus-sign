import { createSign } from 'node:crypto';

/**
 * Exchanges a Google Cloud service account's private key for a short-lived
 * OAuth 2.0 access token (JWT bearer grant, RFC 7523), used to call the Play
 * Integrity decode API and the FCM send API.
 */

export interface GoogleServiceAccount {
  client_email: string;
  private_key: string;
}

export function parseServiceAccountJson(raw: string): GoogleServiceAccount {
  const parsed: unknown = JSON.parse(raw);
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    typeof (parsed as GoogleServiceAccount).client_email !== 'string' ||
    typeof (parsed as GoogleServiceAccount).private_key !== 'string'
  ) {
    throw new Error('Service account JSON is missing client_email or private_key');
  }
  return parsed as GoogleServiceAccount;
}

function base64url(input: Buffer | string): string {
  const buffer = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buffer.toString('base64url');
}

function buildSignedAssertion(serviceAccount: GoogleServiceAccount, scope: string): string {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claims = {
    iss: serviceAccount.client_email,
    scope,
    aud: 'https://oauth2.googleapis.com/token',
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  };

  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const signer = createSign('RSA-SHA256');
  signer.update(unsigned);
  signer.end();
  const signature = signer.sign(serviceAccount.private_key);

  return `${unsigned}.${base64url(signature)}`;
}

const tokenCache = new Map<string, { token: string; expiresAtMs: number }>();

function cacheKey(serviceAccount: GoogleServiceAccount, scope: string): string {
  return `${serviceAccount.client_email} ${scope}`;
}

/** Drops a cached token, e.g. after Google answered 401 to it. */
export function forgetGoogleAccessToken(serviceAccount: GoogleServiceAccount, scope: string): void {
  tokenCache.delete(cacheKey(serviceAccount, scope));
}

/** Returns a cached token while it has more than a minute of validity left,
 * otherwise obtains a new one. Cached per service account and scope. */
export async function getGoogleAccessToken(serviceAccount: GoogleServiceAccount, scope: string): Promise<string> {
  const cached = tokenCache.get(cacheKey(serviceAccount, scope));
  if (cached && cached.expiresAtMs > Date.now() + 60_000) {
    return cached.token;
  }

  const assertion = buildSignedAssertion(serviceAccount, scope);

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    signal: AbortSignal.timeout(10_000),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }).toString(),
  });

  if (!response.ok) {
    throw new Error(`Google token exchange returned HTTP ${response.status}`);
  }

  const body = (await response.json()) as { access_token?: string; expires_in?: number };
  if (!body.access_token) {
    throw new Error('Google token exchange response had no access_token');
  }

  tokenCache.set(cacheKey(serviceAccount, scope), { token: body.access_token, expiresAtMs: Date.now() + (body.expires_in ?? 3600) * 1000 });
  return body.access_token;
}
