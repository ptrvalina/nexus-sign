import { createPrivateKey, sign, type KeyObject } from 'node:crypto';

/**
 * APNs token-based authentication: an ES256 JWT signed with the bank's APNs
 * auth key (.p8). Apple rejects tokens older than one hour and asks providers
 * not to refresh more than once every 20 minutes, so one token is reused for
 * 50 minutes.
 */
const TOKEN_LIFETIME_SECONDS = 50 * 60;

export function buildApnsProviderToken(teamId: string, keyId: string, privateKey: KeyObject, issuedAtSeconds: number): string {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: keyId })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({ iss: teamId, iat: issuedAtSeconds })).toString('base64url');
  const unsigned = `${header}.${claims}`;
  // JWS ES256 uses the 64-byte r || s form, not DER.
  const signature = sign('sha256', Buffer.from(unsigned, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${unsigned}.${signature.toString('base64url')}`;
}

export class ApnsProviderToken {
  private readonly privateKey: KeyObject;
  private current: { token: string; issuedAt: number } | null = null;

  constructor(private readonly teamId: string, private readonly keyId: string, privateKeyPem: string) {
    this.privateKey = createPrivateKey(privateKeyPem);
    if (this.privateKey.asymmetricKeyType !== 'ec') throw new Error('APNS_PRIVATE_KEY_PEM must be an EC (P-256) key');
  }

  get(nowSeconds: number = Math.floor(Date.now() / 1000)): string {
    if (!this.current || nowSeconds - this.current.issuedAt >= TOKEN_LIFETIME_SECONDS) {
      this.current = { token: buildApnsProviderToken(this.teamId, this.keyId, this.privateKey, nowSeconds), issuedAt: nowSeconds };
    }
    return this.current.token;
  }

  /** After APNs answered ExpiredProviderToken or InvalidProviderToken. */
  reset(): void {
    this.current = null;
  }
}
