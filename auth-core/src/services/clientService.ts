import { pool } from '../db/pool';
import { encryptSecret, decryptSecret } from '../crypto/secretBox';
import { hashPassword, verifyAgainstDummy, verifyPassword } from '../crypto/password';

export class InvalidClientSecretError extends Error {
  constructor() {
    super('Invalid client credentials');
    this.name = 'InvalidClientSecretError';
  }
}

export interface RegisterClientInput {
  clientId: string;
  clientSecret: string;
  webhookUrl?: string;
  webhookSecret?: string;
  /** BANK (default): the bank's push system delivers authorization requests.
   * NEXUS: Auth Core delivers them, and bank messages, through secure push. */
  pushMode?: PushMode;
  /** SHA-256 fingerprints (hex) of the bank's client certificates; omitted
   * keeps the registered ones when credentials are rotated. */
  mtlsCertSha256?: string[];
  /** When the client already has a webhook secret and a new one is given,
   * the previous secret still signs deliveries for this many seconds
   * (finding A2-08); 0 ends it at once. */
  webhookSecretOverlapSeconds?: number;
}

/** Default overlap of the previous webhook secret after a rotation. */
export const DEFAULT_WEBHOOK_SECRET_OVERLAP_SECONDS = 86_400;
/** Longest overlap accepted (7 days). */
export const MAX_WEBHOOK_SECRET_OVERLAP_SECONDS = 604_800;

export type PushMode = 'BANK' | 'NEXUS';

/**
 * Registers a bank backend allowed to call this Auth Core deployment. Not
 * exposed over HTTP: onboarding is an operator action
 * (scripts/register-client.ts) that a compromised client cannot reach.
 */
export async function registerBankClient(input: RegisterClientInput): Promise<void> {
  const clientSecretHash = await hashPassword(input.clientSecret, 'secret');
  const webhookSecretEncrypted = input.webhookSecret ? encryptSecret(input.webhookSecret, 'webhook', input.clientId) : null;
  const overlap = input.webhookSecretOverlapSeconds ?? DEFAULT_WEBHOOK_SECRET_OVERLAP_SECONDS;
  if (!Number.isInteger(overlap) || overlap < 0 || overlap > MAX_WEBHOOK_SECRET_OVERLAP_SECONDS) {
    throw new Error(`webhookSecretOverlapSeconds must be an integer from 0 to ${MAX_WEBHOOK_SECRET_OVERLAP_SECONDS}`);
  }

  // On a rotation the secret being replaced becomes the previous one for the
  // overlap (finding A2-08); a secret older than that is dropped.
  await pool.query(
    `INSERT INTO bank_clients (client_id, client_secret_hash, webhook_url, webhook_secret_encrypted, push_mode, mtls_cert_sha256)
     VALUES ($1, $2, $3, $4, $5, COALESCE($6::text[], '{}'))
     ON CONFLICT (client_id) DO UPDATE
       SET client_secret_hash = EXCLUDED.client_secret_hash,
           webhook_url = EXCLUDED.webhook_url,
           webhook_secret_previous_encrypted = CASE WHEN $7::integer > 0 AND bank_clients.webhook_secret_encrypted IS NOT NULL
             AND EXCLUDED.webhook_secret_encrypted IS NOT NULL THEN bank_clients.webhook_secret_encrypted END,
           webhook_secret_previous_until = CASE WHEN $7::integer > 0 AND bank_clients.webhook_secret_encrypted IS NOT NULL
             AND EXCLUDED.webhook_secret_encrypted IS NOT NULL THEN now() + make_interval(secs => $7::integer) END,
           webhook_secret_encrypted = EXCLUDED.webhook_secret_encrypted,
           push_mode = EXCLUDED.push_mode,
           mtls_cert_sha256 = COALESCE($6::text[], bank_clients.mtls_cert_sha256),
           updated_at = now()`,
    [input.clientId, clientSecretHash, input.webhookUrl ?? null, webhookSecretEncrypted, input.pushMode ?? 'BANK', input.mtlsCertSha256 ?? null, overlap],
  );
}

/** Verifies a client_id/client_secret pair for the OAuth2 token endpoint.
 * Throws on any failure; unknown client, disabled client and wrong secret
 * fail identically, so a token request cannot probe which clients exist. */
export async function verifyClientCredentials(clientId: string, clientSecret: string): Promise<void> {
  const result = await pool.query<{ client_secret_hash: string; status: string }>(
    `SELECT client_secret_hash, status FROM bank_clients WHERE client_id = $1`,
    [clientId],
  );
  const row = result.rows[0];
  if (!row || row.status !== 'ACTIVE') {
    await verifyAgainstDummy(clientSecret, 'secret');
    throw new InvalidClientSecretError();
  }
  const isValid = await verifyPassword(clientSecret, row.client_secret_hash);
  if (!isValid) {
    throw new InvalidClientSecretError();
  }
}

export interface WebhookDestination {
  webhookUrl: string;
  webhookSecret: string;
  /** The secret before the last rotation, while its overlap lasts (A2-08). */
  previousWebhookSecret?: string;
}

/** Returns the bank's webhook URL and the decrypted signing secret, or `null`
 * if the client has no webhook configured (a valid state, not an error). */
export async function getWebhookDestination(clientId: string): Promise<WebhookDestination | null> {
  const result = await pool.query<{ webhook_url: string | null; webhook_secret_encrypted: string | null; previous: string | null }>(
    `SELECT webhook_url, webhook_secret_encrypted,
            CASE WHEN webhook_secret_previous_until > now() THEN webhook_secret_previous_encrypted END AS previous
       FROM bank_clients WHERE client_id = $1 AND status = 'ACTIVE'`,
    [clientId],
  );
  const row = result.rows[0];
  if (!row || !row.webhook_url || !row.webhook_secret_encrypted) {
    return null;
  }
  return {
    webhookUrl: row.webhook_url,
    webhookSecret: decryptSecret(row.webhook_secret_encrypted, 'webhook', clientId),
    ...(row.previous ? { previousWebhookSecret: decryptSecret(row.previous, 'webhook', clientId) } : {}),
  };
}

/** True when the client has a webhook configured. Does not decrypt the
 * secret, so recording an event never depends on the encryption key.
 * `runner` is the caller's transaction when there is one: taking a second
 * pool connection while holding row locks can exhaust the pool under
 * concurrency (every waiting transaction holds a connection too). */
export async function hasWebhookDestination(clientId: string, runner: Pick<typeof pool, 'query'> = pool): Promise<boolean> {
  const result = await runner.query(
    `SELECT 1 FROM bank_clients WHERE client_id = $1 AND status = 'ACTIVE' AND webhook_url IS NOT NULL AND webhook_secret_encrypted IS NOT NULL`,
    [clientId],
  );
  return result.rows.length > 0;
}

/** How authorization requests reach this bank's customers; `null` for an
 * unknown or disabled client. */
export async function getClientPushMode(clientId: string): Promise<PushMode | null> {
  const result = await pool.query<{ push_mode: PushMode }>(
    `SELECT push_mode FROM bank_clients WHERE client_id = $1 AND status = 'ACTIVE'`, [clientId]);
  return result.rows[0]?.push_mode ?? null;
}

export async function getClientRecord(clientId: string): Promise<{ status: string; mtlsCertSha256: string[] } | null> {
  const result = await pool.query<{ status: string; mtls_cert_sha256: string[] }>(
    `SELECT status, mtls_cert_sha256 FROM bank_clients WHERE client_id = $1`, [clientId]);
  const row = result.rows[0];
  return row ? { status: row.status, mtlsCertSha256: row.mtls_cert_sha256 } : null;
}

/** True when `fingerprint` is one of the client's registered certificates. */
export function certificateMatches(client: { mtlsCertSha256: string[] } | null, fingerprint: string | null | undefined): boolean {
  return Boolean(client && fingerprint && client.mtlsCertSha256.includes(fingerprint));
}

export interface BankClientSummary {
  clientId: string;
  status: string;
  hasWebhook: boolean;
  pushMode: PushMode;
  certificateCount: number;
  createdAt: Date;
  updatedAt: Date;
}

/** Lists registered bank clients for the admin dashboard, without secret
 * material. */
export async function listBankClients(): Promise<BankClientSummary[]> {
  const result = await pool.query<{
    client_id: string;
    status: string;
    webhook_url: string | null;
    push_mode: PushMode;
    mtls_cert_sha256: string[];
    created_at: Date;
    updated_at: Date;
  }>(`SELECT client_id, status, webhook_url, push_mode, mtls_cert_sha256, created_at, updated_at FROM bank_clients ORDER BY created_at DESC`);

  return result.rows.map((row) => ({
    clientId: row.client_id,
    status: row.status,
    hasWebhook: row.webhook_url !== null,
    pushMode: row.push_mode,
    certificateCount: row.mtls_cert_sha256.length,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}
