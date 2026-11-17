import type { Pool } from 'pg';

/**
 * Webhook secrets written before 2.0.0 without the `v2` prefix are encrypted
 * without associated data, so such a ciphertext is not bound to its bank: a
 * database writer could move it to another bank's row (finding B-11).
 * `rotateSecretKeys.js webhook` re-encrypts them in the bound `k1` format.
 * Production refuses to start while any remain; elsewhere it is a warning.
 */
export async function countUnboundWebhookSecrets(db: Pick<Pool, 'query'>): Promise<number> {
  const result = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM bank_clients
     WHERE webhook_secret_encrypted IS NOT NULL
       AND webhook_secret_encrypted NOT LIKE 'k1$%' AND webhook_secret_encrypted NOT LIKE 'v2$%'`);
  return result.rows[0]?.n ?? 0;
}

export function unboundWebhookSecretsProblem(count: number, nodeEnv: string): { refuse: boolean; message: string } | null {
  if (count === 0) return null;
  const message = `${count} webhook secret(s) are stored in the pre-2.0 format, not bound to their bank: run node dist/cli/rotateSecretKeys.js webhook`;
  return { refuse: nodeEnv === 'production', message };
}
