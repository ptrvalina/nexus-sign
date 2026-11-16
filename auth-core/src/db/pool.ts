import { Pool, type PoolClient } from 'pg';
import { env } from '../config/env';

export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: env.DATABASE_POOL_MAX,
  statement_timeout: env.DATABASE_STATEMENT_TIMEOUT_MS,
  ssl: env.DATABASE_SSL ? { rejectUnauthorized: true } : undefined,
});

/**
 * Runs `work` in a transaction: commits on success, rolls back on any thrown
 * error. The PoolClient lets callers issue several statements atomically
 * (e.g. an authorization and its audit log entry). If the rollback itself
 * fails, the original error is thrown and the connection is destroyed rather
 * than returned to the pool in an unknown transaction state (finding A1-08).
 */
export async function withTransaction<T>(
  work: (client: PoolClient) => Promise<T>,
  source: Pick<Pool, 'connect'> = pool,
): Promise<T> {
  const client = await source.connect();
  let broken: Error | undefined;
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackError) {
      broken = rollbackError instanceof Error ? rollbackError : new Error(String(rollbackError));
    }
    throw error;
  } finally {
    client.release(broken);
  }
}
