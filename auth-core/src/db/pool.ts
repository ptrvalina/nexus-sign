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
 * (e.g. an authorization and its audit log entry).
 */
export async function withTransaction<T>(
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
