import type { PoolClient } from 'pg';

/**
 * Lock order (finding A1-07). Confirming a payment locks its authorization row
 * and then reads the credential and the identity FOR SHARE. Revoking a device,
 * suspending or revoking an identity, replacing a device and completing a
 * recovery change the credential or the identity and then cancel the open
 * authorizations: the opposite order, so the two could deadlock and one side
 * got a 500. These paths call this first, before they touch the identity or
 * its credentials, so both sides take the authorization rows first.
 * Rows are locked in a fixed order, so two of these paths cannot deadlock
 * each other either.
 */
export async function lockOpenAuthorizations(client: Pick<PoolClient, 'query'>, nexusId: string): Promise<void> {
  await client.query(
    `SELECT 1 FROM authorization_requests WHERE nexus_id = $1 AND state = 'PENDING_USER' ORDER BY authorization_id FOR UPDATE`,
    [nexusId]);
}
