import { pool } from '../db/pool';
import { redis } from '../db/redis';
import { normalizeFingerprint } from '../middleware/mtlsGateway';

/**
 * Replaces the client certificate fingerprints registered for a bank client
 * without rotating its secrets (registerClient rotates them). Used for a
 * certificate rollover: register old and new, switch the gateway, then
 * register only the new one.
 *
 * Usage:
 *   node dist/cli/setClientCertificates.js <clientId> <sha256 hex>[,<sha256 hex>...]
 *
 * Fingerprints are the SHA-256 of the DER certificate, hex, with or without
 * colons. With REQUIRE_MTLS_HEADER, tokens are issued and accepted only over a
 * gateway connection authenticated with one of them.
 */
async function main(): Promise<void> {
  const [clientId, list, ...rest] = process.argv.slice(2);
  const certificates = (list ?? '').split(',').filter(Boolean).map((v) => normalizeFingerprint(v));
  if (!clientId || rest.length > 0 || certificates.length === 0 || certificates.some((c) => c === null)) {
    console.error('Usage: setClientCertificates.js <clientId> <64 hex>[,<64 hex>...]');
    process.exitCode = 1;
    return;
  }
  const result = await pool.query(
    `UPDATE bank_clients SET mtls_cert_sha256 = $2::text[], updated_at = now() WHERE client_id = $1`, [clientId, certificates]);
  if (result.rowCount !== 1) {
    console.error(`No bank client "${clientId}"`);
    process.exitCode = 1;
    return;
  }
  console.log(`Client certificates of "${clientId}": ${certificates.join(', ')}`);
}

main()
  .catch((error: unknown) => {
    console.error('Failed to set client certificates:', error);
    process.exitCode = 1;
  })
  .finally(() => {
    void pool.end();
    redis.disconnect();
  });
