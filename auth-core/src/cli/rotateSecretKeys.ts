import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { redis } from '../db/redis';
import { decryptSecretBytes, keyRing, MASTER_KEY_NAMES, needsRewrap, rewrapSecret, type SecretPurpose } from '../crypto/secretBox';
import { recordAuditEvent } from '../services/auditService';
import { loadMasterKeys } from '../crypto/masterKeyVault';

/**
 * Re-encrypts stored secrets under the current master key.
 *
 *   node dist/cli/rotateSecretKeys.js [webhook|device|admin|all] [--dry-run]
 *
 * Rotation:
 *   1. Generate a new key (`openssl rand -base64 32`). Set it as <NAME> and
 *      move the old one to <NAME>_PREVIOUS (comma-separated if several).
 *      Restart Auth Core: it encrypts with the new key and still reads
 *      secrets under the old one.
 *   2. Run this tool. Each secret is decrypted, encrypted under the current
 *      key, checked to decrypt to the same bytes, and written only if the row
 *      still holds the value that was read. Rows are processed in small
 *      transactions; the tool can be run again.
 *   3. When it reports nothing left under previous keys, remove
 *      <NAME>_PREVIOUS and restart.
 *
 * It refuses to run while any stored secret cannot be decrypted with the
 * configured keys, and writes one audit event per purpose with the counts.
 */
interface Column { purpose: SecretPurpose; table: string; key: string; column: string; owner: (row: Record<string, string>) => string }

const COLUMNS: Column[] = [
  { purpose: 'webhook', table: 'bank_clients', key: 'client_id', column: 'webhook_secret_encrypted', owner: (r) => r.client_id },
  { purpose: 'webhook', table: 'bank_clients', key: 'client_id', column: 'webhook_secret_previous_encrypted', owner: (r) => r.client_id },
  { purpose: 'device', table: 'credentials', key: 'credential_id', column: 'offline_secret_encrypted', owner: (r) => r.credential_id },
  { purpose: 'device', table: 'push_registrations', key: 'credential_id', column: 'push_key_encrypted', owner: (r) => `push:${r.credential_id}` },
  { purpose: 'device', table: 'offline_challenges', key: 'authorization_id', column: 'server_private_key_encrypted', owner: (r) => `offline-challenge:${r.authorization_id}` },
  { purpose: 'admin', table: 'admin_users', key: 'username', column: 'totp_secret_encrypted', owner: (r) => r.username },
];

const BATCH = 200;

interface Counts { checked: number; rewrapped: number; current: number; changedMeanwhile: number }

async function rotateColumn(c: Column, dryRun: boolean): Promise<Counts> {
  const counts: Counts = { checked: 0, rewrapped: 0, current: 0, changedMeanwhile: 0 };
  let after = '';
  for (;;) {
    const rows = (await pool.query<Record<string, string>>(
      `SELECT ${c.key}::text AS id, ${c.key}::text AS ${c.key}, ${c.column} AS value FROM ${c.table}
       WHERE ${c.column} IS NOT NULL AND ${c.key}::text > $1 ORDER BY ${c.key}::text LIMIT $2`, [after, BATCH])).rows;
    if (rows.length === 0) return counts;
    after = rows[rows.length - 1].id;
    const pending = rows.filter((row) => {
      counts.checked += 1;
      if (needsRewrap(row.value, c.purpose)) return true;
      counts.current += 1;
      return false;
    });
    if (dryRun) { counts.rewrapped += pending.length; continue; }
    if (pending.length === 0) continue;
    await withTransaction(async (tx: PoolClient) => {
      // Lets the credential trigger accept a new ciphertext of the same
      // offline key (migration 020); only for this transaction.
      await tx.query(`SELECT set_config('nexus.secret_rewrap', 'on', true)`);
      for (const row of pending) {
        const owner = c.owner(row);
        const plaintext = decryptSecretBytes(row.value, c.purpose, owner);
        const rewrapped = rewrapSecret(row.value, c.purpose, owner);
        if (!decryptSecretBytes(rewrapped, c.purpose, owner).equals(plaintext)) throw new Error(`${c.table} ${row.id}: re-encrypted value does not decrypt to the same secret`);
        const updated = await tx.query(`UPDATE ${c.table} SET ${c.column} = $1 WHERE ${c.key}::text = $2 AND ${c.column} = $3`, [rewrapped, row.id, row.value]);
        if (updated.rowCount === 1) counts.rewrapped += 1; else counts.changedMeanwhile += 1;
      }
    });
  }
}

/** Every stored secret must decrypt with the configured keys before anything is written. */
async function preflight(columns: Column[]): Promise<string[]> {
  const problems: string[] = [];
  for (const c of columns) {
    const rows = (await pool.query<Record<string, string>>(`SELECT ${c.key}::text AS ${c.key}, ${c.column} AS value FROM ${c.table} WHERE ${c.column} IS NOT NULL`)).rows;
    for (const row of rows) {
      try { decryptSecretBytes(row.value, c.purpose, c.owner(row)); } catch (error) {
        problems.push(`${c.table} ${row[c.key]}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }
  return problems;
}

async function main(): Promise<void> {
  await loadMasterKeys(); // MASTER_KEY_SOURCE=hsm: unwrap in the HSM
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const which = args.find((a) => !a.startsWith('--')) ?? 'all';
  if (!['webhook', 'device', 'admin', 'all'].includes(which)) throw new Error('usage: rotateSecretKeys.js [webhook|device|admin|all] [--dry-run]');
  const purposes = (which === 'all' ? ['webhook', 'device', 'admin'] : [which]) as SecretPurpose[];
  const configured = purposes.filter((p) => { try { keyRing(p); return true; } catch { return false; } });
  for (const p of purposes) if (!configured.includes(p)) console.log(`${MASTER_KEY_NAMES[p]} is not configured: skipped`);
  const columns = COLUMNS.filter((c) => configured.includes(c.purpose));

  const problems = await preflight(columns);
  if (problems.length > 0) {
    throw new Error(`Some stored secrets cannot be decrypted with the configured keys; nothing was changed:\n- ${problems.slice(0, 20).join('\n- ')}${problems.length > 20 ? `\n- ... ${problems.length - 20} more` : ''}`);
  }
  for (const purpose of configured) {
    const ring = keyRing(purpose);
    const totals: Counts = { checked: 0, rewrapped: 0, current: 0, changedMeanwhile: 0 };
    for (const c of columns.filter((x) => x.purpose === purpose)) {
      const counts = await rotateColumn(c, dryRun);
      for (const k of Object.keys(totals) as (keyof Counts)[]) totals[k] += counts[k];
      console.log(`${c.table}.${c.column}: ${counts.checked} stored, ${counts.current} already under the current key, ${counts.rewrapped} ${dryRun ? 'to re-encrypt' : 're-encrypted'}${counts.changedMeanwhile ? `, ${counts.changedMeanwhile} changed meanwhile (run again)` : ''}`);
    }
    if (!dryRun) {
      await recordAuditEvent('master_key_rotated', { actor: 'cli:rotateSecretKeys' },
        { purpose, currentKeyId: ring.current.id, previousKeyIds: ring.previous.map((k) => k.id), ...totals });
    }
    console.log(`${MASTER_KEY_NAMES[purpose]}: current key ${ring.current.id}${ring.previous.length ? `, previous ${ring.previous.map((k) => k.id).join(', ')}` : ''}`);
  }
  console.log(dryRun ? 'Dry run: nothing written.' : 'Done. Remove the *_PREVIOUS keys once no secret remains under them (run again with --dry-run to check).');
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(() => {
    void pool.end();
    redis.disconnect();
  });
