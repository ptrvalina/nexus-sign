import { readFileSync } from 'node:fs';
import { pool } from '../db/pool';
import { redis } from '../db/redis';
import { parseP256PublicKey } from '../crypto/p256PublicKey';
import { recordAuditEvent } from '../services/auditService';

/**
 * Configures how a bank's audio and video verification results are trusted
 * (FI-002, FI-017). Operator-only: the bank's API cannot change it, so a
 * compromised bank backend cannot register a key of its own.
 *
 *   node dist/cli/verificationSetup.js provider-add <clientId> <providerId> <keyId> <AUDIO,VIDEO> <public-key.pem>
 *   node dist/cli/verificationSetup.js provider-retire <clientId> <providerId> <keyId>
 *   node dist/cli/verificationSetup.js operator <clientId> <AUDIO,VIDEO | none>
 *   node dist/cli/verificationSetup.js show <clientId>
 *
 * provider-add  registers an ES256 (P-256) public key of a verification
 *               provider; result tokens name it with iss=<providerId> and
 *               kid=<keyId> (docs/protocol/verification-result-v1.md).
 * operator      enables in-app calls answered by the bank's operators in the
 *               admin console for the given channels.
 * A channel is offered in verification plans only if one of the two exists.
 */
const NAME = /^[A-Za-z0-9._-]{1,64}$/;

function channels(list: string | undefined, allowNone: boolean): string[] {
  if (allowNone && list === 'none') return [];
  const values = (list ?? '').split(',').map((c) => c.trim().toUpperCase()).filter(Boolean);
  if (values.length === 0 || values.some((c) => c !== 'AUDIO' && c !== 'VIDEO')) throw new Error('channels must be AUDIO, VIDEO or AUDIO,VIDEO');
  return [...new Set(values)];
}

async function requireClient(clientId: string): Promise<void> {
  const found = await pool.query(`SELECT 1 FROM bank_clients WHERE client_id = $1`, [clientId]);
  if (!found.rows[0]) throw new Error(`No bank client "${clientId}"`);
}

async function main(): Promise<void> {
  const [command, clientId, ...args] = process.argv.slice(2);
  const actor = { clientId, actor: 'cli:verificationSetup' };
  switch (command) {
    case 'provider-add': {
      const [providerId, keyId, list, pemFile] = args;
      if (!clientId || !NAME.test(providerId ?? '') || !NAME.test(keyId ?? '') || !pemFile) throw new Error('usage: provider-add <clientId> <providerId> <keyId> <AUDIO,VIDEO> <public-key.pem>');
      await requireClient(clientId);
      const key = parseP256PublicKey(readFileSync(pemFile, 'utf8'));
      const values = channels(list, false);
      await pool.query(
        `INSERT INTO verification_providers (client_id, provider_id, key_id, channels, public_key_pem) VALUES ($1, $2, $3, $4, $5)`,
        [clientId, providerId, keyId, values, key.pem]);
      await recordAuditEvent('verification_provider_registered', actor, { providerId, keyId, channels: values });
      console.log(`Registered verification provider key ${providerId}/${keyId} for "${clientId}" (${values.join(', ')}).`);
      return;
    }
    case 'provider-retire': {
      const [providerId, keyId] = args;
      const result = await pool.query(
        `UPDATE verification_providers SET status = 'RETIRED', retired_at = now() WHERE client_id = $1 AND provider_id = $2 AND key_id = $3 AND status = 'ACTIVE'`,
        [clientId, providerId, keyId]);
      if (result.rowCount !== 1) throw new Error(`No active key ${providerId}/${keyId} for "${clientId}"`);
      await recordAuditEvent('verification_provider_retired', actor, { providerId, keyId });
      console.log(`Retired verification provider key ${providerId}/${keyId} of "${clientId}".`);
      return;
    }
    case 'operator': {
      if (!clientId) throw new Error('usage: operator <clientId> <AUDIO,VIDEO | none>');
      await requireClient(clientId);
      const values = channels(args[0], true);
      await pool.query(`UPDATE bank_clients SET operator_verification_channels = $2, updated_at = now() WHERE client_id = $1`, [clientId, values]);
      await recordAuditEvent('operator_verification_changed', actor, { channels: values });
      console.log(`Operator verification for "${clientId}": ${values.length ? values.join(', ') : 'off'}.`);
      return;
    }
    case 'show': {
      if (!clientId) throw new Error('usage: show <clientId>');
      await requireClient(clientId);
      const operator = await pool.query<{ operator_verification_channels: string[] }>(`SELECT operator_verification_channels FROM bank_clients WHERE client_id = $1`, [clientId]);
      const providers = await pool.query<{ provider_id: string; key_id: string; channels: string[]; status: string }>(
        `SELECT provider_id, key_id, channels, status FROM verification_providers WHERE client_id = $1 ORDER BY created_at`, [clientId]);
      console.log(`operator: ${operator.rows[0].operator_verification_channels.join(', ') || 'off'}`);
      for (const p of providers.rows) console.log(`provider: ${p.provider_id}/${p.key_id} ${p.channels.join(',')} ${p.status}`);
      return;
    }
    default:
      throw new Error('usage: verificationSetup.js provider-add | provider-retire | operator | show <clientId> ...');
  }
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
