import { pool } from '../db/pool';
import { recordAuditEvent } from '../services/auditService';

/**
 * Sets how many devices a customer of a bank client may have active at once
 * (bank_clients.max_devices_per_identity, migration 027). Lowering the limit
 * does not revoke devices already active; it only refuses further additions.
 *
 * Usage:
 *   node dist/cli/setDevicePolicy.js <clientId> <1-10>
 */
async function main(): Promise<void> {
  const [clientId, value, ...rest] = process.argv.slice(2);
  const max = Number(value);
  if (!clientId || rest.length > 0 || !Number.isInteger(max) || max < 1 || max > 10) {
    console.error('Usage: setDevicePolicy.js <clientId> <maximum active devices per NEXUS ID, 1-10>');
    process.exitCode = 1;
    return;
  }
  const result = await pool.query(
    `UPDATE bank_clients SET max_devices_per_identity = $2, updated_at = now() WHERE client_id = $1 RETURNING client_id`, [clientId, max]);
  if (result.rowCount !== 1) {
    console.error(`No bank client "${clientId}"`);
    process.exitCode = 1;
    return;
  }
  await recordAuditEvent('device_policy_changed', { clientId, actor: 'cli:setDevicePolicy' }, { maxDevicesPerIdentity: max });
  console.log(`Bank client "${clientId}": at most ${max} active device(s) per NEXUS ID`);
}

main()
  .catch((error: unknown) => {
    console.error('Failed to set the device policy:', error);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
