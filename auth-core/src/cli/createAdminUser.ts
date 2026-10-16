import { randomBytes } from 'node:crypto';
import { registerAdminUser, type AdminRole } from '../services/adminAuthService';
import { base32Encode, generateTotpSecret, totpUri } from '../crypto/totp';
import { env } from '../config/env';
import { pool } from '../db/pool';
import { redis } from '../db/redis';

/**
 * Creates (or resets) an admin dashboard account. Not an HTTP endpoint;
 * admin accounts are provisioned by the deployment operator.
 *
 * Usage:
 *   node dist/cli/createAdminUser.js <username> <administrator|operator|auditor> [--client=<clientId>] [--keep-totp]
 *
 * --client limits the account to one bank's identities, audit records and
 * deliveries; without it the account is a platform operator (all banks).
 *
 * The password is read from NEXUS_ADMIN_PASSWORD when set (never from the
 * command line, where it would reach shell history and the process list);
 * otherwise a random one is generated and printed once. A new TOTP secret is
 * enrolled and printed once (needs ADMIN_SECRET_ENCRYPTION_KEY) unless
 * --keep-totp keeps the existing one.
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const options = args.filter((a) => a.startsWith('--'));
  const [username, role] = args.filter((a) => !a.startsWith('--'));
  const clientOption = options.find((a) => a.startsWith('--client='));
  const keepTotp = options.includes('--keep-totp');
  const unknown = options.filter((a) => a !== clientOption && a !== '--keep-totp');
  const clientId = clientOption?.slice('--client='.length) || null;
  if (!username || !role || unknown.length > 0 || (clientOption && !clientId)) {
    console.error('Usage: createAdminUser.js <username> <administrator|operator|auditor> [--client=<clientId>] [--keep-totp]');
    process.exitCode = 1;
    return;
  }
  if (!['administrator', 'operator', 'auditor'].includes(role)) {
    console.error(`Invalid role "${role}" — must be administrator, operator, or auditor`);
    process.exitCode = 1;
    return;
  }
  if (!keepTotp && !env.ADMIN_SECRET_ENCRYPTION_KEY) {
    console.error('ADMIN_SECRET_ENCRYPTION_KEY is required to enrol the account\'s TOTP secret');
    process.exitCode = 1;
    return;
  }

  const providedPassword = process.env.NEXUS_ADMIN_PASSWORD;
  const password = providedPassword ?? randomBytes(18).toString('base64url');
  const totpSecret = keepTotp ? undefined : generateTotpSecret();
  await registerAdminUser({ username, password, role: role as AdminRole, clientId, totpSecret });

  console.log(`Created/updated admin user "${username}" with role "${role}" (${clientId ? `bank ${clientId}` : 'all banks'}).`);
  console.log('');
  if (!providedPassword) console.log(`  password: ${password}`);
  if (totpSecret) {
    console.log(`  totp_secret: ${base32Encode(totpSecret)}`);
    console.log(`  totp_uri: ${totpUri('NEXUS-SIGN', username, totpSecret)}`);
  }
  if (!providedPassword || totpSecret) {
    console.log('');
    console.log('Hand these to the account holder over a secure channel now; they are only printed this once.');
  }
}

main()
  .catch((error: unknown) => {
    console.error('Failed to create admin user:', error);
    process.exitCode = 1;
  })
  .finally(() => {
    void pool.end();
    redis.disconnect();
  });
