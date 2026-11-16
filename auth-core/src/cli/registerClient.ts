import { randomBytes } from 'node:crypto';
import { registerBankClient, type PushMode } from '../services/clientService';
import { pool } from '../db/pool';
import { redis } from '../db/redis';
import { revokeClientTokens } from '../services/tokenService';
import { normalizeFingerprint } from '../middleware/mtlsGateway';
import { loadMasterKeys } from '../crypto/masterKeyVault';

/**
 * Registers (or rotates credentials for) a bank client allowed to call this
 * Auth Core deployment. Not an HTTP endpoint, so a compromised client cannot
 * use the API to onboard another; run it where an operator has database access.
 *
 * Usage (from the built image or a build):
 *   node dist/cli/registerClient.js <clientId> [webhookUrl] [--push-mode=BANK|NEXUS] [--mtls-cert-sha256=<hex>[,<hex>]]
 *
 * --push-mode=NEXUS lets Auth Core deliver authorization requests and the
 * bank's messages through secure push (the bank has no push system of its
 * own). The default, BANK, keeps the bank's push system in charge. Running
 * the command again for an existing client sets the mode again.
 *
 * --mtls-cert-sha256 registers the SHA-256 fingerprints of the bank's client
 * certificates (several during a certificate rollover). With
 * REQUIRE_MTLS_HEADER (production) tokens are issued and accepted only over a
 * gateway connection with one of them. Omitted, the registered list is kept.
 *
 * Prints the generated client_secret (and the webhook signing secret, if a
 * webhook URL is given) once; neither is shown again. If a secret is lost,
 * run this again with the same clientId to rotate it.
 */
async function main(): Promise<void> {
  await loadMasterKeys(); // MASTER_KEY_SOURCE=hsm: unwrap in the HSM
  const args = process.argv.slice(2);
  const options = args.filter((arg) => arg.startsWith('--'));
  const [clientId, webhookUrl] = args.filter((arg) => !arg.startsWith('--'));
  const modeOption = options.find((arg) => arg.startsWith('--push-mode='));
  const pushMode = (modeOption?.slice('--push-mode='.length) ?? 'BANK') as PushMode;
  const certOption = options.find((arg) => arg.startsWith('--mtls-cert-sha256='));
  const certificates = certOption?.slice('--mtls-cert-sha256='.length).split(',').map((v) => normalizeFingerprint(v));
  const unknown = options.filter((arg) => arg !== modeOption && arg !== certOption);
  if (!clientId || unknown.length > 0 || !['BANK', 'NEXUS'].includes(pushMode) || certificates?.some((c) => c === null)) {
    console.error('Usage: registerClient.js <clientId> [webhookUrl] [--push-mode=BANK|NEXUS] [--mtls-cert-sha256=<64 hex>[,<64 hex>]]');
    process.exitCode = 1;
    return;
  }

  const clientSecret = randomBytes(32).toString('base64url');
  const webhookSecret = webhookUrl ? randomBytes(32).toString('base64url') : undefined;

  await registerBankClient({ clientId, clientSecret, webhookUrl, webhookSecret, pushMode, mtlsCertSha256: certificates as string[] | undefined });
  // Rotating the secret also ends every session issued under the old one.
  const revoked = await revokeClientTokens(clientId);

  console.log(`Registered client "${clientId}" (push mode ${pushMode}).${revoked > 0 ? ` Revoked ${revoked} existing access token(s).` : ''}`);
  if (certificates) console.log(`Client certificates: ${certificates.join(', ')}`);
  console.log('');
  console.log(`  client_secret: ${clientSecret}`);
  if (webhookSecret) {
    console.log(`  webhook_secret: ${webhookSecret}`);
    console.log(`  (used by the bank to verify the X-NEXUS-SIGN-Signature header on incoming webhooks)`);
  }
  console.log('');
  console.log('Save these now — this is the only time they are printed.');
}

main()
  .catch((error: unknown) => {
    console.error('Failed to register client:', error);
    process.exitCode = 1;
  })
  .finally(() => {
    void pool.end();
    redis.disconnect();
  });
