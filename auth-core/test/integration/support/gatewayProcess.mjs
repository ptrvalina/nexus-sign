// The payment gateway in its own process, as a bank would run it: its own
// database role, mutual TLS towards the execution boundary, the provider
// over HTTP. Test harness entry point (support/bankSide.mjs).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { createGatewayServer, createHttpProvider, createPaymentGateway } from '../../../../bank-integration/index.mjs';

const dir = process.env.GATEWAY_TLS_DIR;
const pool = new pg.Pool({ connectionString: process.env.GATEWAY_DATABASE_URL, max: 4 });
const keys = JSON.parse(readFileSync(process.env.GATEWAY_KEYS_FILE, 'utf8'));
const gateway = createPaymentGateway({
  pool, provider: createHttpProvider({ url: process.env.GATEWAY_PROVIDER_URL, timeoutMs: 5_000 }),
  evidenceKeys: keys.evidenceKeys, bankTrustKeys: keys.bankTrustKeys,
});
const server = createGatewayServer({
  gateway,
  tls: { key: readFileSync(join(dir, 'gateway.key')), cert: readFileSync(join(dir, 'gateway.crt')), ca: readFileSync(join(dir, 'bank-ca.crt')) },
  allowedClients: process.env.GATEWAY_ALLOWED_CLIENTS.split(','),
});
server.listen(0, '127.0.0.1', () => process.stdout.write(`listening ${server.address().port}\n`));
process.on('SIGTERM', () => { server.close(); pool.end().finally(() => process.exit(0)); });
