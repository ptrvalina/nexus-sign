// the master key rotation tool killed in the middle of a run.
// 260 offline-key secrets (one real enrolled device among them) are rotated
// in batches of 200; the second batch is held on a row lock and the tool is
// killed (SIGKILL). Afterwards every secret is under the old or the new key,
// none is damaged, Auth Core with both keys in the ring works, a second run
// finishes the rotation, and then the old key is not needed.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import pg from 'pg';
import { ROOT, createDatabase, skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, offlineCode } from './support/actors.mjs';

const key = () => randomBytes(32).toString('base64');
const keyId = (b64) => createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex').slice(0, 16);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** k1 secret exactly as secretBox writes it. */
function seal(masterB64, plaintext, aad) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', Buffer.from(masterB64, 'base64'), iv); c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return ['k1', keyId(masterB64), iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join('$');
}
function open(ring, value, aad) {
  const [, id, iv, tag, ct] = value.split('$');
  const master = ring.find((k) => keyId(k) === id);
  if (!master) throw new Error(`no key ${id}`);
  const d = createDecipheriv('aes-256-gcm', Buffer.from(master, 'base64'), Buffer.from(iv, 'base64')); d.setAAD(Buffer.from(aad)); d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]);
}

describe('master key rotation interrupted mid-run', { skip: skipWithoutServices }, () => {
  const old = { DEVICE_SECRET_ENCRYPTION_KEY: key(), WEBHOOK_SECRET_ENCRYPTION_KEY: key(), ADMIN_SECRET_ENCRYPTION_KEY: key() };
  const fresh = { DEVICE_SECRET_ENCRYPTION_KEY: key(), WEBHOOK_SECRET_ENCRYPTION_KEY: key(), ADMIN_SECRET_ENCRYPTION_KEY: key() };
  const rotating = Object.fromEntries(Object.entries(fresh).flatMap(([n, v]) => [[n, v], [`${n}_PREVIOUS`, old[n]]]));
  const V1 = { OFFLINE_CONFIRMATION_MODE: 'immediate' };
  let database; let client; let device; let evidenceKey; const synthetic = new Map();

  before(async () => {
    database = await createDatabase();
    const server = await startAuthCore({ database, env: { ...old, ...V1 } });
    try {
      client = await server.registerBank('bank-rotation-kill');
      const bank = await bankSession(server, client);
      device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
      const auth = await bank.createAuthorization(device);
      const { canonical } = await deviceSignature(server, device, auth.authorizationId);
      assert.equal((await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(device, canonical) } })).json.status, 'VERIFIED');
      evidenceKey = (await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/evidence`)).json.evidencePublicKeyPem;
      // 259 more stored offline keys under the old master key (revoked credentials
      // of their own identities), so the tool needs two batches.
      for (let i = 0; i < 259; i += 1) {
        const nexusId = String(500000000 + i);
        const credentialId = randomUUID();
        const secret = randomBytes(32);
        synthetic.set(credentialId, secret);
        await server.db.query(`INSERT INTO nexus_identities (nexus_id, client_id, bank_customer_ref) VALUES ($1, $2, $3)`, [nexusId, client.clientId, `synthetic-${i}`]);
        await server.db.query(`INSERT INTO credentials (credential_id, nexus_id, key_algorithm, public_key_pem, platform, security_level, state, offline_secret_encrypted, offline_server_public_key_pem)
          VALUES ($1, $2, 'ES256', 'pem', 'OTHER', 'SOFTWARE', 'REVOKED', $3, 'pem')`, [credentialId, nexusId, seal(old.DEVICE_SECRET_ENCRYPTION_KEY, secret, `device:${credentialId}`)]);
      }
    } finally {
      await server.stop();
    }
  });
  after(async () => { await database?.drop(); });

  const env = (keys) => ({ ...process.env, ...keys, ...V1, DATABASE_URL: database.url, REDIS_URL: process.env.INTEGRATION_REDIS_URL ?? 'redis://127.0.0.1:6379', NODE_ENV: 'development', ALLOW_INSECURE_DEVELOPMENT: 'true', HSM_ADAPTER: 'software' });
  const stored = async () => (await database.pool.query(`SELECT credential_id::text AS id, offline_secret_encrypted AS v FROM credentials WHERE offline_secret_encrypted IS NOT NULL ORDER BY credential_id::text`)).rows;

  test('killed during the second batch: every secret intact under one of the two keys; a second run completes', async () => {
    const before = await stored();
    assert.equal(before.length, 260);
    // Hold the 230th row (in the second batch of 200) so the tool stops there.
    const held = before[229].id;
    const blocker = new pg.Client({ connectionString: database.url });
    await blocker.connect();
    await blocker.query('BEGIN');
    await blocker.query(`SELECT 1 FROM credentials WHERE credential_id::text = $1 FOR UPDATE`, [held]);

    const tool = spawn(process.execPath, [join(ROOT, 'dist/cli/rotateSecretKeys.js')], { env: env(rotating), cwd: ROOT });
    let output = ''; tool.stdout.on('data', (d) => { output += d; }); tool.stderr.on('data', (d) => { output += d; });
    const exited = new Promise((r) => tool.on('exit', (code, signal) => r({ code, signal })));
    // Wait until the first batch is committed, then until the tool waits on the lock.
    let newCount = 0;
    for (let i = 0; i < 200 && newCount < 200; i += 1) {
      await sleep(100);
      newCount = (await stored()).filter((r) => r.v.split('$')[1] === keyId(fresh.DEVICE_SECRET_ENCRYPTION_KEY)).length;
    }
    assert.equal(newCount, 200, `first batch committed: ${output}`);
    await sleep(500);
    tool.kill('SIGKILL');
    const end = await exited;
    assert.equal(end.signal, 'SIGKILL');
    await blocker.query('ROLLBACK'); await blocker.end();

    const mid = await stored();
    const ids = mid.map((r) => r.v.split('$')[1]);
    assert.equal(ids.filter((k) => k === keyId(fresh.DEVICE_SECRET_ENCRYPTION_KEY)).length, 200, 'the interrupted batch was rolled back entirely');
    assert.equal(ids.filter((k) => k === keyId(old.DEVICE_SECRET_ENCRYPTION_KEY)).length, 60);
    const ring = [fresh.DEVICE_SECRET_ENCRYPTION_KEY, old.DEVICE_SECRET_ENCRYPTION_KEY];
    for (const row of mid) {
      if (synthetic.has(row.id)) assert.deepEqual(open(ring, row.v, `device:${row.id}`), synthetic.get(row.id), `secret ${row.id} intact`);
    }

    // Auth Core with the ring (new current, old previous) works in between.
    const server = await startAuthCore({ database, env: { ...rotating, ...V1, EVIDENCE_RETIRED_PUBLIC_KEYS_PEM: evidenceKey } });
    try {
      const bank = await bankSession(server, client);
      const auth = await bank.createAuthorization(device);
      const { canonical } = await deviceSignature(server, device, auth.authorizationId);
      assert.equal((await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(device, canonical) } })).json.status, 'VERIFIED');
    } finally { await server.stop(); }

    // The second run finishes; then the old key is no longer needed.
    const second = await new Promise((resolve) => {
      const t = spawn(process.execPath, [join(ROOT, 'dist/cli/rotateSecretKeys.js')], { env: env(rotating), cwd: ROOT });
      let o = ''; t.stdout.on('data', (d) => { o += d; }); t.stderr.on('data', (d) => { o += d; });
      t.on('close', (code) => resolve({ code, o }));
    });
    assert.equal(second.code, 0, second.o);
    assert.match(second.o, /credentials\.offline_secret_encrypted: 260 stored, 200 already under the current key, 60 re-encrypted/);
    for (const row of await stored()) {
      assert.equal(row.v.split('$')[1], keyId(fresh.DEVICE_SECRET_ENCRYPTION_KEY));
      if (synthetic.has(row.id)) assert.deepEqual(open([fresh.DEVICE_SECRET_ENCRYPTION_KEY], row.v, `device:${row.id}`), synthetic.get(row.id));
    }
    const after = await startAuthCore({ database, env: { ...fresh, ...V1, EVIDENCE_RETIRED_PUBLIC_KEYS_PEM: evidenceKey } });
    try {
      const bank = await bankSession(after, client);
      const auth = await bank.createAuthorization(device);
      const { canonical } = await deviceSignature(after, device, auth.authorizationId);
      assert.equal((await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(device, canonical) } })).json.status, 'VERIFIED', 'old key not needed');
    } finally { await after.stop(); }
  });
});
