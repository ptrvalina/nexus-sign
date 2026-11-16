// Master keys of stored secrets can be rotated. Secrets name their
// key; previous keys are accepted for decryption; cli/rotateSecretKeys.js
// re-encrypts under the current key; afterwards the old key is not needed
// and no longer works. The credential trigger lets only that tool change the
// offline key ciphertext.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { ROOT, baseEnvironment, createDatabase, processEnvironment, skipWithoutServices, startAuthCore, startExpectingFailure } from './support/harness.mjs';
import { adminSession, bankSession, deviceSignature, offlineCode } from './support/actors.mjs';

const key = () => randomBytes(32).toString('base64');
const keyId = (b64) => createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex').slice(0, 16);

function runCli(env, ...args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(ROOT, 'dist/cli/rotateSecretKeys.js'), ...args], { env, cwd: ROOT });
    let output = '';
    child.stdout.on('data', (d) => { output += d; });
    child.stderr.on('data', (d) => { output += d; });
    child.on('close', (code) => resolve({ code, output }));
  });
}

describe('master key rotation of stored secrets', { skip: skipWithoutServices }, () => {
  const old = { DEVICE_SECRET_ENCRYPTION_KEY: key(), WEBHOOK_SECRET_ENCRYPTION_KEY: key(), ADMIN_SECRET_ENCRYPTION_KEY: key() };
  const fresh = { DEVICE_SECRET_ENCRYPTION_KEY: key(), WEBHOOK_SECRET_ENCRYPTION_KEY: key(), ADMIN_SECRET_ENCRYPTION_KEY: key() };
  const rotating = Object.fromEntries(Object.entries(fresh).flatMap(([name, value]) => [[name, value], [`${name}_PREVIOUS`, old[name]]]));
  let database; let client; let device; const admins = [];
  // The software HSM makes a new evidence key per process; the credential's
  // sealed enrolment record needs the first process's key as a retired key.
  let firstEvidenceKey;
  // Offline codes here show that the offline key decrypts; protocol v1 makes
  // an accepted code read VERIFIED (v2: offline-deferred-signature.test.mjs).
  const V1 = { OFFLINE_CONFIRMATION_MODE: 'immediate' };
  const withEvidence = (env) => ({ ...env, ...V1, EVIDENCE_RETIRED_PUBLIC_KEYS_PEM: firstEvidenceKey });

  async function confirmOffline(server) {
    const bank = await bankSession(server, client);
    const auth = await bank.createAuthorization(device);
    const { canonical } = await deviceSignature(server, device, auth.authorizationId);
    const response = await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(device, canonical) } });
    return { ...response, authorizationId: auth.authorizationId, bank };
  }

  before(async () => {
    database = await createDatabase();
    const server = await startAuthCore({ database, env: { ...old, ...V1 } });
    try {
      client = await server.registerBank('bank-rotation', { webhookUrl: 'https://bank.example/hooks' });
      const bank = await bankSession(server, client);
      device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
      for (const name of ['rot-admin-1', 'rot-admin-2', 'rot-admin-3']) admins.push(await server.createAdmin(name, 'auditor'));
      const baseline = await confirmOffline(server);
      assert.equal(baseline.json.status, 'VERIFIED', 'baseline under the old key');
      const evidence = await baseline.bank.call('GET', `/v1/authorizations/${baseline.authorizationId}/evidence`);
      firstEvidenceKey = evidence.json?.evidencePublicKeyPem;
      assert.ok(firstEvidenceKey, `evidence key: ${evidence.text}`);
    } finally {
      await server.stop();
    }
  });
  after(async () => { await database?.drop(); });

  test('with the new key current and the old one previous, everything still works; the tool re-encrypts', async () => {
    const server = await startAuthCore({ database, env: withEvidence(rotating) });
    try {
      assert.equal((await confirmOffline(server)).json.status, 'VERIFIED', 'offline key under the previous key');
      assert.equal((await adminSession(server, admins[0])).login.status, 200, 'TOTP secret under the previous key');

      const dry = await runCli(server.env, '--dry-run');
      assert.equal(dry.code, 0, dry.output);
      assert.match(dry.output, /credentials\.offline_secret_encrypted: 1 stored, 0 already under the current key, 1 to re-encrypt/);
      assert.match(dry.output, /Dry run: nothing written/);

      const run = await runCli(server.env);
      assert.equal(run.code, 0, run.output);
      assert.match(run.output, /bank_clients\.webhook_secret_encrypted: 1 stored, 0 already under the current key, 1 re-encrypted/);
      assert.match(run.output, /credentials\.offline_secret_encrypted: 1 stored, 0 already under the current key, 1 re-encrypted/);
      assert.match(run.output, /admin_users\.totp_secret_encrypted: 3 stored, 0 already under the current key, 3 re-encrypted/);

      const stored = await server.db.query(`SELECT offline_secret_encrypted FROM credentials WHERE credential_id = $1`, [device.credentialId]);
      assert.equal(stored.rows[0].offline_secret_encrypted.split('$').slice(0, 2).join('$'), `k1$${keyId(fresh.DEVICE_SECRET_ENCRYPTION_KEY)}`);
      const again = await runCli(server.env);
      assert.match(again.output, /credentials\.offline_secret_encrypted: 1 stored, 1 already under the current key, 0 re-encrypted/, 'idempotent');

      const audit = await server.db.query(`SELECT details FROM audit_logs WHERE event_type = 'master_key_rotated' ORDER BY timestamp`);
      assert.ok(audit.rows.some((r) => r.details.purpose === 'device' && r.details.rewrapped === 1 && r.details.currentKeyId === keyId(fresh.DEVICE_SECRET_ENCRYPTION_KEY)));
    } finally {
      await server.stop();
    }
  });

  test('after the rotation the old key is not needed, and alone it no longer works', async () => {
    const server = await startAuthCore({ database, env: withEvidence(fresh) });
    try {
      assert.equal((await confirmOffline(server)).json.status, 'VERIFIED', 'new key only');
      assert.equal((await adminSession(server, admins[1])).login.status, 200);
    } finally {
      await server.stop();
    }
    const stale = await startAuthCore({ database, env: withEvidence(old) });
    try {
      const refused = await confirmOffline(stale);
      assert.notEqual(refused.json?.status, 'VERIFIED', 'the old key cannot open secrets written under the new one');
      assert.notEqual((await adminSession(stale, admins[2])).login.status, 200);
    } finally {
      await stale.stop();
    }
  });

  test('the offline key ciphertext is immutable outside the rotation tool', async () => {
    const server = await startAuthCore({ database, env: withEvidence(fresh) });
    try {
      await assert.rejects(server.db.query(`UPDATE credentials SET offline_secret_encrypted = offline_secret_encrypted || 'x' WHERE credential_id = $1`, [device.credentialId]), /immutable/);
      const tx = await server.db.connect();
      try {
        await tx.query('BEGIN');
        await tx.query(`SELECT set_config('nexus.secret_rewrap', 'on', true)`);
        await assert.rejects(tx.query(`UPDATE credentials SET offline_secret_encrypted = NULL, offline_server_public_key_pem = NULL WHERE credential_id = $1`, [device.credentialId]), /immutable/, 'presence cannot change');
      } finally {
        await tx.query('ROLLBACK').catch(() => undefined);
        tx.release();
      }
    } finally {
      await server.stop();
    }
  });

  test('a secret under an unknown key stops the tool before anything is written', async () => {
    const env = { ...processEnvironment(), ...baseEnvironment(), DATABASE_URL: database.url, REDIS_URL: process.env.INTEGRATION_REDIS_URL, ...Object.fromEntries(Object.keys(fresh).map((n) => [n, key()])) };
    const result = await runCli(env);
    assert.equal(result.code, 1);
    assert.match(result.output, /cannot be decrypted with the configured keys; nothing was changed/);
  });

  test('a previous key equal to the current one is a configuration error', async () => {
    const { code, log } = await startExpectingFailure({ DEVICE_SECRET_ENCRYPTION_KEY: fresh.DEVICE_SECRET_ENCRYPTION_KEY, DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS: fresh.DEVICE_SECRET_ENCRYPTION_KEY });
    assert.notEqual(code, 'still-running');
    assert.match(log, /DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS must not repeat the current/);
  });
});
