// Replacing a credential's offline-secret ciphertext needs more than the
// nexus.secret_rewrap setting when the session is the application role: it
// must also hold nexus_secret_rotator (migration 033, findings B-09, C-08).
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { ROOT, createDatabase, skipWithoutServices } from './support/harness.mjs';

describe('re-encrypting stored secrets needs the rotator role (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let owner; const credentialId = randomUUID();
  const connectAs = async (user) => {
    const url = new URL(db.url); url.username = user; url.password = 'rewrap-test';
    const client = new pg.Client({ connectionString: url.toString() });
    await client.connect();
    return client;
  };
  const operator = `rotator_${randomUUID().replace(/-/g, '').slice(0, 10)}`;
  before(async () => {
    db = await createDatabase();
    owner = new pg.Client({ connectionString: db.url });
    await owner.connect();
    await owner.query(readFileSync(join(ROOT, 'scripts/db/roles.sql'), 'utf8'));
    await owner.query(`ALTER ROLE nexus_app WITH LOGIN PASSWORD 'rewrap-test'`);
    await owner.query(`CREATE ROLE ${operator} LOGIN PASSWORD 'rewrap-test' IN ROLE nexus_app, nexus_secret_rotator`);
    await owner.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ('bank-b09', 'x');
      INSERT INTO nexus_identities (nexus_id, client_id, bank_customer_ref) VALUES ('100000009', 'bank-b09', 'c-9')`);
    await owner.query(`INSERT INTO credentials (credential_id, nexus_id, key_algorithm, public_key_pem, platform, security_level, offline_secret_encrypted, offline_server_public_key_pem)
      VALUES ($1, '100000009', 'ES256', 'pem', 'IOS', 'SECURE_ENCLAVE', 'k1$old', 'server-pem')`, [credentialId]);
  });
  after(async () => { await owner?.query(`DROP OWNED BY ${operator}; DROP ROLE ${operator}`).catch(() => undefined); await owner?.end(); await db?.drop(); });

  const rewrap = async (client, value) => {
    await client.query('BEGIN');
    try {
      await client.query(`SELECT set_config('nexus.secret_rewrap', 'on', true)`);
      await client.query(`UPDATE credentials SET offline_secret_encrypted = $2 WHERE credential_id = $1`, [credentialId, value]);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  };

  test('the application role cannot replace the ciphertext, even with the setting', async () => {
    const app = await connectAs('nexus_app');
    try {
      await assert.rejects(rewrap(app, 'k1$swapped'), /keys and identity binding are immutable/);
    } finally { await app.end(); }
  });

  test('an operator login with nexus_secret_rotator can, as rotateSecretKeys.js does', async () => {
    const client = await connectAs(operator);
    try {
      await rewrap(client, 'k1$rotated');
    } finally { await client.end(); }
    assert.equal((await owner.query(`SELECT offline_secret_encrypted FROM credentials WHERE credential_id = $1`, [credentialId])).rows[0].offline_secret_encrypted, 'k1$rotated');
  });

  test('without the setting nobody can, and the offline key cannot be removed', async () => {
    const client = await connectAs(operator);
    try {
      await assert.rejects(client.query(`UPDATE credentials SET offline_secret_encrypted = 'k1$x' WHERE credential_id = $1`, [credentialId]), /immutable/);
      await assert.rejects(rewrap(client, null), /immutable/);
    } finally { await client.end(); }
  });
});
