// Device request nonces can be deleted only after they expire (migration 031,
// audit finding C-11), also by the application role that runs the expiry
// sweep. Deleting a live nonce would let a captured device request be
// replayed inside its timestamp window.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { ROOT, createDatabase, skipWithoutServices } from './support/harness.mjs';

describe('device request nonces are deleted only after expiry (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let owner; let app;
  before(async () => {
    db = await createDatabase();
    owner = new pg.Client({ connectionString: db.url });
    await owner.connect();
    // The deployment's roles, as in the database roles suite.
    await owner.query(readFileSync(join(ROOT, 'scripts/db/roles.sql'), 'utf8'));
    await owner.query(`ALTER ROLE nexus_app WITH LOGIN PASSWORD 'nexus-app-test'`);
    const url = new URL(db.url); url.username = 'nexus_app'; url.password = 'nexus-app-test';
    app = new pg.Client({ connectionString: url.toString() });
    await app.connect();
  });
  after(async () => { await app?.end(); await owner?.end(); await db?.drop(); });

  const insert = (client, seconds) => client.query(
    `INSERT INTO device_request_nonces (credential_id, nonce, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3)) RETURNING nonce`,
    [randomUUID(), randomUUID().replace(/-/g, ''), seconds]);

  test('a live nonce cannot be deleted, by the application role or the owner', async () => {
    const live = (await insert(app, 300)).rows[0].nonce;
    for (const client of [app, owner]) {
      await assert.rejects(client.query(`DELETE FROM device_request_nonces WHERE nonce = $1`, [live]), /has not expired \(DELETE refused\)/);
    }
    assert.equal((await app.query(`SELECT count(*)::int AS n FROM device_request_nonces WHERE nonce = $1`, [live])).rows[0].n, 1);
  });

  test('the application role cannot move a live nonce into the past to delete it', async () => {
    const live = (await insert(app, 300)).rows[0].nonce;
    await assert.rejects(app.query(`UPDATE device_request_nonces SET expires_at = now() - interval '1 second' WHERE nonce = $1`, [live]), /permission denied/);
    await assert.rejects(app.query(`TRUNCATE device_request_nonces`), /permission denied/);
  });

  test('the expiry sweep deletes expired nonces only', async () => {
    const expired = (await insert(app, -5)).rows[0].nonce;
    const live = (await insert(app, 300)).rows[0].nonce;
    // The statement of authorizationExpiry.ts.
    const swept = await app.query(`DELETE FROM device_request_nonces WHERE ctid IN (
       SELECT ctid FROM device_request_nonces WHERE expires_at < now() LIMIT $1)`, [1000]);
    assert.ok(swept.rowCount >= 1);
    const left = (await app.query(`SELECT nonce FROM device_request_nonces WHERE nonce = ANY($1)`, [[expired, live]])).rows.map((r) => r.nonce);
    assert.deepEqual(left, [live]);
  });

  test('the guard is installed by the migration as well as by schema.sql', () => {
    const migration = readFileSync(join(ROOT, 'migrations/031_device_nonce_delete_guard.sql'), 'utf8');
    const schema = readFileSync(join(ROOT, 'src/db/schema.sql'), 'utf8');
    for (const text of [migration, schema]) assert.match(text, /CREATE TRIGGER device_request_nonces_expired_only BEFORE DELETE ON device_request_nonces/);
  });
});
