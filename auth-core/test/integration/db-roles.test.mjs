// With scripts/db/roles.sql applied, Auth Core runs as a role that
// owns nothing, so it cannot disable or replace the protective triggers or
// rewrite evidence and audit records, and the service still works.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { ROOT, createDatabase, skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, submitSignature } from './support/actors.mjs';

const require = createRequire(import.meta.url);

describe('database roles', { skip: skipWithoutServices }, () => {
  let db; let server; let app;
  before(async () => {
    db = await createDatabase();
    await db.pool.query(readFileSync(join(ROOT, 'scripts/db/roles.sql'), 'utf8'));
    await db.pool.query(`ALTER ROLE nexus_app WITH LOGIN PASSWORD 'nexus-app-test'`);
    const url = new URL(db.url); url.username = 'nexus_app'; url.password = 'nexus-app-test';
    server = await startAuthCore({ database: { ...db, url: url.toString() } });
    const { Pool } = require('pg');
    app = new Pool({ connectionString: url.toString(), max: 2 });
  });
  after(async () => { await app?.end(); await server?.stop(); await db?.drop(); });

  test('the service runs a full confirmation as the application role', async () => {
    const bank = await bankSession(server, await server.registerBank('bank-roles'));
    const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const auth = await bank.createAuthorization(device);
    const { signature } = await deviceSignature(server, device, auth.authorizationId);
    assert.equal((await submitSignature(server, device, auth.authorizationId, signature)).json.status, 'VERIFIED');
  });

  test('the application role cannot touch the protections', async () => {
    for (const statement of [
      'ALTER TABLE evidence_records DISABLE TRIGGER ALL',
      'ALTER TABLE credentials DISABLE TRIGGER credential_lifecycle',
      'DROP TRIGGER audit_logs_no_update ON audit_logs',
      "CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger AS $$ BEGIN RETURN NEW; END $$ LANGUAGE plpgsql",
      'TRUNCATE audit_logs',
      'TRUNCATE evidence_records',
      'UPDATE evidence_records SET result = result',
      'DELETE FROM audit_logs',
      'DELETE FROM recovery_sessions',
      'DELETE FROM credentials',
      'DELETE FROM admin_approvals',
      'SET session_replication_role = replica',
      'CREATE TABLE stash (x int)',
    ]) {
      await assert.rejects(app.query(statement), /permission denied|must be owner|not allowed|append-only/, statement);
    }
    assert.ok((await app.query('SELECT count(*)::int AS n FROM audit_logs')).rows[0].n > 0);
  });
});
