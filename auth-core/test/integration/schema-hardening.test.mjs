// Schema hardening (audit findings C-15, C-16), on PostgreSQL with the full
// schema and the real scripts/db/roles.sql.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { ROOT, createDatabase, skipWithoutServices } from './support/harness.mjs';

describe('schema hardening (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin;
  before(async () => {
    db = await createDatabase();
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(readFileSync(join(ROOT, 'scripts/db/roles.sql'), 'utf8'));
  });
  after(async () => { await admin?.end(); await db?.drop(); });

  test('every function of the schema runs with a fixed search_path (C-15)', async () => {
    const unpinned = (await admin.query(`SELECT p.oid::regprocedure::text AS f FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.prokind = 'f' AND p.prolang IN (SELECT oid FROM pg_language WHERE lanname IN ('plpgsql', 'sql'))
        AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')
        AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}')) c WHERE c LIKE 'search_path=%')`)).rows.map((r) => r.f);
    assert.deepEqual(unpinned, []);
    const triggers = (await admin.query(`SELECT count(*)::int AS n FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND NOT t.tgisinternal`)).rows[0].n;
    assert.ok(triggers > 20, `the schema has its triggers (${triggers})`);
  });

  test('the application role has no temporary objects (C-15)', async () => {
    const { rows } = await admin.query(`SELECT has_database_privilege('nexus_app', current_database(), 'TEMPORARY') AS temp`);
    assert.equal(rows[0].temp, false);
  });

  test('tables that keep a history refuse TRUNCATE, even for a superuser (C-16)', async () => {
    for (const table of ['offline_deferred_signatures', 'offline_challenges', 'authorization_requests', 'credentials', 'nexus_identities', 'admin_approvals']) {
      await assert.rejects(admin.query(`TRUNCATE ${table} CASCADE`), /TRUNCATE refused/, table);
    }
  });
});
