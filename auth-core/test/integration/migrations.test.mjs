// Database migrations under a ledger (audit finding C-06), on PostgreSQL.
// Before, migrations 002 to 022 could not build a database from empty, and
// nothing recorded which migrations a database had: an upgrade could not be
// checked. Now `migrate()` installs from an empty database, adopts a database
// installed before the ledger only when told its version, refuses changed,
// missing or out-of-order migrations, and applies each migration with its
// ledger row in one transaction.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { ROOT, createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';

const { migrate, planMigrations, readMigrations, schemaVersionOf } = loadTs('db/migrator.ts');
const MIGRATIONS = join(ROOT, 'migrations');
const SCHEMA = readFileSync(join(ROOT, 'src/db/schema.sql'), 'utf8');
const RC2_SCHEMA = readFileSync(join(ROOT, 'test/fixtures/schema-2.0.0-rc.2.sql'), 'utf8');

/** Tables, columns, constraints, indexes, triggers and functions, as sorted text. */
async function shape(client) {
  const q = async (sql) => (await client.query(sql)).rows.map((r) => Object.values(r).join('|')).sort();
  return {
    columns: await q(`SELECT table_name, column_name, data_type, coalesce(character_maximum_length::text,''), is_nullable, coalesce(column_default,'')
                        FROM information_schema.columns WHERE table_schema = 'public' AND table_name <> 'schema_migrations'`),
    constraints: await q(`SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid) FROM pg_constraint
                           WHERE connamespace = 'public'::regnamespace AND conrelid::regclass::text <> 'schema_migrations'`),
    indexes: await q(`SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename <> 'schema_migrations'`),
    triggers: await q(`SELECT tgrelid::regclass::text, tgname, pg_get_triggerdef(oid) FROM pg_trigger
                        WHERE NOT tgisinternal AND tgrelid::regclass::text <> 'schema_migrations'`),
    functions: await q(`SELECT proname, md5(prosrc), coalesce(array_to_string(proconfig, ','), '') FROM pg_proc
                         WHERE pronamespace = 'public'::regnamespace AND proname <> 'schema_migrations_append_only'`),
  };
}

describe('database migrations with a ledger (PostgreSQL)', { skip: skipWithoutServices }, () => {
  const databases = [];
  const clients = [];
  async function database(options) {
    const db = await createDatabase(options);
    databases.push(db);
    const client = new pg.Client({ connectionString: db.url });
    await client.connect();
    clients.push(client);
    return client;
  }
  let work;
  before(() => { work = mkdtempSync(join(tmpdir(), 'nexus-migrations-')); });
  after(async () => {
    for (const c of clients) await c.end().catch(() => {});
    for (const d of databases) await d.drop().catch(() => {});
    rmSync(work, { recursive: true, force: true });
  });
  const copyOfMigrations = (name) => { const dir = join(work, name); cpSync(MIGRATIONS, dir, { recursive: true }); return dir; };
  const ledger = async (client) => (await client.query(`SELECT version, mode FROM schema_migrations ORDER BY version`)).rows;

  test('schema.sql states the last migration, and the files are numbered without gaps', () => {
    const { files, problems } = readMigrations(MIGRATIONS);
    assert.deepEqual(problems, []);
    assert.equal(schemaVersionOf(SCHEMA), files[files.length - 1].version);
  });

  test('a fresh install from an empty database equals schema.sql plus every migration, and a second run does nothing', async () => {
    const fresh = await database({ schema: false });
    const result = await migrate(fresh, { migrationsDir: MIGRATIONS, schemaSql: SCHEMA });
    assert.equal(result.installed, true);
    const rows = await ledger(fresh);
    assert.equal(rows.length, readMigrations(MIGRATIONS).files.length);
    assert.ok(rows.every((r) => r.mode === 'BASELINE'));
    assert.deepEqual(await migrate(fresh, { migrationsDir: MIGRATIONS, schemaSql: SCHEMA }), { installed: false, adopted: [], applied: [] });
    const plan = await planMigrations(fresh, readMigrations(MIGRATIONS).files);
    assert.deepEqual([plan.state, plan.pending.length, plan.problems], ['TRACKED', 0, []]);

    const reference = await database(); // the harness: schema.sql, then every migration file with psql semantics
    assert.deepEqual(await shape(fresh), await shape(reference));
  });

  test('upgrade from the 2.0.0-rc.2 schema: adopted at 022, then 023 onwards applied, ending equal to a fresh install', async () => {
    const old = await database({ schema: false });
    await old.query(RC2_SCHEMA);
    await old.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ('bank-old', 'x');
      INSERT INTO nexus_identities (nexus_id, client_id, bank_customer_ref) VALUES ('100000777', 'bank-old', 'c-1')`);
    await assert.rejects(migrate(old, { migrationsDir: MIGRATIONS, schemaSql: SCHEMA }), /no migration ledger: state the last migration/);
    assert.equal((await old.query(`SELECT to_regclass('public.schema_migrations') AS t`)).rows[0].t, null, 'a refusal changes nothing');

    const result = await migrate(old, { migrationsDir: MIGRATIONS, schemaSql: SCHEMA, adoptAt: 22 });
    assert.equal(result.adopted.length, 21);
    assert.deepEqual(result.applied, readMigrations(MIGRATIONS).files.filter((f) => f.version > 22).map((f) => f.version));
    assert.equal((await old.query(`SELECT count(*)::int AS n FROM nexus_identities WHERE nexus_id = '100000777'`)).rows[0].n, 1, 'data kept');
    const fresh = await database({ schema: false });
    await migrate(fresh, { migrationsDir: MIGRATIONS, schemaSql: SCHEMA });
    assert.deepEqual(await shape(old), await shape(fresh));
  });

  test('a migration changed or removed after it was applied, or a gap in the numbering, stops the run before any change', async () => {
    const db = await database({ schema: false });
    await migrate(db, { migrationsDir: MIGRATIONS, schemaSql: SCHEMA });
    const changed = copyOfMigrations('changed');
    appendFileSync(join(changed, '024_authorization_insert_state.sql'), '\n-- edited later\n');
    await assert.rejects(migrate(db, { migrationsDir: changed, schemaSql: SCHEMA }), /migration 24 \(024_authorization_insert_state.sql\) was changed after it was applied/);

    const removed = copyOfMigrations('removed');
    rmSync(join(removed, '025_evidence_outcomes.sql'));
    await assert.rejects(migrate(db, { migrationsDir: removed, schemaSql: SCHEMA }), /migration 25 .* missing from this release/);

    const gap = copyOfMigrations('gap');
    writeFileSync(join(gap, '027_later.sql'), 'SELECT 1;');
    await assert.rejects(migrate(db, { migrationsDir: gap, schemaSql: SCHEMA }), /leave a gap/);
    assert.equal((await ledger(db)).length, readMigrations(MIGRATIONS).files.length);
  });

  test('a failing migration leaves neither its changes nor a ledger row; the ledger is append-only', async () => {
    const db = await database({ schema: false });
    await migrate(db, { migrationsDir: MIGRATIONS, schemaSql: SCHEMA });
    const bad = copyOfMigrations('bad');
    writeFileSync(join(bad, '026_half_done.sql'), 'CREATE TABLE half_done (id int);\nSELECT * FROM table_that_does_not_exist;');
    await assert.rejects(migrate(db, { migrationsDir: bad, schemaSql: SCHEMA }), /table_that_does_not_exist/);
    assert.equal((await db.query(`SELECT to_regclass('public.half_done') AS t`)).rows[0].t, null);
    assert.equal((await ledger(db)).some((r) => r.version === 26), false);

    writeFileSync(join(bad, '026_half_done.sql'), 'CREATE TABLE half_done (id int);');
    assert.deepEqual((await migrate(db, { migrationsDir: bad, schemaSql: SCHEMA })).applied, [26]);
    await assert.rejects(db.query(`DELETE FROM schema_migrations WHERE version = 26`), /append-only/);
    await assert.rejects(db.query(`UPDATE schema_migrations SET checksum = repeat('0', 64) WHERE version = 26`), /append-only/);
  });

  test('two runs at once apply each migration once', async () => {
    const created = await createDatabase({ schema: false });
    databases.push(created);
    const a = new pg.Client({ connectionString: created.url }); const b = new pg.Client({ connectionString: created.url });
    await a.connect(); await b.connect(); clients.push(a, b);
    const results = await Promise.allSettled([
      migrate(a, { migrationsDir: MIGRATIONS, schemaSql: SCHEMA }),
      migrate(b, { migrationsDir: MIGRATIONS, schemaSql: SCHEMA }),
    ]);
    assert.ok(results.every((r) => r.status === 'fulfilled'), JSON.stringify(results.map((r) => r.reason?.message)));
    assert.equal(results.filter((r) => r.value.installed).length, 1);
    assert.equal((await ledger(a)).length, readMigrations(MIGRATIONS).files.length);
  });

  test('a schema.sql behind the migrations is refused at a fresh install', async () => {
    const db = await database({ schema: false });
    const ahead = copyOfMigrations('ahead');
    writeFileSync(join(ahead, '026_new.sql'), 'SELECT 1;');
    const stale = SCHEMA.replace(/^-- schema-version: \d{3}$/m, '-- schema-version: 027');
    await assert.rejects(migrate(db, { migrationsDir: ahead, schemaSql: stale }), /states version 27, but the last migration is 26/);
    // An older schema.sql with later migration files is fine: they are applied.
    const result = await migrate(db, { migrationsDir: ahead, schemaSql: SCHEMA });
    assert.deepEqual(result.applied, [26]);
    renameSync(join(ahead, '026_new.sql'), join(ahead, '026_new.sql.off'));
  });
});
