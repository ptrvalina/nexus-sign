import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Database migrations with a ledger (audit finding C-06).
 *
 * - The ledger `schema_migrations` records every migration file applied, with
 *   the SHA-256 of the file and how it got there: APPLIED (run by this tool),
 *   BASELINE (contained in schema.sql at a fresh install) or ADOPTED (declared
 *   already applied when an existing database was first put under the
 *   ledger). It is append-only.
 * - A fresh install starts from an empty database: schema.sql, which states
 *   the migration it contains (`-- schema-version: NNN`), then every later
 *   migration file, each in its own transaction with its ledger row.
 * - An existing database without a ledger is adopted only when the operator
 *   states the last migration it has (`adoptAt`); nothing is guessed.
 * - On every run the files are checked: numbered without gaps or duplicates,
 *   applied files unchanged (checksum), no applied file missing, the ledger a
 *   contiguous prefix of the files. Any mismatch stops before any change.
 * - One run at a time (advisory lock). A migration and its ledger row commit
 *   together, so a failed migration leaves nothing half-applied.
 *
 * Migrations are forward-only; the rollback path is the backup taken before
 * the upgrade (docs/operations/database-migrations.md).
 */

export interface MigrationFile { version: number; name: string; checksum: string; sql: string }
export interface LedgerRow { version: number; name: string; checksum: string; mode: 'APPLIED' | 'BASELINE' | 'ADOPTED' }
export interface Queryable { query: (sql: string, args?: unknown[]) => Promise<{ rows: any[]; rowCount?: number | null }> }

export interface MigrationPlan {
  state: 'EMPTY' | 'UNTRACKED' | 'TRACKED';
  applied: LedgerRow[];
  pending: MigrationFile[];
  problems: string[];
}

const LOCK_KEY = 'nexus-sign:schema-migrations';

export const LEDGER_SQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version      INTEGER PRIMARY KEY CHECK (version > 0),
    name         TEXT NOT NULL,
    checksum     CHAR(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    mode         VARCHAR(8) NOT NULL CHECK (mode IN ('APPLIED','BASELINE','ADOPTED')),
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    applied_by   TEXT NOT NULL DEFAULT current_user
);
CREATE OR REPLACE FUNCTION schema_migrations_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  RAISE EXCEPTION 'schema_migrations is append-only (% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;
DROP TRIGGER IF EXISTS schema_migrations_append_only ON schema_migrations;
CREATE TRIGGER schema_migrations_append_only BEFORE UPDATE OR DELETE ON schema_migrations
  FOR EACH ROW EXECUTE FUNCTION schema_migrations_append_only();
DROP TRIGGER IF EXISTS schema_migrations_no_truncate ON schema_migrations;
CREATE TRIGGER schema_migrations_no_truncate BEFORE TRUNCATE ON schema_migrations
  FOR EACH STATEMENT EXECUTE FUNCTION schema_migrations_append_only();
`;

const sha256 = (data: Buffer | string): string => createHash('sha256').update(data).digest('hex');

/** Reads `NNN_name.sql` files; problems in numbering are reported, not fixed. */
export function readMigrations(directory: string): { files: MigrationFile[]; problems: string[] } {
  const problems: string[] = [];
  const files: MigrationFile[] = [];
  for (const entry of readdirSync(directory).filter((f) => f.endsWith('.sql')).sort()) {
    const match = /^(\d{3})_([a-z0-9_]+)\.sql$/.exec(entry);
    if (!match) { problems.push(`migration file name ${entry} is not NNN_name.sql`); continue; }
    const bytes = readFileSync(join(directory, entry));
    files.push({ version: Number(match[1]), name: entry, checksum: sha256(bytes), sql: bytes.toString('utf8') });
  }
  for (let i = 1; i < files.length; i += 1) {
    if (files[i].version === files[i - 1].version) problems.push(`two migrations are numbered ${files[i].version}`);
    else if (files[i].version !== files[i - 1].version + 1) problems.push(`migrations ${files[i - 1].version} and ${files[i].version} leave a gap`);
  }
  return { files, problems };
}

/** The migration schema.sql contains, from its `-- schema-version: NNN` line. */
export function schemaVersionOf(schemaSql: string): number | null {
  const match = /^-- schema-version: (\d{3})\s*$/m.exec(schemaSql);
  return match ? Number(match[1]) : null;
}

async function tableExists(db: Queryable, name: string): Promise<boolean> {
  return (await db.query(`SELECT to_regclass($1) IS NOT NULL AS present`, [`public.${name}`])).rows[0].present === true;
}

/** What a run would do, and why it would refuse. Changes nothing. */
export async function planMigrations(db: Queryable, files: MigrationFile[], fileProblems: string[] = []): Promise<MigrationPlan> {
  const problems = [...fileProblems];
  if (await tableExists(db, 'schema_migrations')) {
    const applied = (await db.query(`SELECT version, name, checksum, mode FROM schema_migrations ORDER BY version`)).rows as LedgerRow[];
    const byVersion = new Map(files.map((f) => [f.version, f]));
    applied.forEach((row, index) => {
      const file = byVersion.get(row.version);
      if (!file) problems.push(`migration ${row.version} (${row.name}) is recorded as applied but missing from this release`);
      else if (file.checksum !== row.checksum) problems.push(`migration ${row.version} (${row.name}) was changed after it was applied (checksum differs)`);
      if (index > 0 && row.version !== applied[index - 1].version + 1) problems.push(`the ledger skips from ${applied[index - 1].version} to ${row.version}`);
    });
    if (applied.length > 0 && files.length > 0 && applied[0].version !== files[0].version) {
      problems.push(`the ledger starts at ${applied[0].version}, the migrations at ${files[0].version}`);
    }
    const last = applied.length ? applied[applied.length - 1].version : 0;
    return { state: 'TRACKED', applied, pending: files.filter((f) => f.version > last), problems };
  }
  const state = (await tableExists(db, 'nexus_identities')) ? 'UNTRACKED' : 'EMPTY';
  return { state, applied: [], pending: files, problems };
}

export interface MigrateOptions {
  migrationsDir: string;
  schemaSql: string;
  /** For a database installed before the ledger: the last migration it has. */
  adoptAt?: number;
  log?: (line: string) => void;
}

export interface MigrateResult { installed: boolean; adopted: number[]; applied: number[] }

/**
 * Brings the database to the latest migration. Refuses (throws, changing
 * nothing) on any problem the plan reports, on an untracked database without
 * `adoptAt`, and on a schema.sql that does not match the migrations.
 */
export async function migrate(db: Queryable, options: MigrateOptions): Promise<MigrateResult> {
  const log = options.log ?? (() => undefined);
  const { files, problems: fileProblems } = readMigrations(options.migrationsDir);
  const latest = files.length ? files[files.length - 1].version : 0;
  await db.query(`SELECT pg_advisory_lock(hashtext($1))`, [LOCK_KEY]);
  try {
    const plan = await planMigrations(db, files, fileProblems);
    if (plan.problems.length) throw new Error(`migrations refused:\n  - ${plan.problems.join('\n  - ')}`);
    const result: MigrateResult = { installed: false, adopted: [], applied: [] };
    let pending = plan.pending;

    if (plan.state === 'EMPTY') {
      const contained = schemaVersionOf(options.schemaSql);
      if (contained === null) throw new Error('schema.sql does not state its version (-- schema-version: NNN)');
      if (contained > latest) throw new Error(`schema.sql states version ${contained}, but the last migration is ${latest}`);
      await inTransaction(db, async () => {
        await db.query(options.schemaSql);
        await db.query(LEDGER_SQL);
        for (const f of files.filter((m) => m.version <= contained)) await record(db, f, 'BASELINE');
      });
      result.installed = true;
      pending = files.filter((f) => f.version > contained);
      log(`installed schema.sql (version ${contained})`);
    } else if (plan.state === 'UNTRACKED') {
      if (options.adoptAt === undefined) {
        throw new Error('this database has NEXUS-SIGN tables but no migration ledger: state the last migration it has with --adopt-at <NNN> (see docs/operations/database-migrations.md)');
      }
      const adoptAt = options.adoptAt;
      if (!files.some((f) => f.version === adoptAt)) throw new Error(`--adopt-at ${adoptAt} is not a migration of this release`);
      await inTransaction(db, async () => {
        await db.query(LEDGER_SQL);
        for (const f of files.filter((m) => m.version <= adoptAt)) { await record(db, f, 'ADOPTED'); result.adopted.push(f.version); }
      });
      pending = files.filter((f) => f.version > adoptAt);
      log(`adopted migrations up to ${adoptAt}`);
    } else if (options.adoptAt !== undefined) {
      throw new Error('--adopt-at is only for a database without a migration ledger');
    }

    for (const f of pending) {
      await inTransaction(db, async () => {
        await db.query(f.sql);
        await record(db, f, 'APPLIED');
      });
      result.applied.push(f.version);
      log(`applied ${f.name}`);
    }
    return result;
  } finally {
    await db.query(`SELECT pg_advisory_unlock(hashtext($1))`, [LOCK_KEY]);
  }
}

async function record(db: Queryable, f: MigrationFile, mode: LedgerRow['mode']): Promise<void> {
  await db.query(`INSERT INTO schema_migrations (version, name, checksum, mode) VALUES ($1, $2, $3, $4)`, [f.version, f.name, f.checksum, mode]);
}

async function inTransaction(db: Queryable, work: () => Promise<void>): Promise<void> {
  await db.query('BEGIN');
  try {
    await work();
    await db.query('COMMIT');
  } catch (error) {
    await db.query('ROLLBACK').catch(() => undefined);
    throw error;
  }
}
