import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';
import { migrate, planMigrations, readMigrations } from '../db/migrator';

/**
 * Applies the database migrations under the ledger (src/db/migrator.ts).
 *
 * Usage (as a DBA account that can SET ROLE nexus_owner, or the owner):
 *   MIGRATION_DATABASE_URL=postgres://... node dist/cli/migrate.js            apply
 *   MIGRATION_DATABASE_URL=postgres://... node dist/cli/migrate.js --check    report only; exit 1 if anything is pending or wrong
 *   MIGRATION_DATABASE_URL=postgres://... node dist/cli/migrate.js --adopt-at 024
 *       first run on a database installed before the ledger: it has every
 *       migration up to 024 (check with the upgrade notes before stating it)
 *   --role nexus_owner    SET ROLE before running (default: none)
 *
 * Then run scripts/db/roles.sql again (docs/operations/database-migrations.md).
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const value = (flag: string): string | undefined => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
  const url = process.env.MIGRATION_DATABASE_URL ?? process.env.DATABASE_URL;
  if (!url) throw new Error('set MIGRATION_DATABASE_URL (or DATABASE_URL)');
  const root = join(__dirname, '..', '..');
  const migrationsDir = join(root, 'migrations');
  const schemaSql = readFileSync(join(root, 'src', 'db', 'schema.sql'), 'utf8');
  const adoptRaw = value('--adopt-at');
  const adoptAt = adoptRaw === undefined ? undefined : Number(adoptRaw);
  if (adoptRaw !== undefined && !Number.isInteger(adoptAt)) throw new Error('--adopt-at takes a migration number');

  const db = new Client({ connectionString: url });
  await db.connect();
  try {
    const role = value('--role');
    if (role) {
      if (!/^[a-z_][a-z0-9_]*$/.test(role)) throw new Error('invalid role name');
      await db.query(`SET ROLE ${role}`);
    }
    if (args.includes('--check')) {
      const { files, problems } = readMigrations(migrationsDir);
      const plan = await planMigrations(db, files, problems);
      console.log(JSON.stringify({ state: plan.state, applied: plan.applied.length, pending: plan.pending.map((f) => f.name), problems: plan.problems }, null, 2));
      if (plan.problems.length || plan.pending.length || plan.state !== 'TRACKED') process.exitCode = 1;
      return;
    }
    const result = await migrate(db, { migrationsDir, schemaSql, adoptAt, log: (line) => console.log(line) });
    console.log(JSON.stringify(result));
  } finally {
    await db.end();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
