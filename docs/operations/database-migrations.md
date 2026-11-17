# Database migrations

How Auth Core's PostgreSQL schema is installed and upgraded. Tool: `npm run migrate` (`auth-core/src/cli/migrate.ts`, logic in `src/db/migrator.ts`). Tests: `auth-core/test/integration/migrations.test.mjs`.

## Ledger

`schema_migrations` records each migration file a database has, with the SHA-256 of the file and how it got there:

| `mode` | Meaning |
|---|---|
| `BASELINE` | Contained in `schema.sql` when the database was installed from empty |
| `ADOPTED` | Declared present by the operator when a database installed before the ledger was first put under it |
| `APPLIED` | Run by the tool, in one transaction with its ledger row |

The table is append-only (trigger), and `scripts/db/roles.sql` removes `INSERT` and `UPDATE` on it from the service role `nexus_app`.

## Rules the tool enforces

Before it changes anything, every run checks:

- files are named `NNN_name.sql` and numbered without gaps or duplicates;
- every migration in the ledger is still present and unchanged (checksum);
- the ledger has no gaps and starts at the first migration;
- `schema.sql` states the migration it contains (`-- schema-version: NNN`) and is not ahead of the files. `scripts/check-repository.sh` fails when the line differs from the last migration.

Any problem stops the run with the list of problems and no change. One run at a time: the tool holds a PostgreSQL advisory lock. A migration that fails rolls back with its ledger row, so a database is never left half-migrated.

## New installation

```bash
cd auth-core
MIGRATION_DATABASE_URL=postgres://dba@db/nexus npm run migrate -- --role nexus_owner
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -f scripts/db/roles.sql
```

On an empty database the tool applies `schema.sql`, records the migrations it contains as `BASELINE`, then applies any later migration files.

## Upgrade

```bash
MIGRATION_DATABASE_URL=... npm run migrate -- --check     # what would run; exit 1 when anything is pending or wrong
MIGRATION_DATABASE_URL=... npm run migrate -- --role nexus_owner
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -f scripts/db/roles.sql
```

### First run on a database installed before the ledger

The tool refuses a database that has Auth Core tables and no ledger until the operator states the last migration it has:

```bash
MIGRATION_DATABASE_URL=... npm run migrate -- --adopt-at 022 --role nexus_owner
```

A database installed from the 2.0.0-rc.2 `schema.sql`, or upgraded to 2.0.0-rc.2 with migrations, has every migration up to `022`. The tool records 002 to 022 as `ADOPTED` and applies 023 onwards. Stating a wrong number is not detectable by the tool. Check it against the deployment record before the run. The test suite upgrades the real 2.0.0-rc.2 schema this way and checks the result against a fresh installation (tables, columns, constraints, indexes, triggers and functions).

## Rollback

Migrations are forward-only. Several remove data or constraints that cannot be restored by a script (see [migrations/README.md](../../auth-core/migrations/README.md)). The rollback path is:

1. Take a backup immediately before the run.
2. Restore that backup.
3. Deploy the previous release.

Rehearse every upgrade on a restored copy of production first.
