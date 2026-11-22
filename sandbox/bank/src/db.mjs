// The sandbox bank's own database: one SQLite file inside SANDBOX_DATA_DIR.
// It holds only demo data and is never shared with Auth Core or any other
// system. Money is in integer minor units; the ledger is double-entry and the
// balances are kept in the same database transaction as the entries.
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const MIGRATIONS = [
  // 1: initial schema
  `
  CREATE TABLE customers (
    id TEXT PRIMARY KEY,
    login TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    device_kind TEXT NOT NULL CHECK (device_kind IN ('PHONE', 'SOFTWARE_TEST_DEVICE')),
    password_hash TEXT NOT NULL,
    nexus_id TEXT UNIQUE,
    credential_id TEXT,
    settings TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
  ) STRICT;

  CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    customer_id TEXT REFERENCES customers(id),
    name TEXT NOT NULL,
    iban TEXT NOT NULL UNIQUE,
    currency TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('CUSTOMER', 'BANK')),
    balance_minor INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (kind = 'BANK' OR balance_minor >= 0)
  ) STRICT;

  CREATE TABLE cards (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    last4 TEXT NOT NULL,
    brand TEXT NOT NULL,
    expires TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'FROZEN', 'BLOCKED'))
  ) STRICT;

  CREATE TABLE favorites (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id),
    name TEXT NOT NULL,
    iban TEXT NOT NULL,
    created_at TEXT NOT NULL
  ) STRICT;

  CREATE TABLE transactions (
    id TEXT PRIMARY KEY,
    reference TEXT NOT NULL UNIQUE,
    customer_id TEXT NOT NULL REFERENCES customers(id),
    kind TEXT NOT NULL CHECK (kind IN ('INTERNAL_TRANSFER', 'EXTERNAL_PAYMENT')),
    source_account_id TEXT NOT NULL REFERENCES accounts(id),
    destination_account_id TEXT REFERENCES accounts(id),
    beneficiary_name TEXT NOT NULL,
    beneficiary_iban TEXT NOT NULL,
    amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
    fee_minor INTEGER NOT NULL CHECK (fee_minor >= 0),
    currency TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('CREATED', 'AUTHORIZATION_PENDING', 'OFFLINE_PROVISIONAL', 'AUTHORIZING',
      'EXECUTED', 'REJECTED', 'EXPIRED', 'CANCELLED', 'FAILED')),
    authorization_id TEXT UNIQUE,
    canonical_payload_hash TEXT,
    authorization_expires_at TEXT,
    signed_terms TEXT,
    failure_reason TEXT,
    commit_reported TEXT,
    scenario_run_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  ) STRICT;

  CREATE TABLE idempotency_keys (
    customer_id TEXT NOT NULL,
    key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    transaction_id TEXT NOT NULL REFERENCES transactions(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (customer_id, key)
  ) STRICT;

  CREATE TABLE journals (
    id TEXT PRIMARY KEY,
    transaction_id TEXT UNIQUE REFERENCES transactions(id),
    kind TEXT NOT NULL CHECK (kind IN ('OPENING', 'TRANSFER')),
    created_at TEXT NOT NULL
  ) STRICT;

  CREATE TABLE ledger_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    journal_id TEXT NOT NULL REFERENCES journals(id),
    account_id TEXT NOT NULL REFERENCES accounts(id),
    amount_minor INTEGER NOT NULL CHECK (amount_minor <> 0),
    currency TEXT NOT NULL,
    memo TEXT NOT NULL
  ) STRICT;

  CREATE TABLE receipts (
    id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL UNIQUE REFERENCES transactions(id),
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
  ) STRICT;

  CREATE TABLE evidence (
    transaction_id TEXT PRIMARY KEY REFERENCES transactions(id),
    authorization_id TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    chain_sequence INTEGER,
    seal_key_id TEXT,
    record TEXT NOT NULL,
    problems TEXT NOT NULL,
    received_at TEXT NOT NULL
  ) STRICT;

  CREATE TABLE evidence_keys (
    key_id TEXT PRIMARY KEY,
    public_key_pem TEXT NOT NULL,
    pinned_at TEXT NOT NULL
  ) STRICT;

  CREATE TABLE notifications (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id),
    transaction_id TEXT REFERENCES transactions(id),
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('QUEUED', 'DELIVERED', 'READ', 'SUPPRESSED')),
    created_at TEXT NOT NULL,
    delivered_at TEXT
  ) STRICT;

  CREATE TABLE app_sessions (
    token_hash TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id),
    expires_at TEXT NOT NULL
  ) STRICT;

  CREATE TABLE scenario_runs (
    id TEXT PRIMARY KEY,
    scenario TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('RUNNING', 'PASSED', 'FAILED', 'NOT_AVAILABLE')),
    expected TEXT NOT NULL,
    actual TEXT,
    transaction_id TEXT,
    steps TEXT NOT NULL DEFAULT '[]',
    started_at TEXT NOT NULL,
    finished_at TEXT
  ) STRICT;

  -- Audit log and transaction timeline. Append-only: rows cannot be changed or removed.
  CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    type TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('BANK', 'AUTH_CORE', 'DEVICE', 'CONSOLE', 'SCENARIO', 'SYSTEM')),
    customer_id TEXT,
    transaction_id TEXT,
    detail TEXT NOT NULL DEFAULT '{}'
  ) STRICT;
  CREATE INDEX events_by_transaction ON events(transaction_id, id);
  CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
  CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
  `,
];

export function openDatabase(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  db.exec('CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL) STRICT;');
  const row = db.prepare('SELECT version FROM schema_version').get();
  let version = row?.version ?? 0;
  if (!row) db.prepare('INSERT INTO schema_version (version) VALUES (0)').run();
  for (; version < MIGRATIONS.length; version++) {
    transaction(db, () => {
      db.exec(MIGRATIONS[version]);
      db.prepare('UPDATE schema_version SET version = ?').run(version + 1);
    });
  }
  return db;
}

/** Runs fn inside BEGIN IMMEDIATE … COMMIT; rolls back on any error. */
export function transaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export const now = () => new Date().toISOString();
