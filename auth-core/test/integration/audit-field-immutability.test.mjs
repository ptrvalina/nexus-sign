// Audit fields are written by the server, once (migration 032, audit finding
// C-07): consumed_at on verification, the bank commit result with the final
// bank transaction state, and an audit row's timestamp by the database.
// Before, the application role could clear or backdate them.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { ROOT, createDatabase, skipWithoutServices } from './support/harness.mjs';

describe('audit fields are set once by the server (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let owner; let app;
  before(async () => {
    db = await createDatabase();
    owner = new pg.Client({ connectionString: db.url });
    await owner.connect();
    await owner.query(readFileSync(join(ROOT, 'scripts/db/roles.sql'), 'utf8'));
    await owner.query(`ALTER ROLE nexus_app WITH LOGIN PASSWORD 'nexus-app-test'`);
    await owner.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ('bank-c07', 'x');
      INSERT INTO nexus_identities (nexus_id, client_id, bank_customer_ref) VALUES ('100000007', 'bank-c07', 'c-7')`);
    const url = new URL(db.url); url.username = 'nexus_app'; url.password = 'nexus-app-test';
    app = new pg.Client({ connectionString: url.toString() });
    await app.connect();
  });
  after(async () => { await app?.end(); await owner?.end(); await db?.drop(); });

  /** A VERIFIED authorization, as authorizationConfirmation.ts writes it. */
  const verified = async () => {
    const id = randomUUID();
    await app.query(`INSERT INTO authorization_requests (authorization_id, client_id, nexus_id, transaction_reference, operation_type, amount_minor, currency,
        beneficiary, policy_reference, policy_version, canonical_payload_hash, nonce, issued_at, expires_at)
      VALUES ($1::uuid, 'bank-c07', '100000007', $1::text, 'TRANSFER', 1, 'EUR', '{}', 'p', '1', repeat('0', 64), $1::text, now(), now() + interval '1 hour')`, [id]);
    await app.query(`UPDATE authorization_requests SET state = 'VERIFIED', signature = 'MEUCIQ', signature_format = 'der', confirmation_method = 'DEVICE_SIGNATURE',
        verified_at = now(), consumed_at = now() WHERE authorization_id = $1`, [id]);
    return id;
  };
  const refused = (client, sql, id, pattern) => assert.rejects(client.query(sql, [id]), pattern);

  test('consumed_at is set once, on verification', async () => {
    const id = await verified();
    for (const client of [app, owner]) {
      await refused(client, `UPDATE authorization_requests SET consumed_at = NULL WHERE authorization_id = $1`, id, /consumed_at is set once/);
      await refused(client, `UPDATE authorization_requests SET consumed_at = '2001-01-01' WHERE authorization_id = $1`, id, /consumed_at is set once/);
    }
  });

  test('the bank commit result is set with the final bank state and not rewritten', async () => {
    const id = await verified();
    await refused(app, `UPDATE authorization_requests SET bank_commit_error = 'early' WHERE authorization_id = $1`, id, /bank commit result is set once/);
    await app.query(`UPDATE authorization_requests SET bank_transaction_state = 'COMMIT_REQUESTED', bank_transaction_reference = 'tx-1' WHERE authorization_id = $1`, [id]);
    // bankTransactionService.ts: the final state with its time and error.
    await app.query(`UPDATE authorization_requests SET bank_transaction_state = 'COMMITTED', bank_commit_at = now(), bank_commit_error = NULL WHERE authorization_id = $1`, [id]);
    await refused(app, `UPDATE authorization_requests SET bank_commit_at = '2001-01-01', bank_commit_error = 'rewritten' WHERE authorization_id = $1`, id, /bank commit result is set once/);
    const row = (await app.query(`SELECT bank_transaction_state, bank_commit_error, bank_commit_at > now() - interval '1 minute' AS recent FROM authorization_requests WHERE authorization_id = $1`, [id])).rows[0];
    assert.deepEqual(row, { bank_transaction_state: 'COMMITTED', bank_commit_error: null, recent: true });
  });

  test('an audit row carries the database time, whatever the application role supplies', async () => {
    const eventId = randomUUID();
    await app.query(`INSERT INTO audit_logs (event_id, event_type, actor, "timestamp", details) VALUES ($1, 'admin_login', 'admin:alice', now() - interval '400 days', '{}')`, [eventId]);
    const { rows } = await owner.query(`SELECT "timestamp" > now() - interval '1 minute' AS recent FROM audit_logs WHERE event_id = $1`, [eventId]);
    assert.deepEqual(rows, [{ recent: true }]);
  });

  test('the guards are installed by the migration as well as by schema.sql', () => {
    const migration = readFileSync(join(ROOT, 'migrations/032_audit_field_immutability.sql'), 'utf8');
    const schema = readFileSync(join(ROOT, 'src/db/schema.sql'), 'utf8');
    for (const text of [migration, schema]) {
      assert.match(text, /CREATE TRIGGER authorization_audit_fields BEFORE UPDATE ON authorization_requests/);
      assert.match(text, /CREATE TRIGGER audit_logs_server_time BEFORE INSERT ON audit_logs/);
    }
  });
});
