// Authorizations are created PENDING_USER / PENDING (migration 024, audit
// finding C-05), on PostgreSQL. The lifecycle trigger checks UPDATE only, so
// before 024 a direct INSERT could create a row already VERIFIED and
// COMMITTED with no signature, or with any bank_transaction_state text.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { ROOT, createDatabase, skipWithoutServices } from './support/harness.mjs';

const COLUMNS = `authorization_id, client_id, nexus_id, transaction_reference, operation_type, amount_minor, currency, beneficiary,
  policy_reference, policy_version, canonical_payload_hash, nonce, issued_at, expires_at`;
const insert = (client, extra = {}) => {
  const names = Object.keys(extra);
  const sql = `INSERT INTO authorization_requests (${COLUMNS}${names.map((n) => `, ${n}`).join('')})
    VALUES ($1, 'bank-c05', '100000005', $2, 'TRANSFER', 1, 'EUR', '{}', 'p', '1', repeat('0', 64), $2, now(), now() + interval '1 hour'
    ${names.map((_, i) => `, $${i + 3}`).join('')})`;
  return client.query(sql, [randomUUID(), randomUUID(), ...Object.values(extra)]);
};

describe('authorization insert state (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let client;
  before(async () => {
    db = await createDatabase();
    client = new pg.Client({ connectionString: db.url });
    await client.connect();
    await client.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ('bank-c05', 'x');
      INSERT INTO nexus_identities (nexus_id, client_id, bank_customer_ref) VALUES ('100000005', 'bank-c05', 'c-5')`);
  });
  after(async () => { await client?.end(); await db?.drop(); });

  test('a new authorization is PENDING_USER / PENDING', async () => {
    await insert(client);
  });

  test('a row created already verified, committed or confirmed is refused', async () => {
    const refused = /created PENDING_USER with bank transaction PENDING/;
    await assert.rejects(insert(client, { state: 'VERIFIED', bank_transaction_state: 'COMMITTED' }), refused);
    await assert.rejects(insert(client, { state: 'VERIFIED', signature: 'MEUCIQ', verified_at: new Date() }), refused);
    await assert.rejects(insert(client, { bank_transaction_state: 'COMMIT_REQUESTED' }), refused);
    await assert.rejects(insert(client, { state: 'OFFLINE_PROVISIONAL', offline_code_tag: 'x' }), refused);
    await assert.rejects(insert(client, { confirmation_method: 'DEVICE_SIGNATURE' }), refused);
    await assert.rejects(insert(client, { consumed_at: new Date() }), refused);
  });

  test('an unknown bank transaction state is refused on every write', async () => {
    await assert.rejects(insert(client, { bank_transaction_state: 'ANY_STRING_AT_ALL' }), /bank_state_check|created PENDING_USER/);
    await client.query('ALTER TABLE authorization_requests DISABLE TRIGGER authorization_lifecycle');
    try {
      await assert.rejects(client.query(`UPDATE authorization_requests SET bank_transaction_state = 'ANY' WHERE client_id = 'bank-c05'`), /bank_state_check/);
    } finally {
      await client.query('ALTER TABLE authorization_requests ENABLE TRIGGER authorization_lifecycle');
    }
  });

  test('the migration stops, naming the rows, when existing data has an unknown bank transaction state', async () => {
    const migration = readFileSync(join(ROOT, 'migrations/024_authorization_insert_state.sql'), 'utf8');
    await client.query(`ALTER TABLE authorization_requests DROP CONSTRAINT authorization_requests_bank_state_check;
      ALTER TABLE authorization_requests DISABLE TRIGGER authorization_insert_state`);
    const id = randomUUID();
    await client.query(`INSERT INTO authorization_requests (${COLUMNS}, bank_transaction_state)
      VALUES ($1, 'bank-c05', '100000005', $1, 'TRANSFER', 1, 'EUR', '{}', 'p', '1', repeat('0', 64), $1, now(), now() + interval '1 hour', 'LEGACY')`, [id]);
    await assert.rejects(client.query(migration), new RegExp(`unknown bank_transaction_state: ${id} \\(LEGACY\\)`));
    await client.query(`ALTER TABLE authorization_requests DISABLE TRIGGER authorization_lifecycle;
      UPDATE authorization_requests SET bank_transaction_state = 'CANCELLED' WHERE authorization_id = '${id}';
      ALTER TABLE authorization_requests ENABLE TRIGGER authorization_lifecycle`);
    await client.query(migration); // resolved data: the migration completes and is re-runnable
    await client.query(migration);
    await assert.rejects(insert(client, { state: 'VERIFIED' }), /created PENDING_USER/);
  });
});
