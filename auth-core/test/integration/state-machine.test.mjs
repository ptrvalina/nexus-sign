// Lifecycle state machines enforced by PostgreSQL (migrations 017, 018): every
// transition is checked against the specification below, including random
// sequences of writes (property test), so a defect or a direct write by the
// application role cannot move an authorization, credential or identity into
// a state the protocol does not allow.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomInt, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, createDatabase, skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, enrolWithToken, submitSignature } from './support/actors.mjs';

// The specification (docs/architecture/state-machines.md).
const AUTHORIZATION = {
  PENDING_USER: ['VERIFIED', 'EXPIRED', 'CANCELLED', 'REJECTED', 'OFFLINE_PROVISIONAL'],
  // Offline confirmation v2 (migration 022).
  OFFLINE_PROVISIONAL: ['VERIFIED', 'OFFLINE_UNSIGNED'],
  VERIFIED: [], EXPIRED: [], CANCELLED: [], REJECTED: [], OFFLINE_UNSIGNED: [],
};
// States a bare state write can never reach: each needs its own fields
// (signature; accepted code and deadline; unsigned reason).
const NEEDS_FIELDS = ['VERIFIED', 'OFFLINE_PROVISIONAL', 'OFFLINE_UNSIGNED'];
const CREDENTIAL = { ACTIVE: ['REVOKED'], REVOKED: [] };
// Removed by migration 018: never used by Auth Core.
const REMOVED_AUTHORIZATION_STATES = ['CREATED', 'DELIVERING', 'SIGNED', 'CONSUMED'];
const REMOVED_CREDENTIAL_STATES = ['PENDING', 'SUSPENDED'];
const IDENTITY = { ACTIVE: ['SUSPENDED', 'REVOKED'], SUSPENDED: ['ACTIVE', 'REVOKED'], REVOKED: [] };
const BANK = { PENDING: ['COMMIT_REQUESTED'], COMMIT_REQUESTED: ['COMMITTED', 'FAILED', 'CANCELLED'], COMMITTED: [], FAILED: [], CANCELLED: [] };

const refused = /not a permitted transition|immutable|set once|needs a signature|set with the commit request|needs the accepted code|needs a reason/;

describe('database state machines', { skip: skipWithoutServices }, () => {
  let server; let bank; let device;
  before(async () => {
    server = await startAuthCore();
    bank = await bankSession(server, await server.registerBank('bank-states'));
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
  });
  after(async () => { await server?.stop(); });

  const q = (sql, args) => server.db.query(sql, args);
  const verified = async () => {
    const auth = await bank.createAuthorization(device);
    const { signature } = await deviceSignature(server, device, auth.authorizationId);
    assert.equal((await submitSignature(server, device, auth.authorizationId, signature)).json.status, 'VERIFIED');
    return auth.authorizationId;
  };

  test('a verified authorization cannot be reopened, re-signed or altered', async () => {
    const id = await verified();
    for (const [sql, args] of [
      ['UPDATE authorization_requests SET state = $2 WHERE authorization_id = $1', [id, 'PENDING_USER']],
      ['UPDATE authorization_requests SET state = $2 WHERE authorization_id = $1', [id, 'EXPIRED']],
      ['UPDATE authorization_requests SET signature = $2 WHERE authorization_id = $1', [id, 'AAAA']],
      ['UPDATE authorization_requests SET amount_minor = 1 WHERE authorization_id = $1', [id]],
      ["UPDATE authorization_requests SET beneficiary = '{\"iban\":\"X\"}' WHERE authorization_id = $1", [id]],
      ['UPDATE authorization_requests SET expires_at = now() + interval \'1 day\' WHERE authorization_id = $1', [id]],
      ["UPDATE authorization_requests SET bank_transaction_state = 'COMMITTED' WHERE authorization_id = $1", [id]],
      ["UPDATE authorization_requests SET bank_transaction_reference = 'other' WHERE authorization_id = $1", [id]],
    ]) await assert.rejects(q(sql, args), refused, sql);
  });

  test('a pending authorization cannot be verified without a signature or have its transaction changed', async () => {
    const { authorizationId: id } = await bank.createAuthorization(device);
    await assert.rejects(q("UPDATE authorization_requests SET state = 'VERIFIED' WHERE authorization_id = $1", [id]), refused);
    await assert.rejects(q("UPDATE authorization_requests SET canonical_payload_hash = repeat('0', 64) WHERE authorization_id = $1", [id]), refused);
    await assert.rejects(q("UPDATE authorization_requests SET bank_transaction_state = 'COMMIT_REQUESTED' WHERE authorization_id = $1", [id]), refused);
    await q("UPDATE authorization_requests SET state = 'CANCELLED' WHERE authorization_id = $1", [id]);
    await assert.rejects(q("UPDATE authorization_requests SET state = 'PENDING_USER' WHERE authorization_id = $1", [id]), refused);
  });

  test('random authorization and bank-transaction writes follow the specification (property test)', async () => {
    const states = Object.keys(AUTHORIZATION);
    const bankStates = Object.keys(BANK);
    for (let run = 0; run < 12; run += 1) {
      const id = run % 3 === 0 ? await verified() : (await bank.createAuthorization(device)).authorizationId;
      let { state, bank_transaction_state: bankState } = (await q('SELECT state, bank_transaction_state FROM authorization_requests WHERE authorization_id = $1', [id])).rows[0];
      for (let step = 0; step < 8; step += 1) {
        if (randomInt(2) === 0) {
          const next = states[randomInt(states.length)];
          if (next === state) continue;
          // A bare state write never verifies, and never reaches the offline
          // v2 states: each needs its own fields.
          const allowed = AUTHORIZATION[state].includes(next) && !NEEDS_FIELDS.includes(next);
          const attempt = q('UPDATE authorization_requests SET state = $2 WHERE authorization_id = $1', [id, next]);
          if (allowed) { await attempt; state = next; } else await assert.rejects(attempt, refused, `${state} -> ${next}`);
        } else {
          const next = bankStates[randomInt(bankStates.length)];
          if (next === bankState) continue;
          const allowed = BANK[bankState].includes(next) && (next !== 'COMMIT_REQUESTED' || state === 'VERIFIED');
          const attempt = q(`UPDATE authorization_requests SET bank_transaction_state = $2${next === 'COMMIT_REQUESTED' ? ", bank_transaction_reference = 'B-1'" : ''} WHERE authorization_id = $1`, [id, next]);
          if (allowed) { await attempt; bankState = next; } else await assert.rejects(attempt, refused, `bank ${bankState} -> ${next}`);
        }
      }
    }
  });

  test('credentials: revoked is final, keys are immutable, one ACTIVE per identity', async () => {
    const other = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    await assert.rejects(q("UPDATE credentials SET public_key_pem = 'x' WHERE credential_id = $1", [other.credentialId]), refused);
    await assert.rejects(q("UPDATE credentials SET nexus_id = $2 WHERE credential_id = $1", [other.credentialId, device.nexusId]), refused);
    const copy = (state) => q(`INSERT INTO credentials (credential_id, nexus_id, key_algorithm, public_key_pem, platform, security_level, state)
      SELECT $1, nexus_id, key_algorithm, public_key_pem, platform, security_level, $3 FROM credentials WHERE credential_id = $2`, [randomUUID(), other.credentialId, state]);
    await assert.rejects(copy('ACTIVE'), /idx_credentials_one_active/);
    await q("UPDATE credentials SET state = 'REVOKED' WHERE credential_id = $1", [other.credentialId]);
    await assert.rejects(q("UPDATE credentials SET state = 'ACTIVE' WHERE credential_id = $1", [other.credentialId]), refused, 'REVOKED -> ACTIVE');
    for (const state of REMOVED_CREDENTIAL_STATES) {
      await assert.rejects(copy(state), /credentials_state_check/, `INSERT ${state}`);
    }
  });

  test('states removed by migration 018 cannot be written', async () => {
    const { authorizationId: id } = await bank.createAuthorization(device);
    for (const state of REMOVED_AUTHORIZATION_STATES) {
      await assert.rejects(q('UPDATE authorization_requests SET state = $2 WHERE authorization_id = $1', [id, state]),
        /authorization_requests_state_check|not a permitted transition/, state);
    }
    for (const state of REMOVED_CREDENTIAL_STATES) {
      await assert.rejects(q('UPDATE credentials SET state = $2 WHERE credential_id = $1', [device.credentialId, state]),
        /credentials_state_check|not a permitted transition/, state);
    }
    // The CHECK constraints themselves, not only the triggers that fire first.
    const checks = Object.fromEntries((await q(`SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
      WHERE conname IN ('authorization_requests_state_check', 'credentials_state_check')`)).rows.map((r) => [r.conname, r.def]));
    for (const state of [...REMOVED_AUTHORIZATION_STATES, ...REMOVED_CREDENTIAL_STATES]) {
      assert.ok(!checks.authorization_requests_state_check.includes(`'${state}'`) && !checks.credentials_state_check.includes(`'${state}'`), `${state} not in a CHECK`);
    }
    for (const table of ['attestation_records', 'policy_decisions']) {
      assert.equal((await q('SELECT to_regclass($1) AS t', [table])).rows[0].t, null, `${table} is dropped`);
    }
    const columns = (await q(`SELECT table_name, column_name FROM information_schema.columns
      WHERE (table_name, column_name) IN (('nexus_identities', 'recovery_verifier'), ('credentials', 'suspended_at'))`)).rows;
    assert.deepEqual(columns, [], 'protocol 1 verifiers and credential suspension are gone');
  });

  test('migration 018 stops, naming the rows, when existing data uses a removed state or a dropped table holds rows', async () => {
    const db = await createDatabase();
    try {
      const migration = readFileSync(join(ROOT, 'migrations/018_remove_unused_schema.sql'), 'utf8');
      // Recreate a database before 018 that holds a SUSPENDED credential (possible after the 1.x import in 002).
      await db.pool.query(`ALTER TABLE credentials DROP CONSTRAINT credentials_state_check;
        INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ('legacy-bank', 'x');
        INSERT INTO nexus_identities (nexus_id, client_id, bank_customer_ref) VALUES ('100000001', 'legacy-bank', 'c-1');`);
      const id = randomUUID();
      await db.pool.query(`INSERT INTO credentials (credential_id, nexus_id, key_algorithm, public_key_pem, platform, security_level, state)
        VALUES ($1, '100000001', 'ES256', 'pem', 'OTHER', 'SOFTWARE', 'SUSPENDED')`, [id]);
      await assert.rejects(db.pool.query(migration), new RegExp(`credentials in a state that no longer exists: ${id} \\(SUSPENDED\\)`));
      await db.pool.query(`ALTER TABLE credentials DISABLE TRIGGER credential_lifecycle;
        UPDATE credentials SET state = 'REVOKED' WHERE credential_id = '${id}';
        ALTER TABLE credentials ENABLE TRIGGER credential_lifecycle;`);
      // An authorization in a removed state, then a row in a dropped table.
      // Before 018 there was no insert-state trigger (migration 024) either.
      await db.pool.query(`ALTER TABLE authorization_requests DROP CONSTRAINT authorization_requests_state_check;
        ALTER TABLE authorization_requests DISABLE TRIGGER authorization_insert_state`);
      const auth = randomUUID();
      await db.pool.query(`INSERT INTO authorization_requests (authorization_id, client_id, nexus_id, credential_id, transaction_reference, operation_type,
          amount_minor, currency, beneficiary, policy_reference, policy_version, canonical_payload_hash, nonce, issued_at, expires_at, state)
        VALUES ($1, 'legacy-bank', '100000001', $2, 't-1', 'TRANSFER', 1, 'EUR', '{}', 'p', '1', repeat('0', 64), 'n-1', now(), now() + interval '1 hour', 'SIGNED')`, [auth, id]);
      await assert.rejects(db.pool.query(migration), new RegExp(`authorizations in a state that no longer exists: ${auth} \\(SIGNED\\)`));
      await db.pool.query(`ALTER TABLE authorization_requests DISABLE TRIGGER authorization_lifecycle;
        UPDATE authorization_requests SET state = 'EXPIRED' WHERE authorization_id = '${auth}';
        ALTER TABLE authorization_requests ENABLE TRIGGER authorization_lifecycle;
        CREATE TABLE policy_decisions (decision_id uuid PRIMARY KEY); INSERT INTO policy_decisions VALUES (gen_random_uuid());`);
      await assert.rejects(db.pool.query(migration), /policy_decisions is not empty/);
      await db.pool.query('DELETE FROM policy_decisions');
      await db.pool.query(migration); // resolved data: the migration completes
      assert.equal((await db.pool.query(`SELECT to_regclass('policy_decisions') AS t`)).rows[0].t, null);
    } finally {
      await db.drop();
    }
  });

  test('device keys change only through device enrolment; exactly one ACTIVE credential remains (red-team RT-03)', async () => {
    const rotating = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    const key = (await import('./support/actors.mjs')).newKey().publicKeyPem;
    // The bank-side provisioning and rotation endpoints were removed in 2.0.0-rc.2.
    for (const path of [`/v1/nexus-identities/${rotating.nexusId}/credentials`, `/v1/credentials/${rotating.credentialId}/rotate`]) {
      const r = await bank.call('POST', path, { body: { publicKeyPem: key, platform: 'OTHER', securityLevel: 'SOFTWARE_TEST' } });
      assert.equal(r.status, 404, `${path}: ${r.text}`);
    }
    await bank.replaceDevice(rotating, { method: 'BRANCH_VISIT', reference: 'rt-03' });
    const states = (await q('SELECT state FROM credentials WHERE nexus_id = $1 ORDER BY created_at', [rotating.nexusId])).rows.map((x) => x.state);
    assert.deepEqual(states, ['REVOKED', 'ACTIVE']);
  });

  test('security history rows are not deleted, even by the table owner\'s session (red-team RT-08)', async () => {
    // Row triggers fire only for existing rows; the app role has no DELETE at all (db-roles.test.mjs).
    for (const table of ['credentials', 'nexus_identities', 'authorization_requests']) {
      await assert.rejects(q(`DELETE FROM ${table} WHERE true`), /rows are not deleted/, table);
    }
  });

  test('identities: revoked is final and the bank binding is immutable', async () => {
    const { nexusId } = await bank.createIdentity();
    await assert.rejects(q("UPDATE nexus_identities SET bank_customer_ref = 'someone-else' WHERE nexus_id = $1", [nexusId]), refused);
    for (const [from, to] of [['ACTIVE', 'SUSPENDED'], ['SUSPENDED', 'ACTIVE'], ['ACTIVE', 'REVOKED']]) {
      assert.ok(IDENTITY[from].includes(to));
      await q('UPDATE nexus_identities SET status = $2 WHERE nexus_id = $1', [nexusId, to]);
    }
    for (const to of ['ACTIVE', 'SUSPENDED']) {
      await assert.rejects(q('UPDATE nexus_identities SET status = $2 WHERE nexus_id = $1', [nexusId, to]), refused);
    }
  });
});
