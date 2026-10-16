// Regression tests for findings of the 2026-10-16 forensic inventory that need
// no database. Each test names its finding (FI-xxx).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './support/load-ts.mjs';

test('FI-013: an authorization past its expiry is reported EXPIRED even before the sweep', () => {
  const { reportedState } = loadTs('services/authorizationExpiry.ts', {
    stubs: { '../db/pool': { withTransaction: () => { throw new Error('not used'); } }, './webhookService': {}, './auditService': {} },
  });
  const now = Date.parse('2026-10-16T12:00:00Z');
  const at = (iso) => new Date(iso);
  assert.equal(reportedState({ state: 'PENDING_USER', expiresAt: at('2026-10-16T12:00:01Z') }, now), 'PENDING_USER');
  assert.equal(reportedState({ state: 'PENDING_USER', expiresAt: at('2026-10-16T12:00:00Z') }, now), 'EXPIRED', 'expiry is inclusive, as in the confirmation path');
  assert.equal(reportedState({ state: 'PENDING_USER', expiresAt: at('2026-10-16T11:00:00Z') }, now), 'EXPIRED');
  for (const final of ['VERIFIED', 'REJECTED', 'CANCELLED', 'EXPIRED']) {
    assert.equal(reportedState({ state: final, expiresAt: at('2026-10-16T11:00:00Z') }, now), final, `${final} is never rewritten`);
  }
});

/** A pool double: answers the queries createNexusIdentity makes, and fails the
 * first INSERTs with the given PostgreSQL errors. */
function identityStore(insertErrors) {
  const inserted = [];
  const client = {
    async query(sql, args) {
      if (/^SELECT nexus_id FROM nexus_identities WHERE client_id/.test(sql.trim())) return { rows: [] };
      if (/^SELECT 1 FROM nexus_identities/.test(sql.trim())) return { rowCount: 0, rows: [] };
      if (/^INSERT INTO nexus_identities/.test(sql.trim())) {
        const error = insertErrors.shift();
        if (error) throw Object.assign(new Error('duplicate key value violates unique constraint'), error);
        inserted.push(args[0]);
        const now = new Date();
        return { rows: [{ nexus_id: args[0], client_id: args[1], bank_customer_ref: args[2], status: 'ACTIVE', created_at: now, updated_at: now, last_used_at: null }] };
      }
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  const service = loadTs('services/nexusIdentityService.ts', {
    stubs: {
      '../db/pool': { withTransaction: (fn) => fn(client), pool: client },
      './auditService': { recordAuditEvent: async () => {} },
      './pushRegistrationService': { forgetInactivePushRegistrations: async () => {} },
    },
  });
  return { service, inserted };
}

test('FI-015: a NEXUS ID collision between concurrent requests retries with a new ID', async () => {
  const { service, inserted } = identityStore([{ code: '23505', constraint: 'nexus_identities_pkey' }]);
  const identity = await service.createNexusIdentity('bank-a', 'customer-1');
  assert.match(identity.nexusId, /^\d{9}$/);
  assert.deepEqual(inserted, [identity.nexusId]);
});

test('FI-015: a duplicate bank customer reference is still reported as a duplicate customer', async () => {
  const { service } = identityStore([{ code: '23505', constraint: 'uq_nexus_identity_customer' }]);
  await assert.rejects(service.createNexusIdentity('bank-a', 'customer-1'), { name: 'DuplicateBankCustomerError' });
});

test('FI-015: repeated ID collisions end with an allocation error, not a duplicate-customer error', async () => {
  const pkey = { code: '23505', constraint: 'nexus_identities_pkey' };
  const { service } = identityStore([pkey, pkey, pkey]);
  await assert.rejects(service.createNexusIdentity('bank-a', 'customer-1'), /Unable to allocate a unique 9-digit NEXUS ID/);
});
