// Regression tests for findings of the 2026-10-16 internal review that need
// no database. Each test names its finding (FI-xxx).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './support/load-ts.mjs';

test('An authorization past its expiry is reported EXPIRED even before the sweep', () => {
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

test('A NEXUS ID collision between concurrent requests retries with a new ID', async () => {
  const { service, inserted } = identityStore([{ code: '23505', constraint: 'nexus_identities_pkey' }]);
  const identity = await service.createNexusIdentity('bank-a', 'customer-1');
  assert.match(identity.nexusId, /^\d{9}$/);
  assert.deepEqual(inserted, [identity.nexusId]);
});

test('A duplicate bank customer reference is still reported as a duplicate customer', async () => {
  const { service } = identityStore([{ code: '23505', constraint: 'uq_nexus_identity_customer' }]);
  await assert.rejects(service.createNexusIdentity('bank-a', 'customer-1'), { name: 'DuplicateBankCustomerError' });
});

test('Repeated ID collisions end with an allocation error, not a duplicate-customer error', async () => {
  const pkey = { code: '23505', constraint: 'nexus_identities_pkey' };
  const { service } = identityStore([pkey, pkey, pkey]);
  await assert.rejects(service.createNexusIdentity('bank-a', 'customer-1'), /Unable to allocate a unique 9-digit NEXUS ID/);
});

test('The result-token parser accepts ES256 only and never a key from the token', async () => {
  const { generateKeyPairSync, sign } = await import('node:crypto');
  const { parseEs256Jws, verifyEs256 } = loadTs('crypto/jws.ts');
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const make = (header, payload = { a: 1 }) => {
    const input = `${b64(header)}.${b64(payload)}`;
    return `${input}.${sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  };
  const good = parseEs256Jws(make({ alg: 'ES256' }));
  assert.equal(verifyEs256(good, publicKey.export({ type: 'spki', format: 'pem' })), true);
  for (const header of [{ alg: 'none' }, { alg: 'HS256' }, { alg: 'ES384' }, { alg: 'ES256', jwk: {} }, { alg: 'ES256', x5c: [] }, { alg: 'ES256', jku: 'https://x' }, { alg: 'ES256', crit: ['x'] }]) {
    assert.throws(() => parseEs256Jws(make(header)), /JwsError|alg|not accepted/, JSON.stringify(header));
  }
  assert.throws(() => parseEs256Jws(`${b64({ alg: 'ES256' })}.${b64({})}.`), /compact JWS/);
  assert.throws(() => parseEs256Jws(`${b64({ alg: 'ES256' })}.${b64({})}.${Buffer.alloc(70).toString('base64url')}`), /64 bytes/, 'DER-encoded signatures are refused');
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => verifyEs256(good, rsa), /not a P-256 key/);
  const otherKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'pem' });
  assert.equal(verifyEs256(good, otherKey), false);
});
