// NXS-010 (audit attribution, append-only audit log), NXS-011 (admin bank
// scope, TOTP, four-eyes approvals) and NXS-012 (bank tokens bound to the
// client certificate) against a live Auth Core and PostgreSQL.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { adminSession, bankSession, call, totp } from './support/actors.mjs';

const fingerprint = (label) => createHash('sha256').update(label).digest('hex');

describe('audit log', { skip: skipWithoutServices }, () => {
  let server; let bank;
  before(async () => {
    server = await startAuthCore();
    bank = await bankSession(server, await server.registerBank('bank-audit'));
  });
  after(async () => { await server?.stop(); });

  test('bank calls are recorded with bank, actor, address and user agent', async () => {
    const { nexusId } = await bank.createIdentity();
    const { rows } = await server.db.query(`SELECT client_id, actor, ip_address, user_agent FROM audit_logs WHERE event_type = 'identity_created' AND nexus_id = $1`, [nexusId]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].client_id, 'bank-audit');
    assert.equal(rows[0].actor, 'bank:bank-audit');
    assert.ok(rows[0].ip_address);
    assert.ok(rows[0].user_agent);
    const issued = await server.db.query(`SELECT client_id FROM audit_logs WHERE event_type = 'oauth_token_issued'`);
    assert.deepEqual(issued.rows.map((r) => r.client_id), ['bank-audit']);
  });

  test('a rejected token request is recorded without attributing it to the claimed bank', async () => {
    const r = await call(server.baseUrl, 'POST', '/oauth/token', { body: { grant_type: 'client_credentials', client_id: 'bank-audit', client_secret: 'wrong' } });
    assert.equal(r.status, 401);
    const { rows } = await server.db.query(`SELECT client_id, details FROM audit_logs WHERE event_type = 'oauth_token_rejected'`);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].client_id, null);
    assert.equal(rows[0].details.claimedClientId, 'bank-audit');
  });

  test('audit records cannot be updated, deleted or truncated', async () => {
    for (const statement of ['UPDATE audit_logs SET event_type = $$x$$', 'DELETE FROM audit_logs', 'TRUNCATE audit_logs']) {
      await assert.rejects(server.db.query(statement), /append-only/, statement);
    }
    assert.ok((await server.db.query('SELECT count(*)::int AS n FROM audit_logs')).rows[0].n > 0);
  });
});

describe('admin console', { skip: skipWithoutServices }, () => {
  let server; let bankA; let bankB; let platform; let platform2; let operatorA; let operatorB; let identityA;
  before(async () => {
    server = await startAuthCore({ env: { ADMIN_MFA_REQUIRED: 'true' } });
    bankA = await bankSession(server, await server.registerBank('bank-a'));
    bankB = await bankSession(server, await server.registerBank('bank-b'));
    platform = await server.createAdmin('platform-1', 'operator');
    platform2 = await server.createAdmin('platform-2', 'operator');
    operatorA = await server.createAdmin('operator-a', 'operator', { clientId: 'bank-a' });
    operatorB = await server.createAdmin('operator-b', 'operator', { clientId: 'bank-b' });
    identityA = await bankA.createIdentity();
  });
  after(async () => { await server?.stop(); });

  test('the CLI enrols a TOTP secret, and login needs a valid, unused code', async () => {
    assert.match(platform.totpSecret, /^[A-Z2-7]{32}$/);
    assert.equal((await adminSession(server, { ...platform, totpSecret: undefined })).login.status, 401);
    assert.equal((await adminSession(server, platform, { code: '000000' === totp(platform.totpSecret) ? '111111' : '000000' })).login.status, 401);
    const code = totp(platform.totpSecret);
    assert.equal((await adminSession(server, platform, { code })).login.status, 200);
    assert.equal((await adminSession(server, platform, { code })).login.status, 401, 'a code is accepted once');
    const failures = await server.db.query(`SELECT details->>'reason' AS reason FROM audit_logs WHERE event_type = 'admin_login_failed' ORDER BY "timestamp"`);
    assert.deepEqual(failures.rows.map((r) => r.reason), ['totp_missing', 'wrong_or_reused_totp', 'wrong_or_reused_totp']);
  });

  test('an account without TOTP cannot log in while MFA is required', async () => {
    await server.db.query(`INSERT INTO admin_users (username, password_hash, role) SELECT 'no-mfa', password_hash, 'operator' FROM admin_users WHERE username = 'operator-a'`);
    assert.equal((await adminSession(server, { username: 'no-mfa', password: operatorA.password })).login.status, 401);
  });

  test('a bank-scoped admin sees only its bank', async () => {
    const identityB = await bankB.createIdentity();
    const a = await adminSession(server, operatorA, { code: totp(operatorA.totpSecret, 1) });
    assert.equal((await a.call('GET', `/admin/api/identities/${identityA.nexusId}`)).status, 200);
    assert.equal((await a.call('GET', `/admin/api/identities/${identityB.nexusId}`)).status, 404);
    assert.equal((await a.call('POST', `/admin/api/identities/${identityB.nexusId}/suspend`, { body: { reason: 'x' } })).status, 404);
    const clients = (await a.call('GET', '/admin/api/clients')).json;
    assert.deepEqual(clients.map((c) => c.clientId), ['bank-a']);
    const logs = (await a.call('GET', '/admin/api/audit-logs?limit=500')).json;
    assert.ok(logs.length > 0);
    assert.ok(logs.every((l) => l.clientId === 'bank-a'), 'no other bank\'s audit records');
    const viewed = await server.db.query(`SELECT actor, nexus_id FROM audit_logs WHERE event_type = 'admin_identity_viewed'`);
    assert.deepEqual(viewed.rows, [{ actor: 'admin:operator-a', nexus_id: identityA.nexusId }]);
  });

  test('revocation needs a second admin with access to the bank', async () => {
    const requester = await adminSession(server, platform2, { code: totp(platform2.totpSecret) });
    const requested = await requester.call('POST', `/admin/api/identities/${identityA.nexusId}/revoke`, { body: { reason: 'customer request' } });
    assert.equal(requested.status, 202);
    assert.equal(requested.json.status, 'PENDING');
    assert.equal((await server.db.query('SELECT status FROM nexus_identities WHERE nexus_id = $1', [identityA.nexusId])).rows[0].status, 'ACTIVE');
    assert.equal((await requester.call('POST', `/admin/api/identities/${identityA.nexusId}/revoke`, { body: { reason: 'again' } })).status, 409);

    const id = requested.json.approvalId;
    assert.equal((await requester.call('POST', `/admin/api/approvals/${id}/approve`)).status, 403, 'the requester cannot approve');
    const otherBank = await adminSession(server, operatorB, { code: totp(operatorB.totpSecret) });
    assert.equal((await otherBank.call('POST', `/admin/api/approvals/${id}/approve`)).status, 404, 'another bank\'s admin cannot see it');
    assert.equal((await otherBank.call('GET', '/admin/api/approvals')).json.length, 0);

    // operator-a's codes up to the next step are used up by the earlier login.
    const approverAccount = await server.createAdmin('operator-a2', 'operator', { clientId: 'bank-a' });
    const approver = await adminSession(server, approverAccount);
    assert.equal((await approver.call('GET', '/admin/api/approvals')).json.length, 1);
    const approved = await approver.call('POST', `/admin/api/approvals/${id}/approve`);
    assert.equal(approved.status, 200);
    assert.equal(approved.json.status, 'EXECUTED');
    assert.equal(approved.json.decidedBy, 'operator-a2');
    assert.equal((await server.db.query('SELECT status FROM nexus_identities WHERE nexus_id = $1', [identityA.nexusId])).rows[0].status, 'REVOKED');
    const revoked = await server.db.query(`SELECT actor FROM audit_logs WHERE event_type = 'identity_revoked' AND nexus_id = $1`, [identityA.nexusId]);
    assert.equal(revoked.rows[0].actor, 'admin:operator-a2 (requested by admin:platform-2)');
    assert.equal((await approver.call('POST', `/admin/api/approvals/${id}/approve`)).status, 409, 'executed once');
  });

  test('NXS-032: resetting the password ends existing sessions, and cross-origin state changes are refused', async () => {
    const account = await server.createAdmin('session-check', 'operator', { clientId: 'bank-a' });
    const session = await adminSession(server, account);
    assert.equal((await session.call('GET', '/admin/api/me')).status, 200);
    const { nexusId } = await bankA.createIdentity();
    const crossSite = await session.call('POST', `/admin/api/identities/${nexusId}/suspend`, { body: { reason: 'x' }, headers: { origin: 'https://evil.example' } });
    assert.equal(crossSite.status, 403);
    const sameSite = await session.call('POST', `/admin/api/identities/${nexusId}/suspend`, { body: { reason: 'x' }, headers: { origin: server.baseUrl } });
    assert.equal(sameSite.status, 200, sameSite.text);
    await server.createAdmin('session-check', 'operator', { clientId: 'bank-a' });
    assert.equal((await session.call('GET', '/admin/api/me')).status, 401, 'the old session ended');
  });

  test('the database refuses an approval executed by its requester', async () => {
    const { nexusId } = await bankA.createIdentity();
    await server.db.query(`INSERT INTO admin_approvals (action, nexus_id, client_id, reason, requested_by, expires_at) VALUES ('REVOKE', $1, 'bank-a', 'r', 'platform-1', now() + interval '1 hour')`, [nexusId]);
    await assert.rejects(server.db.query(`UPDATE admin_approvals SET status = 'EXECUTED', decided_by = 'platform-1', decided_at = now() WHERE nexus_id = $1`, [nexusId]), /admin_approvals_two_people/);
  });
});

describe('bank certificate binding', { skip: skipWithoutServices }, () => {
  let server; let credsA; let credsB;
  const gateway = (label) => ({ 'x-client-cert-verified': 'SUCCESS', 'x-client-cert-sha256': fingerprint(label) });
  before(async () => {
    server = await startAuthCore({ env: { REQUIRE_MTLS_HEADER: 'true', TRUSTED_PROXY_IPS: '127.0.0.1,::1,::ffff:127.0.0.1' } });
    credsA = await server.registerBank('bank-a', { certificateSha256: fingerprint('cert-a') });
    credsB = await server.registerBank('bank-b', { certificateSha256: fingerprint('cert-b') });
  });
  after(async () => { await server?.stop(); });

  const tokenRequest = (creds, headers) => call(server.baseUrl, 'POST', '/oauth/token', {
    body: { grant_type: 'client_credentials', client_id: creds.clientId, client_secret: creds.secret }, headers });

  test('a token is issued only over the bank\'s own certificate', async () => {
    assert.equal((await tokenRequest(credsB, gateway('cert-a'))).status, 401);
    assert.equal((await tokenRequest(credsB, { 'x-client-cert-verified': 'SUCCESS' })).status, 403, 'no fingerprint');
    assert.equal((await tokenRequest(credsB, gateway('cert-b'))).status, 200);
    const { rows } = await server.db.query(`SELECT client_id, details->>'stage' AS stage FROM audit_logs WHERE event_type = 'bank_certificate_mismatch'`);
    assert.deepEqual(rows, [{ client_id: 'bank-b', stage: 'token' }]);
  });

  test('a bank token is refused over another bank\'s certificate', async () => {
    const bankB = await bankSession(server, credsB, { headers: gateway('cert-b') });
    assert.equal((await bankB.call('POST', '/v1/nexus-identities', { body: { bankCustomerRef: 'c-1' } })).status, 201);
    const stolen = await call(server.baseUrl, 'POST', '/v1/nexus-identities', { token: bankB.token, body: { bankCustomerRef: 'c-2' }, headers: gateway('cert-a') });
    assert.equal(stolen.status, 401);
    // The registered fingerprint is also accepted in colon-separated upper case.
    const colons = fingerprint('cert-b').toUpperCase().match(/../g).join(':');
    const r = await call(server.baseUrl, 'POST', '/v1/nexus-identities', { token: bankB.token, body: { bankCustomerRef: 'c-3' }, headers: { ...gateway('cert-b'), 'x-client-cert-sha256': colons } });
    assert.equal(r.status, 201);
  });

  test('re-registering a bank without the option keeps its certificates', async () => {
    const rotated = await server.registerBank('bank-a');
    assert.equal((await tokenRequest(rotated, gateway('cert-a'))).status, 200);
    credsA = rotated;
  });

  test('a certificate rollover changes the fingerprints without rotating the secret', async () => {
    const { spawnSync } = await import('node:child_process');
    const { join } = await import('node:path');
    const { ROOT } = await import('./support/harness.mjs');
    const run = (args) => spawnSync(process.execPath, [join(ROOT, 'dist/cli/setClientCertificates.js'), ...args], { env: server.env, encoding: 'utf8' });
    assert.equal(run(['bank-a', `${fingerprint('cert-a')},${fingerprint('cert-a2')}`]).status, 0);
    assert.equal((await tokenRequest(credsA, gateway('cert-a2'))).status, 200, 'the same secret works over the new certificate');
    assert.equal(run(['bank-a', fingerprint('cert-a2')]).status, 0);
    assert.equal((await tokenRequest(credsA, gateway('cert-a'))).status, 401, 'the old certificate is no longer accepted');
    assert.notEqual(run(['bank-a', 'not-hex']).status, 0);
    assert.notEqual(run(['no-such-bank', fingerprint('x')]).status, 0);
  });
});
