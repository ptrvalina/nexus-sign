// SIEM export of the audit log (services/auditExport.ts) on PostgreSQL:
// cursor order, the lag that keeps late commits from being skipped, the
// per-bank filter, and the JSON (ECS) and CEF line formats with escaping.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';

describe('audit export for a SIEM (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let client; let x;
  before(async () => {
    db = await createDatabase();
    client = new pg.Client({ connectionString: db.url });
    await client.connect();
    x = loadTs('services/auditExport.ts');
    const insert = (ts, type, clientId, extra = {}) => client.query(
      `INSERT INTO audit_logs (event_id, timestamp, event_type, nexus_id, client_id, actor, ip_address, user_agent, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [randomUUID(), ts, type, extra.nexusId ?? null, clientId, extra.actor ?? null, extra.ip ?? null, extra.ua ?? null, JSON.stringify(extra.details ?? {})]);
    const old = (s) => new Date(Date.now() - s * 1000).toISOString();
    await insert(old(600), 'admin_login', 'bank-a', { actor: 'admin:anna', ip: '192.0.2.10' });
    await insert(old(500), 'admin_login_failed', 'bank-b', { actor: 'admin:x|y=z', ip: '198.51.100.7', ua: 'curl/8\nInjected: line', details: { reason: 'bad=password|x\\y' } });
    await insert(old(400), 'credential_revoked', 'bank-a', { nexusId: '123456789', details: { credentialId: 'c1', reason: 'lost' } });
    await insert(old(5), 'identity_created', 'bank-a', { nexusId: '987654321' }); // inside the lag
  });
  after(async () => { await client?.end(); await db?.drop(); });

  test('events after the cursor in order; younger than the lag are held back; the cursor resumes exactly', async () => {
    const first = await x.exportAuditEvents(client, { limit: 2, lagSeconds: 60 });
    assert.deepEqual(first.events.map((e) => e.eventType), ['admin_login', 'admin_login_failed']);
    const second = await x.exportAuditEvents(client, { after: first.next, lagSeconds: 60 });
    assert.deepEqual(second.events.map((e) => e.eventType), ['credential_revoked']);
    const third = await x.exportAuditEvents(client, { after: second.next, lagSeconds: 60 });
    assert.deepEqual(third.events, []); assert.equal(third.next, second.next);
    const noLag = await x.exportAuditEvents(client, { after: second.next, lagSeconds: 0 });
    assert.deepEqual(noLag.events.map((e) => e.eventType), ['identity_created']);
    assert.deepEqual((await x.exportAuditEvents(client, { clientId: 'bank-b', lagSeconds: 0 })).events.map((e) => e.clientId), ['bank-b']);
    assert.throws(() => x.parseCursor('yesterday'), /cursor must be/);
  });

  test('JSON lines carry ECS names; CEF lines escape what would split a field or a line', async () => {
    const { events } = await x.exportAuditEvents(client, { lagSeconds: 0 });
    const failed = events.find((e) => e.eventType === 'admin_login_failed');
    const json = JSON.parse(x.toJsonLine(failed, { vendor: 'NEXIS', name: 'NEXUS-SIGN', version: '2.0.0-rc.2' }));
    assert.equal(json.event.action, 'admin_login_failed'); assert.equal(json.event.severity, 7);
    assert.equal(json.source.ip, '198.51.100.7'); assert.equal(json.user.name, 'admin:x|y=z');
    assert.equal(json.nexus_sign.details.reason, 'bad=password|x\\y');
    assert.match(json['@timestamp'], /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
    const cef = x.toCef(failed, { vendor: 'NEXIS', name: 'NEXUS-SIGN', version: '2.0.0-rc.2' });
    assert.equal(cef.split('\n').length, 1, 'one line');
    assert.match(cef, /^CEF:0\|NEXIS\|NEXUS-SIGN\|2\.0\.0-rc\.2\|admin_login_failed\|admin_login_failed\|7\|/);
    assert.match(cef, / suser=admin:x\|y\\=z /, 'equals sign escaped in an extension value');
    assert.match(cef, /requestClientApplication=curl\/8\\nInjected: line/, 'line break escaped');
    assert.equal(x.severity('admin_login'), 3);
    const revoked = x.toCef(events.find((e) => e.eventType === 'credential_revoked'));
    assert.match(revoked, /cs1Label=nexusId cs1=123456789/);
  });
});
