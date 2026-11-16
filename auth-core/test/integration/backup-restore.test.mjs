// Backup and restore with the PostgreSQL tools a bank uses (pg_dump -Fc,
// pg_restore into an empty database), then: the same rows, the evidence
// chain still verifies offline with the HSM public key, the append-only and
// lifecycle triggers are still in force, a tampered record is still found,
// and Auth Core continues the chain on the restored database.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';
import { verifyEvidenceChain } from '../../scripts/lib/evidence.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
};
let tools = true;
try { execFileSync('pg_dump', ['--version']); execFileSync('pg_restore', ['--version']); } catch { tools = false; }

describe('backup and restore keep the evidence verifiable (PostgreSQL)', { skip: skipWithoutServices || (tools ? false : 'pg_dump/pg_restore are not installed') }, () => {
  let source; let restored; let dir; let hsm; let s; let r; let src; let dst;
  const clientId = `bank-${randomBytes(4).toString('hex')}`;
  const TABLES = ['nexus_identities', 'credentials', 'mandates', 'mandate_debits', 'evidence_records', 'evidence_outcomes', 'audit_logs', 'device_replacements'];

  const services = (url) => {
    process.env.DATABASE_URL = url;
    const cache = new Map();
    const out = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      mandates: loadTs('services/mandateService.ts', { stubs, cache }),
      evidence: loadTs('services/evidenceService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    return out;
  };

  before(async () => {
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs });
    hsm = new SoftwareHsmAdapter();
    source = await createDatabase();
    restored = await createDatabase({ schema: false });
    dir = mkdtempSync(join(tmpdir(), 'nexus-backup-'));
    src = new pg.Client({ connectionString: source.url }); await src.connect();
    dst = new pg.Client({ connectionString: restored.url }); await dst.connect();
    await src.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ($1, 'x')`, [clientId]);
    s = services(source.url);
  });
  after(async () => {
    await s?.db.pool.end(); await r?.db.pool.end(); await src?.end(); await dst?.end();
    await source?.drop(); await restored?.drop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  const chain = async (c, nexusId) => (await c.query(`SELECT * FROM evidence_records WHERE nexus_id = $1 ORDER BY chain_sequence`, [nexusId])).rows.map((row) => s.evidence.mapEvidenceRow(row));
  const keys = async () => ({ [await hsm.evidenceKeyId()]: await hsm.evidencePublicKeyPem() });
  let nexusId; let phone; let mandate;

  test('a customer with a device, a signed mandate, a debit and a revoked device is backed up and restored', async () => {
    nexusId = (await s.identities.createNexusIdentity(clientId, `cust-${randomBytes(4).toString('hex')}`)).nexusId;
    const enrol = async () => {
      const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const c = await s.credentials.createCredential({
        nexusId, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), platform: 'IOS', securityLevel: 'SECURE_ENCLAVE',
        attestationStatus: 'VERIFIED', clientId, hsm, enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
      });
      return { ...c, privateKey, device: { clientId, nexusId, credentialId: c.credentialId } };
    };
    phone = await enrol();
    const offered = await s.mandates.createMandate(clientId, {
      nexusId, credentialId: phone.credentialId, mandateReference: `M-${randomUUID()}`, payee: { iban: 'PL61109010140000071219812874', name: 'Energy Co' },
      currency: 'EUR', perPaymentLimitMinor: '15000', totalLimitMinor: null, frequency: 'MONTHLY', validFrom: new Date(Date.now() - 60_000).toISOString(),
      validUntil: new Date(Date.now() + 365 * 86400_000).toISOString(), termsVersion: '2026-11',
    });
    mandate = await s.mandates.signMandate(hsm, phone.device, offered.mandateId,
      sign('sha256', Buffer.from(offered.termsBase64, 'base64'), { key: phone.privateKey, dsaEncoding: 'der' }).toString('base64'), 'der');
    assert.equal((await s.mandates.requestMandateDebit(clientId, mandate.mandateId, { debitReference: 'D1', amountMinor: '9000', currency: 'EUR' })).decision, 'ALLOWED');
    await s.credentials.revokeCredentialForClient(phone.credentialId, clientId, 'lost');
    while (await s.evidence.sealPendingOutcomes(hsm) > 0);
    assert.deepEqual(verifyEvidenceChain(await chain(src, nexusId), await keys()), []);

    const file = join(dir, 'nexus.dump');
    execFileSync('pg_dump', ['--format=custom', '--no-owner', '--file', file, source.url]);
    execFileSync('pg_restore', ['--no-owner', '--exit-on-error', '--dbname', restored.url, file]);
    for (const table of TABLES) {
      const [a, b] = await Promise.all([src.query(`SELECT count(*)::int AS n FROM ${table}`), dst.query(`SELECT count(*)::int AS n FROM ${table}`)]);
      assert.equal(b.rows[0].n, a.rows[0].n, `${table} row count`);
    }
  });

  test('the restored chain verifies offline, and a record altered after restore is found', async () => {
    const records = await chain(dst, nexusId);
    assert.deepEqual(records.map((x) => x.recordType), ['CREDENTIAL_ENROLLED', 'MANDATE', 'CREDENTIAL_REVOKED']);
    assert.deepEqual(verifyEvidenceChain(records, await keys()), []);
    const altered = records.map((x, i) => (i === 1 ? { ...x, sealedPayload: { ...x.sealedPayload, termsHash: '0'.repeat(64) } } : x));
    assert.ok(verifyEvidenceChain(altered, await keys()).length > 0);
    const head = await src.query(`SELECT max(chain_sequence) AS seq, (array_agg(evidence_hash ORDER BY chain_sequence DESC))[1] AS hash FROM evidence_records WHERE nexus_id = $1`, [nexusId]);
    const headAfter = await dst.query(`SELECT max(chain_sequence) AS seq, (array_agg(evidence_hash ORDER BY chain_sequence DESC))[1] AS hash FROM evidence_records WHERE nexus_id = $1`, [nexusId]);
    assert.deepEqual(headAfter.rows[0], head.rows[0], 'the chain head the bank holds matches the restored database');
  });

  test('the database rules are restored with the data', async () => {
    await assert.rejects(dst.query(`UPDATE evidence_records SET evidence_hash = $2 WHERE nexus_id = $1`, [nexusId, 'f'.repeat(64)]), /append-only|not allowed|immutable|cannot/i);
    await assert.rejects(dst.query(`DELETE FROM audit_logs`), /append-only|not allowed|immutable|cannot/i);
    await assert.rejects(dst.query(`UPDATE mandates SET per_payment_limit_minor = 99999 WHERE mandate_id = $1`, [mandate.mandateId]), /immutable/);
    await assert.rejects(dst.query(`DELETE FROM mandate_debits`), /./);
    await assert.rejects(dst.query(`UPDATE credentials SET state = 'ACTIVE' WHERE credential_id = $1`, [phone.credentialId]), /./);
  });

  test('Auth Core continues the chain on the restored database', async () => {
    r = services(restored.url);
    const withdrawn = await r.mandates.withdrawMandate(hsm, clientId, mandate.mandateId, 'after restore');
    assert.equal(withdrawn.state, 'WITHDRAWN');
    const records = await chain(dst, nexusId);
    assert.equal(records.at(-1).sealedPayload.event, 'WITHDRAWN');
    assert.equal(records.at(-1).chainSequence, records.at(-2).chainSequence + 1);
    assert.deepEqual(verifyEvidenceChain(records, await keys()), []);
    // The source never saw that record: the two databases have diverged, as a restore to a new primary does.
    assert.equal((await chain(src, nexusId)).length, records.length - 1);
  });
});
