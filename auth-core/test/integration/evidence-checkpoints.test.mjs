// FI-019: every record appended to a customer's evidence chain sends the new,
// HSM-sealed head to the bank (`evidence.appended` webhook). With the heads
// it kept, the bank detects records removed from the end of an export, which
// the chain alone cannot show.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT, skipWithoutServices, startAuthCore } from './support/harness.mjs';
import { bankSession, deviceSignature, submitSignature } from './support/actors.mjs';

const verify = (...args) => spawnSync(process.execPath, [join(ROOT, 'scripts/verify-evidence.mjs'), ...args], { encoding: 'utf8' });

describe('evidence chain checkpoints held by the bank', { skip: skipWithoutServices }, () => {
  let server; let bank; let device; let dir;
  before(async () => {
    server = await startAuthCore();
    bank = await bankSession(server, await server.registerBank('bank-checkpoints', { webhookUrl: 'https://bank.example/hooks' }));
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    for (let i = 0; i < 2; i += 1) {
      const auth = await bank.createAuthorization(device);
      const { signature } = await deviceSignature(server, device, auth.authorizationId);
      assert.equal((await submitSignature(server, device, auth.authorizationId, signature)).json.status, 'VERIFIED');
    }
    dir = mkdtempSync(join(tmpdir(), 'nexus-heads-'));
  });
  after(async () => { await server?.stop(); });

  async function exportAndHeads() {
    const exported = await bank.call('GET', `/v1/nexus-identities/${device.nexusId}/evidence`);
    assert.equal(exported.status, 200, exported.text);
    const heads = (await server.db.query(
      `SELECT payload FROM webhook_deliveries WHERE client_id = 'bank-checkpoints' AND event_type = 'evidence.appended' ORDER BY created_at`)).rows.map((r) => r.payload);
    const keys = join(dir, 'keys.pem');
    writeFileSync(keys, exported.json.evidencePublicKeyPem);
    return { chain: exported.json, heads, keys };
  }

  test('one sealed head per appended record reaches the bank outbox', async () => {
    const { chain, heads } = await exportAndHeads();
    assert.equal(chain.records.length, 3, 'enrolment + two confirmations');
    assert.deepEqual(heads.map((h) => [h.chainSequence, h.recordType]), [[1, 'CREDENTIAL_ENROLLED'], [2, 'AUTHORIZATION'], [3, 'AUTHORIZATION']]);
    assert.deepEqual(heads.map((h) => h.evidenceHash), chain.records.map((r) => r.evidenceHash));
    assert.ok(heads.every((h) => h.hsmSignature && h.sealKeyId));
  });

  test('the export verifies against the retained heads; a truncated export does not', async () => {
    const { chain, heads, keys } = await exportAndHeads();
    const headsFile = join(dir, 'heads.jsonl');
    writeFileSync(headsFile, heads.map((h) => JSON.stringify(h)).join('\n'));
    const full = join(dir, 'full.json');
    writeFileSync(full, JSON.stringify(chain));
    const ok = verify(full, `--public-keys=${keys}`, `--heads=${headsFile}`);
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.match(ok.stdout, /EVIDENCE_VALID records=3 .*heads=3_matched/);

    const truncated = join(dir, 'truncated.json');
    writeFileSync(truncated, JSON.stringify({ ...chain, records: chain.records.slice(0, 2) }));
    const withoutHeads = verify(truncated, `--public-keys=${keys}`);
    assert.equal(withoutHeads.status, 0, 'the chain alone cannot show a removed tail');
    const withHeads = verify(truncated, `--public-keys=${keys}`, `--heads=${headsFile}`);
    assert.equal(withHeads.status, 1);
    assert.match(withHeads.stderr, /records missing at the end of the chain: the bank holds head #3, the export ends at 2/);
  });

  test('a head not sealed by the evidence key is reported', async () => {
    const { chain, heads, keys } = await exportAndHeads();
    const forged = heads.map((h, i) => (i === 2 ? { ...h, hsmSignature: heads[1].hsmSignature } : h));
    const file = join(dir, 'forged.json');
    writeFileSync(file, JSON.stringify(forged));
    const full = join(dir, 'full2.json');
    writeFileSync(full, JSON.stringify(chain));
    const result = verify(full, `--public-keys=${keys}`, `--heads=${file}`);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /head #3: its HSM seal does not verify/);
  });
});
