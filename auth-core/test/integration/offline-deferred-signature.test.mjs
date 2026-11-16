// offline confirmation v2 (docs/protocol/offline-confirmation-v2-deferred-signature.md):
// an accepted offline code leaves the authorization OFFLINE_PROVISIONAL; it
// becomes VERIFIED only with the device's ECDSA signature over the same
// canonical bytes, uploaded later. Negative, ordering, concurrency, restart
// and insider cases, numbered as in the specification's test matrix.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, createHash, createHmac } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices, startAuthCore, startExpectingFailure } from './support/harness.mjs';
import { bankSession, call, deviceSignature, offlineCode, signDer, submitSignature } from './support/actors.mjs';
import { verifyDeviceSignature, verifyEvidenceRecord } from '../../scripts/lib/evidence.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('offline confirmation v2: deferred device signature', { skip: skipWithoutServices }, () => {
  let server; let bank; let client;
  before(async () => {
    server = await startAuthCore({ env: { OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY: '3', AUTHORIZATION_EXPIRY_SWEEP_MS: '500' } });
    client = await server.registerBank('bank-deferred', { webhookUrl: 'https://bank.example/hooks' });
    bank = await bankSession(server, client);
  });
  after(async () => { await server?.stop(); });

  const q = (sql, args) => server.db.query(sql, args);
  const newDevice = async () => bank.enrolDevice((await bank.createIdentity()).nexusId);
  const stateOf = async (id) => (await bank.call('GET', `/v1/authorizations/${id}`)).json;
  const submitCode = (id, code) => bank.call('POST', `/v1/authorizations/${id}/offline-confirmation`, { body: { code } });
  const upload = (device, id, signature, signatureFormat = 'der') =>
    call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${id}/deferred-signature`, { device, body: { signature, signatureFormat } });
  const evidenceCount = async (id) => (await q(`SELECT count(*)::int AS n FROM evidence_records WHERE authorization_id = $1`, [id])).rows[0].n;
  const webhooks = async (id, type) => (await q(`SELECT payload FROM webhook_deliveries WHERE event_type = $2 AND payload->>'authorizationId' = $1`, [id, type])).rows;
  const audits = async (type, id) => (await q(`SELECT details FROM audit_logs WHERE event_type = $1 AND details->>'authorizationId' = $2`, [type, id])).rows;

  /** What the phone holds after confirming offline: the QR bytes, its signature and the code. */
  async function confirmOnPhone(device, overrides) {
    const auth = await bank.createAuthorization(device, overrides);
    const challenge = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/offline-challenge`);
    assert.equal(challenge.status, 200, challenge.text);
    assert.ok(challenge.json.qrPayload.startsWith('NXS2.'), 'v2 QR prefix');
    const canonical = Buffer.from(challenge.json.qrPayload.slice(5), 'base64url');
    return { id: auth.authorizationId, canonical, signature: signDer(device.signingKey, canonical), code: offlineCode(device, canonical) };
  }

  /** Moves the deadline into the past, as if the hours had passed (test-only write past the trigger). */
  async function passDeadline(id) {
    await q(`ALTER TABLE authorization_requests DISABLE TRIGGER authorization_lifecycle;
      UPDATE authorization_requests SET offline_signature_deadline = now() - interval '1 second' WHERE authorization_id = '${id}';
      ALTER TABLE authorization_requests ENABLE TRIGGER authorization_lifecycle;`);
  }

  async function waitForState(id, state) {
    for (let i = 0; i < 60; i += 1) {
      if ((await stateOf(id)).state === state) return;
      await sleep(100);
    }
    assert.fail(`authorization ${id} did not reach ${state}: ${JSON.stringify(await stateOf(id))}`);
  }

  test('1, 9: code, then signature: PROVISIONAL, then VERIFIED as OFFLINE_SIGNED; a repeat changes nothing', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    const accepted = await submitCode(phone.id, phone.code);
    assert.equal(accepted.json.status, 'PROVISIONAL', accepted.text);
    assert.ok(Date.parse(accepted.json.signatureDeadline) > Date.now() + 71 * 3600_000, 'deadline about 72 hours ahead');
    const provisional = await stateOf(phone.id);
    assert.equal(provisional.state, 'OFFLINE_PROVISIONAL');
    assert.equal(provisional.verifiedAt, null);
    assert.equal(await evidenceCount(phone.id), 0, 'nothing sealed for a provisional confirmation');
    assert.equal((await webhooks(phone.id, 'authorization.offline_provisional')).length, 1);
    assert.equal((await webhooks(phone.id, 'authorization.verified')).length, 0, 'the bank is not told VERIFIED');
    const commit = await bank.call('POST', `/v1/authorizations/${phone.id}/bank-commit-request`, { body: { bankTransactionReference: 'B-1' } });
    assert.equal(commit.status, 409, `no bank commit while provisional: ${commit.text}`);
    assert.equal((await submitCode(phone.id, phone.code)).json.status, 'FAILED', 'the code is single-use');

    const signed = await upload(device, phone.id, phone.signature);
    assert.equal(signed.status, 200, signed.text);
    assert.equal(signed.json.status, 'VERIFIED');
    const verified = await stateOf(phone.id);
    assert.equal(verified.state, 'VERIFIED');
    assert.equal(verified.confirmationMethod, 'OFFLINE_SIGNED');
    const hook = await webhooks(phone.id, 'authorization.verified');
    assert.equal(hook.length, 1);
    assert.equal(hook[0].payload.confirmationMethod, 'OFFLINE_SIGNED');

    const evidence = await bank.call('GET', `/v1/authorizations/${phone.id}/evidence`);
    const payload = evidence.json.sealedPayload;
    assert.equal(payload.confirmationMethod, 'OFFLINE_SIGNED');
    assert.equal(payload.signature, phone.signature);
    assert.equal(payload.signatureFormat, 'der');
    assert.equal(Buffer.from(payload.offlineCodeTag, 'base64').length, 32);
    assert.ok(payload.offlineCodeAcceptedAt && payload.deferredSignatureReceivedAt);
    assert.deepEqual(verifyEvidenceRecord(evidence.json, evidence.json.evidencePublicKeys ?? evidence.json.evidencePublicKeyPem, { standalone: true }), []);

    const repeat = await upload(device, phone.id, phone.signature);
    assert.equal(repeat.status, 200, repeat.text);
    assert.equal(repeat.json.status, 'ALREADY_RECORDED');
    assert.equal(await evidenceCount(phone.id), 1);
  });

  test('2: signature first (phone online before the code is typed): RECEIVED, the code then verifies at once', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    const early = await upload(device, phone.id, phone.signature);
    assert.equal(early.status, 202, early.text);
    assert.equal(early.json.status, 'RECEIVED');
    assert.equal((await stateOf(phone.id)).state, 'PENDING_USER', 'a signature alone confirms nothing');
    const accepted = await submitCode(phone.id, phone.code);
    assert.equal(accepted.json.status, 'VERIFIED', accepted.text);
    assert.equal((await stateOf(phone.id)).confirmationMethod, 'OFFLINE_SIGNED');
    assert.equal(await evidenceCount(phone.id), 1);
  });

  test('3: signatures over changed amount, changed payee or another authorization are refused; nothing changes', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    assert.equal((await submitCode(phone.id, phone.code)).json.status, 'PROVISIONAL');
    const amount = Buffer.from(phone.canonical.toString('utf8').replace('"amount_minor":"125000"', '"amount_minor":"999999"'));
    const payee = Buffer.from(phone.canonical.toString('utf8').replace('PL61109010140000071219812874', 'PL27114020040000300201355387'));
    assert.notDeepEqual(amount, phone.canonical);
    assert.notDeepEqual(payee, phone.canonical);
    const other = await confirmOnPhone(device);
    for (const [what, bytes] of [['amount', amount], ['payee', payee], ['other authorization', other.canonical]]) {
      const r = await upload(device, phone.id, signDer(device.signingKey, bytes));
      assert.equal(r.status, 422, `${what}: ${r.text}`);
      assert.equal(r.json.code, 'INVALID_DEFERRED_SIGNATURE');
    }
    assert.equal((await stateOf(phone.id)).state, 'OFFLINE_PROVISIONAL');
    assert.equal((await audits('deferred_signature_invalid', phone.id)).length, 3);
    assert.equal((await q(`SELECT count(*)::int AS n FROM offline_deferred_signatures WHERE authorization_id = $1`, [phone.id])).rows[0].n, 0);
  });

  test('4: another device\'s key, or a request from another credential, is refused', async () => {
    const device = await newDevice();
    const intruder = await newDevice();
    const phone = await confirmOnPhone(device);
    assert.equal((await submitCode(phone.id, phone.code)).json.status, 'PROVISIONAL');
    const wrongKey = await upload(device, phone.id, signDer(intruder.signingKey, phone.canonical));
    assert.equal(wrongKey.status, 422, wrongKey.text);
    const wrongSender = await upload(intruder, phone.id, phone.signature);
    assert.equal(wrongSender.status, 403, wrongSender.text);
    assert.equal((await stateOf(phone.id)).state, 'OFFLINE_PROVISIONAL');
  });

  test('5: credential revoked while provisional: the device cannot upload; the sweep records OFFLINE_UNSIGNED', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    assert.equal((await submitCode(phone.id, phone.code)).json.status, 'PROVISIONAL');
    const revoked = await bank.call('POST', `/v1/credentials/${device.credentialId}/revoke`, { body: { reason: 'lost phone' } });
    assert.ok(revoked.status < 300, revoked.text);
    const late = await upload(device, phone.id, phone.signature);
    assert.ok(late.status === 401 || late.status === 403, `revoked device: ${late.status} ${late.text}`);
    await waitForState(phone.id, 'OFFLINE_UNSIGNED');
    assert.equal((await stateOf(phone.id)).offlineUnsignedReason, 'credential_not_active');
    const hook = await webhooks(phone.id, 'authorization.offline_unsigned');
    assert.equal(hook.length, 1);
    assert.equal(hook[0].payload.reason, 'credential_not_active');
    assert.equal(await evidenceCount(phone.id), 0);
  });

  test('6: unknown signature format and malformed signatures are refused', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    assert.equal((await submitCode(phone.id, phone.code)).json.status, 'PROVISIONAL');
    assert.equal((await upload(device, phone.id, phone.signature, 'pem')).status, 400);
    assert.equal((await upload(device, phone.id, 'not*base64')).status, 422);
    assert.equal((await upload(device, phone.id, phone.signature, 'raw')).status, 422, 'a DER signature declared raw');
    assert.equal((await stateOf(phone.id)).state, 'OFFLINE_PROVISIONAL');
  });

  test('7, 12: no signature is taken for an expired or an already verified authorization', async () => {
    const device = await newDevice();
    const expired = await confirmOnPhone(device);
    await q(`UPDATE authorization_requests SET expires_at = now() - interval '1 second' WHERE authorization_id = $1`, [expired.id]);
    const r = await upload(device, expired.id, expired.signature);
    assert.equal(r.status, 409, r.text);
    assert.equal(r.json.code, 'NOT_AWAITING_SIGNATURE');

    const online = await bank.createAuthorization(device);
    const signed = await deviceSignature(server, device, online.authorizationId);
    assert.equal((await submitSignature(server, device, online.authorizationId, signed.signature)).json.status, 'VERIFIED');
    const again = await upload(device, online.authorizationId, signDer(device.signingKey, signed.canonical));
    assert.equal(again.status, 409, again.text);
    assert.equal(await evidenceCount(online.authorizationId), 1);
  });

  test('8: deadline passed: OFFLINE_UNSIGNED; a genuine signature afterwards is refused and audited as late', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    assert.equal((await submitCode(phone.id, phone.code)).json.status, 'PROVISIONAL');
    await passDeadline(phone.id);
    await waitForState(phone.id, 'OFFLINE_UNSIGNED');
    assert.equal((await stateOf(phone.id)).offlineUnsignedReason, 'deadline');
    assert.equal((await audits('offline_signature_missing', phone.id)).length, 1);
    const late = await upload(device, phone.id, phone.signature);
    assert.equal(late.status, 409, late.text);
    const audit = await audits('deferred_signature_late', phone.id);
    assert.equal(audit.length, 1);
    assert.equal(audit[0].details.verified, true, 'recorded that the late signature was genuine');
    assert.equal((await stateOf(phone.id)).state, 'OFFLINE_UNSIGNED', 'final');
  });

  test('10: concurrent uploads and concurrent codes: one transition, one evidence record', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    const codes = await Promise.all(Array.from({ length: 20 }, () => submitCode(phone.id, phone.code)));
    assert.equal(codes.filter((r) => r.json?.status === 'PROVISIONAL').length, 1, JSON.stringify(codes.map((r) => r.json?.status)));
    assert.ok(codes.every((r) => r.status === 200));
    const uploads = await Promise.all(Array.from({ length: 20 }, () => upload(device, phone.id, phone.signature)));
    const statuses = uploads.map((r) => r.json?.status);
    assert.equal(statuses.filter((s) => s === 'VERIFIED').length, 1, JSON.stringify(statuses));
    assert.equal(statuses.filter((s) => s === 'ALREADY_RECORDED').length, 19, JSON.stringify(statuses));
    assert.equal(await evidenceCount(phone.id), 1);

    // Code and signature at the same moment, from both sides.
    const race = await confirmOnPhone(device);
    const [code, sig] = await Promise.all([submitCode(race.id, race.code), upload(device, race.id, race.signature)]);
    assert.ok(['PROVISIONAL', 'VERIFIED'].includes(code.json.status), code.text);
    assert.ok(['RECEIVED', 'VERIFIED'].includes(sig.json.status), sig.text);
    assert.equal((await stateOf(race.id)).state, 'VERIFIED');
    assert.equal(await evidenceCount(race.id), 1);
  });

  test('13: an OFFLINE_SIGNED record with its signature or bytes replaced fails verification', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    assert.equal((await upload(device, phone.id, phone.signature)).status, 202);
    assert.equal((await submitCode(phone.id, phone.code)).json.status, 'VERIFIED');
    const evidence = (await bank.call('GET', `/v1/authorizations/${phone.id}/evidence`)).json;
    const keys = evidence.evidencePublicKeys ?? evidence.evidencePublicKeyPem;
    const swapped = structuredClone(evidence);
    swapped.sealedPayload.signature = signDer(device.signingKey, Buffer.from('other bytes'));
    assert.ok(verifyEvidenceRecord(swapped, keys, { standalone: true }).length > 0, 'replaced signature');
    // The ECDSA check itself, apart from the seal: a record re-sealed by
    // whoever holds the evidence key would still fail here.
    assert.deepEqual(verifyDeviceSignature(evidence.sealedPayload), []);
    assert.ok(verifyDeviceSignature(swapped.sealedPayload).some((p) => /device signature does not verify/.test(p)), 'the signature is checked');
    const downgraded = structuredClone(evidence);
    downgraded.sealedPayload.confirmationMethod = 'DEVICE_SIGNATURE';
    assert.ok(verifyEvidenceRecord(downgraded, keys, { standalone: true }).some((p) => /evidence hash/.test(p)), 'relabelled record');
    const noCode = structuredClone(evidence);
    delete noCode.sealedPayload.offlineCodeTag;
    assert.ok(verifyEvidenceRecord(noCode, keys, { standalone: true }).some((p) => /accepted code/.test(p)));
  });

  test('14: terms and policy version cannot change under a provisional confirmation', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    assert.equal((await submitCode(phone.id, phone.code)).json.status, 'PROVISIONAL');
    for (const sql of [
      `UPDATE authorization_requests SET amount_minor = '1' WHERE authorization_id = $1`,
      `UPDATE authorization_requests SET policy_version = '2' WHERE authorization_id = $1`,
      `UPDATE authorization_requests SET offline_signature_deadline = now() + interval '30 days' WHERE authorization_id = $1`,
      `UPDATE authorization_requests SET offline_code_tag = 'x' WHERE authorization_id = $1`,
      `UPDATE authorization_requests SET state = 'PENDING_USER' WHERE authorization_id = $1`,
      `UPDATE authorization_requests SET state = 'OFFLINE_UNSIGNED' WHERE authorization_id = $1`,
    ]) {
      await assert.rejects(q(sql, [phone.id]), /immutable|set once|not a permitted transition|needs a reason/, sql);
    }
    assert.equal((await upload(device, phone.id, phone.signature)).json.status, 'VERIFIED', 'the untouched authorization still completes');
  });

  test('15: a database writer cannot finalize with a signature row it inserted', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    // A forged signature row (a signature over other bytes), written straight to the table.
    await q(`INSERT INTO offline_deferred_signatures (authorization_id, credential_id, signature, signature_format) VALUES ($1, $2, $3, 'der')`,
      [phone.id, device.credentialId, signDer(device.signingKey, Buffer.from('not the authorization'))]);
    const accepted = await submitCode(phone.id, phone.code);
    assert.equal(accepted.json.status, 'PROVISIONAL', `the stored row is re-verified: ${accepted.text}`);
    await assert.rejects(q(`DELETE FROM offline_deferred_signatures WHERE authorization_id = $1`, [phone.id]), /append-only/);
    await assert.rejects(q(`UPDATE offline_deferred_signatures SET signature = 'x' WHERE authorization_id = $1`, [phone.id]), /append-only/);
  });

  test('16: an insider with K (database plus device master key) gets at most PROVISIONAL, never VERIFIED', async () => {
    const device = await newDevice();
    const auth = await bank.createAuthorization(device);
    const { canonical } = await deviceSignature(server, device, auth.authorizationId);
    const row = (await q(`SELECT offline_secret_encrypted FROM credentials WHERE credential_id = $1`, [device.credentialId])).rows[0];
    const [, , ivB64, tagB64, ctB64] = row.offline_secret_encrypted.split('$');
    const d = createDecipheriv('aes-256-gcm', Buffer.from(server.env.DEVICE_SECRET_ENCRYPTION_KEY, 'base64'), Buffer.from(ivB64, 'base64'));
    d.setAAD(Buffer.from(`device:${device.credentialId}`));
    d.setAuthTag(Buffer.from(tagB64, 'base64'));
    const k = Buffer.concat([d.update(Buffer.from(ctB64, 'base64')), d.final()]);
    const tag = createHmac('sha256', k)
      .update(Buffer.concat([Buffer.from('NEXUS-SIGN/OFFLINE-CODE/v1'), Buffer.from([0]), createHash('sha256').update(canonical).digest()])).digest();
    const o = tag[31] & 0x0f;
    const forged = String((((tag[o] & 0x7f) << 24) | (tag[o + 1] << 16) | (tag[o + 2] << 8) | tag[o + 3]) % 1e8).padStart(8, '0');
    const r = await submitCode(auth.authorizationId, forged);
    assert.equal(r.json.status, 'PROVISIONAL', 'the forged code is accepted as a code (residual: the bank is told PROVISIONAL)');
    assert.equal((await stateOf(auth.authorizationId)).state, 'OFFLINE_PROVISIONAL');
    assert.equal(await evidenceCount(auth.authorizationId), 0);
    // Without the device there is no signature; the deadline ends it.
    await passDeadline(auth.authorizationId);
    await waitForState(auth.authorizationId, 'OFFLINE_UNSIGNED');
  });

  test('19: the daily ceiling counts provisional confirmations', async () => {
    const device = await newDevice();
    const results = [];
    for (let i = 0; i < 4; i += 1) {
      const phone = await confirmOnPhone(device);
      results.push((await submitCode(phone.id, phone.code)).json);
    }
    assert.deepEqual(results.map((r) => r.status), ['PROVISIONAL', 'PROVISIONAL', 'PROVISIONAL', 'FAILED']);
    assert.match(results[3].reason, /offline confirmation limit/);

    // In parallel, for six different authorizations: still at most three.
    const parallelDevice = await newDevice();
    const phones = [];
    for (let i = 0; i < 6; i += 1) phones.push(await confirmOnPhone(parallelDevice));
    const parallel = await Promise.all(phones.map((p) => submitCode(p.id, p.code)));
    assert.equal(parallel.filter((r) => r.json?.status === 'PROVISIONAL').length, 3, JSON.stringify(parallel.map((r) => r.json)));
  });

  test('20: --reject-offline-code fails code-only records and accepts OFFLINE_SIGNED ones', async () => {
    const device = await newDevice();
    const phone = await confirmOnPhone(device);
    await submitCode(phone.id, phone.code);
    await upload(device, phone.id, phone.signature);
    const evidence = (await bank.call('GET', `/v1/authorizations/${phone.id}/evidence`)).json;
    const keys = evidence.evidencePublicKeys ?? evidence.evidencePublicKeyPem;
    assert.deepEqual(verifyEvidenceRecord(evidence, keys, { standalone: true, rejectOfflineCode: true }), []);
    const codeOnly = { ...evidence, sealedPayload: { ...evidence.sealedPayload, confirmationMethod: 'OFFLINE_CODE', signatureFormat: 'hmac', signatureAlgorithm: 'HMAC-SHA256' } };
    assert.ok(verifyEvidenceRecord(codeOnly, keys, { rejectOfflineCode: true }).some((p) => /reject-offline-code/.test(p)));
  });
});

describe('offline confirmation v2: restart, v1 deployments, production posture', { skip: skipWithoutServices }, () => {
  test('11: Auth Core killed while an upload waits for the row lock: nothing changes; after restart the retry verifies', async () => {
    const database = await createDatabase();
    let first; let second; let blocker;
    try {
      first = await startAuthCore({ database });
      const client = await first.registerBank('bank-restart');
      const bank = await bankSession(first, client);
      const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
      // An online confirmation, to learn this process's evidence key (the
      // software HSM makes a new one per process).
      const online = await bank.createAuthorization(device);
      const s = await deviceSignature(first, device, online.authorizationId);
      assert.equal((await submitSignature(first, device, online.authorizationId, s.signature)).json.status, 'VERIFIED');
      const evidenceKey = (await bank.call('GET', `/v1/authorizations/${online.authorizationId}/evidence`)).json.evidencePublicKeyPem;

      const auth = await bank.createAuthorization(device);
      const { canonical } = await deviceSignature(first, device, auth.authorizationId);
      const code = offlineCode(device, canonical);
      assert.equal((await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code } })).json.status, 'PROVISIONAL');
      const signature = signDer(device.signingKey, canonical);

      blocker = new pg.Client({ connectionString: database.url });
      await blocker.connect();
      await blocker.query('BEGIN');
      await blocker.query(`SELECT 1 FROM authorization_requests WHERE authorization_id = $1 FOR UPDATE`, [auth.authorizationId]);
      const pending = call(first.baseUrl, 'POST', `/v1/mobile/authorizations/${auth.authorizationId}/deferred-signature`,
        { device, body: { signature, signatureFormat: 'der' } }).catch((error) => ({ error }));
      await sleep(700);
      await first.crash();
      const lost = await pending;
      assert.ok(lost.error || lost.status >= 500, 'the phone got no success, so it keeps the signature');
      await blocker.query('ROLLBACK');
      await blocker.end();
      blocker = null;
      const row = (await database.pool.query(`SELECT state FROM authorization_requests WHERE authorization_id = $1`, [auth.authorizationId])).rows[0];
      assert.equal(row.state, 'OFFLINE_PROVISIONAL', 'nothing committed by the killed process');
      assert.equal((await database.pool.query(`SELECT count(*)::int AS n FROM offline_deferred_signatures WHERE authorization_id = $1`, [auth.authorizationId])).rows[0].n, 0);

      const keys = Object.fromEntries(['DEVICE_SECRET_ENCRYPTION_KEY', 'WEBHOOK_SECRET_ENCRYPTION_KEY', 'ADMIN_SECRET_ENCRYPTION_KEY'].map((k) => [k, first.env[k]]));
      second = await startAuthCore({ database, env: { ...keys, EVIDENCE_RETIRED_PUBLIC_KEYS_PEM: evidenceKey } });
      const retry = await call(second.baseUrl, 'POST', `/v1/mobile/authorizations/${auth.authorizationId}/deferred-signature`,
        { device, body: { signature, signatureFormat: 'der' } });
      assert.equal(retry.status, 200, retry.text);
      assert.equal(retry.json.status, 'VERIFIED');
    } finally {
      if (blocker) { await blocker.query('ROLLBACK').catch(() => {}); await blocker.end().catch(() => {}); }
      await first?.stop();
      await second?.stop();
      await database.drop();
    }
  });

  test('8b: past the deadline, before the sweep ran, a signature is refused', async () => {
    const server = await startAuthCore({ env: { AUTHORIZATION_EXPIRY_SWEEP_MS: '300000' } });
    try {
      const bank = await bankSession(server, await server.registerBank('bank-deadline'));
      const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
      const auth = await bank.createAuthorization(device);
      const { canonical } = await deviceSignature(server, device, auth.authorizationId);
      assert.equal((await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(device, canonical) } })).json.status, 'PROVISIONAL');
      await server.db.query(`ALTER TABLE authorization_requests DISABLE TRIGGER authorization_lifecycle;
        UPDATE authorization_requests SET offline_signature_deadline = now() - interval '1 second' WHERE authorization_id = '${auth.authorizationId}';
        ALTER TABLE authorization_requests ENABLE TRIGGER authorization_lifecycle;`);
      const late = await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${auth.authorizationId}/deferred-signature`,
        { device, body: { signature: signDer(device.signingKey, canonical), signatureFormat: 'der' } });
      assert.equal(late.status, 409, late.text);
      assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}`)).json.state, 'OFFLINE_PROVISIONAL', 'the sweep, not the upload, records OFFLINE_UNSIGNED');
    } finally {
      await server.stop();
    }
  });

  test('17: on a v1 deployment the QR is NXS1., a code verifies at once, and no deferred signature is taken', async () => {
    const server = await startAuthCore({ env: { OFFLINE_CONFIRMATION_MODE: 'immediate' } });
    try {
      const bank = await bankSession(server, await server.registerBank('bank-v1'));
      const device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
      const auth = await bank.createAuthorization(device);
      const challenge = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/offline-challenge`);
      assert.ok(challenge.json.qrPayload.startsWith('NXS1.'));
      const canonical = Buffer.from(challenge.json.qrPayload.slice(5), 'base64url');
      const early = await call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${auth.authorizationId}/deferred-signature`,
        { device, body: { signature: signDer(device.signingKey, canonical), signatureFormat: 'der' } });
      assert.equal(early.status, 409, early.text);
      const r = await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(device, canonical) } });
      assert.equal(r.json.status, 'VERIFIED');
      assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}`)).json.confirmationMethod, 'OFFLINE_CODE');
      const accepted = (await server.db.query(`SELECT offline_code_accepted_at, offline_code_tag FROM authorization_requests WHERE authorization_id = $1`, [auth.authorizationId])).rows[0];
      assert.ok(accepted.offline_code_accepted_at && accepted.offline_code_tag, 'v1 acceptance is recorded too (daily ceiling)');
    } finally {
      await server.stop();
    }
  });

  test('18: production refuses offline confirmation v1', async () => {
    const { code, log } = await startExpectingFailure({ NODE_ENV: 'production', ALLOW_INSECURE_DEVELOPMENT: 'false', OFFLINE_CONFIRMATION_MODE: 'immediate' });
    assert.notEqual(code, 0);
    assert.match(log, /OFFLINE_CONFIRMATION_MODE must be deferred_signature in production/);
  });
});



