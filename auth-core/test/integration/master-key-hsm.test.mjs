// Master keys wrapped by an HSM key-encryption key (SoftHSM2).
// The configuration holds no plaintext master key; Auth Core unwraps them in
// the HSM at startup and refuses to start when it cannot. Covers a KEK
// rotation, a master key rotation interrupted by restarts, and the failure
// modes: HSM unavailable, wrong PIN, unknown KEK, a KEK that may not
// decrypt, a wrapped key configured for another purpose.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createDecipheriv, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { ROOT, createDatabase, processEnvironment, skipWithoutServices, startAuthCore, startExpectingFailure } from './support/harness.mjs';
import { SOFTHSM_MODULE, generateKeyPair, initToken, skipWithoutSoftHsm, softHsmDirectory } from './support/softhsm.mjs';
import { adminSession, bankSession, deviceSignature, offlineCode } from './support/actors.mjs';

const skip = skipWithoutServices || skipWithoutSoftHsm;
const NAMES = { webhook: 'WEBHOOK_SECRET_ENCRYPTION_KEY', device: 'DEVICE_SECRET_ENCRYPTION_KEY', admin: 'ADMIN_SECRET_ENCRYPTION_KEY' };

describe('HSM-wrapped master keys', { skip }, () => {
  let conf; let database; let hsmEnv; let client; let device; const admins = [];
  const deviceKeys = {}; // purpose -> wrapped value, and the plaintext of the device key (known only to this test)
  let deviceKeyPlain;

  const cli = (script, args, extra = {}, input) => {
    // The key tools need no database; the configuration still requires the URLs.
    const placeholders = { DATABASE_URL: 'postgres://unused@127.0.0.1:1/x', REDIS_URL: 'redis://127.0.0.1:1' };
    const run = spawnSync(process.execPath, [join(ROOT, 'dist/cli', script), ...args], { cwd: ROOT, env: { ...processEnvironment(), ...placeholders, ...hsmEnv, ...extra }, input, encoding: 'utf8' });
    return { code: run.status, out: run.stdout + run.stderr };
  };
  const wrappedFrom = (out, name) => new RegExp(`${name}_WRAPPED=(\\S+)`).exec(out)?.[1];

  const serverEnv = (keys, extra = {}) => ({
    ...hsmEnv,
    DEVICE_SECRET_ENCRYPTION_KEY: undefined, WEBHOOK_SECRET_ENCRYPTION_KEY: undefined, ADMIN_SECRET_ENCRYPTION_KEY: undefined,
    ...Object.fromEntries(Object.entries(keys).map(([k, v]) => [k, v])),
    ...extra,
  });

  async function confirmOffline(server, who = device) {
    const bank = await bankSession(server, client);
    const auth = await bank.createAuthorization(who);
    const { canonical } = await deviceSignature(server, who, auth.authorizationId);
    return (await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { body: { code: offlineCode(who, canonical) } })).json;
  }

  before(async () => {
    conf = softHsmDirectory();
    const token = initToken(conf, 'nexus-main');
    generateKeyPair(conf, token, { label: 'nexus-evidence' });
    hsmEnv = {
      // Accepted codes show that the offline key decrypts; v1 reads VERIFIED.
      OFFLINE_CONFIRMATION_MODE: 'immediate',
      SOFTHSM2_CONF: conf, HSM_ADAPTER: 'pkcs11', PKCS11_MODULE_PATH: SOFTHSM_MODULE, PKCS11_PIN: '12345678',
      PKCS11_TOKEN_LABEL: 'nexus-main', PKCS11_EVIDENCE_KEY_LABEL: 'nexus-evidence', PKCS11_KEK_LABEL: 'nexus-master-kek',
      MASTER_KEY_SOURCE: 'hsm', NODE_ENV: 'development', ALLOW_INSECURE_DEVELOPMENT: 'true',
    };
    const created = cli('masterKeys.js', ['create-kek']);
    assert.equal(created.code, 0, created.out);
    assert.equal(cli('masterKeys.js', ['create-kek']).code, 1, 'a KEK is never replaced in place');
    for (const purpose of ['webhook', 'admin']) {
      const g = cli('masterKeys.js', ['generate', purpose]);
      assert.equal(g.code, 0, g.out);
      deviceKeys[NAMES[purpose]] = wrappedFrom(g.out, NAMES[purpose]);
    }
    // The device key is wrapped from a known value, so the test can check that
    // it never appears in logs and that the database cannot be read without it.
    deviceKeyPlain = randomBytes(32);
    const w = cli('masterKeys.js', ['wrap', 'device'], {}, deviceKeyPlain.toString('base64'));
    assert.equal(w.code, 0, w.out);
    assert.doesNotMatch(w.out, new RegExp(deviceKeyPlain.toString('base64').replace(/[+/=]/g, '.')), 'wrap prints no plaintext');
    deviceKeys[NAMES.device] = wrappedFrom(w.out, NAMES.device);
    database = await createDatabase();
  });
  after(async () => { await database?.drop(); });

  const wrappedKeys = () => Object.fromEntries(Object.entries(deviceKeys).map(([name, v]) => [`${name}_WRAPPED`, v]));

  test('with wrapped keys only, the service runs offline confirmation, TOTP login and webhook secrets', async () => {
    const server = await startAuthCore({ database, env: serverEnv(wrappedKeys()) });
    try {
      for (const name of Object.values(NAMES)) assert.equal(server.env[name], undefined, `${name} is not in the configuration`);
      client = await server.registerBank('bank-kek', { webhookUrl: 'https://bank.example/hooks' });
      const bank = await bankSession(server, client);
      device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
      for (const n of ['kek-admin-1', 'kek-admin-2', 'kek-admin-3', 'kek-admin-4']) admins.push(await server.createAdmin(n, 'auditor'));
      assert.equal((await confirmOffline(server)).status, 'VERIFIED');
      assert.equal((await adminSession(server, admins[0])).login.status, 200);
      const keyB64 = deviceKeyPlain.toString('base64');
      assert.ok(!server.logs().includes(keyB64) && !server.logs().includes(deviceKeyPlain.toString('hex')), 'no key material in the log');
    } finally { await server.stop(); }
  });

  test('a copy of the database and the configuration does not open stored secrets', async () => {
    const pool = database.pool;
    const stored = (await pool.query(`SELECT offline_secret_encrypted FROM credentials WHERE credential_id = $1`, [device.credentialId])).rows[0].offline_secret_encrypted;
    const [, , ivB64, tagB64, ctB64] = stored.split('$');
    const tryKey = (key) => {
      try {
        const d = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
        d.setAAD(Buffer.from(`device:${device.credentialId}`)); d.setAuthTag(Buffer.from(tagB64, 'base64'));
        Buffer.concat([d.update(Buffer.from(ctB64, 'base64')), d.final()]);
        return true;
      } catch { return false; }
    };
    // Every value in the configuration, read as a key candidate, fails.
    const config = serverEnv(wrappedKeys());
    for (const value of Object.values(config).filter((v) => typeof v === 'string')) {
      for (const candidate of [Buffer.from(value, 'base64'), Buffer.from(value)]) {
        if (candidate.length === 32) assert.equal(tryKey(candidate), false);
      }
      for (const part of value.split('$')) {
        const b = Buffer.from(part, 'base64');
        if (b.length >= 32) assert.equal(tryKey(b.subarray(0, 32)), false);
      }
    }
    assert.equal(tryKey(deviceKeyPlain), true, 'only the unwrapped key opens it (control)');
  });

  test('master key rotation interrupted by restarts, then completed; afterwards the old key alone fails', async () => {
    const g = cli('masterKeys.js', ['generate', 'device']);
    const newDevice = wrappedFrom(g.out, NAMES.device);
    const oldDevice = deviceKeys[NAMES.device];
    const rotating = { ...wrappedKeys(), [`${NAMES.device}_WRAPPED`]: newDevice, [`${NAMES.device}_PREVIOUS_WRAPPED`]: deviceKeys[NAMES.device] };
    let second;
    let server = await startAuthCore({ database, env: serverEnv(rotating) });
    try {
      const bank = await bankSession(server, client);
      second = await bank.enrolDevice((await bank.createIdentity()).nexusId); // written under the new key
      assert.equal((await confirmOffline(server)).status, 'VERIFIED', 'old secret under the previous key');
    } finally { await server.stop(); }
    // Restart in the middle of the rotation, before the tool ran.
    server = await startAuthCore({ database, env: serverEnv(rotating) });
    try {
      assert.equal((await confirmOffline(server, second)).status, 'VERIFIED');
      assert.equal((await confirmOffline(server)).status, 'VERIFIED');
      const rotated = cli('rotateSecretKeys.js', ['device'], { ...serverEnv(rotating), DATABASE_URL: database.url, REDIS_URL: server.env.REDIS_URL });
      assert.equal(rotated.code, 0, rotated.out);
      assert.match(rotated.out, /credentials\.offline_secret_encrypted: 2 stored, 1 already under the current key, 1 re-encrypted/);
    } finally { await server.stop(); }
    deviceKeys[NAMES.device] = newDevice;
    server = await startAuthCore({ database, env: serverEnv(wrappedKeys()) });
    try {
      assert.equal((await confirmOffline(server)).status, 'VERIFIED', 'previous key no longer needed');
      assert.equal((await confirmOffline(server, second)).status, 'VERIFIED');
    } finally { await server.stop(); }
    const stale = await startAuthCore({ database, env: serverEnv({ ...wrappedKeys(), [`${NAMES.device}_WRAPPED`]: oldDevice }) });
    try {
      assert.notEqual((await confirmOffline(stale)).status, 'VERIFIED', 'the old key alone cannot open re-encrypted secrets');
    } finally { await stale.stop(); }
  });

  test('KEK rotation re-wraps the master keys; their key IDs and the stored data stay the same', async () => {
    const created = cli('masterKeys.js', ['create-kek'], { PKCS11_KEK_LABEL: 'nexus-master-kek-2' });
    assert.equal(created.code, 0, created.out);
    const before = cli('masterKeys.js', ['check'], wrappedKeys());
    assert.equal(before.code, 0, before.out);
    const rewrapped = {};
    for (const [purpose, name] of Object.entries(NAMES)) {
      const r = cli('masterKeys.js', ['rewrap', purpose, '--to-label=nexus-master-kek-2'], {}, deviceKeys[name]);
      assert.equal(r.code, 0, r.out);
      rewrapped[`${name}_WRAPPED`] = wrappedFrom(r.out, name);
      assert.match(rewrapped[`${name}_WRAPPED`], /^w1\$nexus-master-kek-2\$/);
    }
    const after2 = cli('masterKeys.js', ['check'], { ...rewrapped, PKCS11_KEK_LABEL: 'nexus-master-kek-2' });
    assert.equal(after2.code, 0, after2.out);
    assert.equal(after2.out, before.out, 'same key IDs under the new KEK');
    assert.doesNotMatch(after2.out, /[A-Za-z0-9+/]{43}=/, 'check prints no key material');
    const server = await startAuthCore({ database, env: serverEnv(rewrapped, { PKCS11_KEK_LABEL: 'nexus-master-kek-2' }) });
    try {
      assert.equal((await confirmOffline(server)).status, 'VERIFIED');
      assert.equal((await adminSession(server, admins[1])).login.status, 200);
    } finally { await server.stop(); }
  });

  for (const [what, extra, pattern] of [
    ['the PKCS#11 module is missing (HSM unavailable)', { PKCS11_MODULE_PATH: '/nonexistent/libsofthsm2.so' }, /nonexistent|cannot open|ENOENT|load/i],
    ['the PIN is wrong', { PKCS11_PIN: '00000000' }, /HSM login refused \(CKR_PIN_INCORRECT\)/],
    ['the KEK does not exist', { PKCS11_KEK_LABEL: 'no-such-kek' }, /No KEK labelled 'no-such-kek'|wrapped with KEK/],
  ]) {
    test(`startup is refused when ${what}, and the log carries no key material`, async () => {
      const { code, log } = await startExpectingFailure(serverEnv(wrappedKeys(), extra), { database });
      assert.notEqual(code, 'still-running');
      assert.notEqual(code, 0);
      assert.match(log, pattern);
      assert.ok(!log.includes(deviceKeyPlain.toString('base64')));
    });
  }

  test('a wrapped key configured for another purpose does not unwrap', async () => {
    const swapped = { ...wrappedKeys(), [`${NAMES.device}_WRAPPED`]: deviceKeys[NAMES.webhook] };
    const { code, log } = await startExpectingFailure(serverEnv(swapped), { database });
    assert.notEqual(code, 0);
    assert.match(log, /DEVICE_SECRET_ENCRYPTION_KEY: the HSM could not unwrap it \(CKR_[A-Z_]+\)/);
  });

  test('a KEK that may not decrypt cannot be used by the service', async () => {
    // An encrypt-only key, as a token for a key-generation role might hold.
    const script = `
      const p11 = require('pkcs11js'); const p = new p11.PKCS11(); p.load(process.env.M); p.C_Initialize();
      const slot = p.C_GetSlotList(true).find((s) => p.C_GetTokenInfo(s).label.trim() === 'nexus-main');
      const s = p.C_OpenSession(slot, p11.CKF_SERIAL_SESSION | p11.CKF_RW_SESSION); p.C_Login(s, p11.CKU_USER, '12345678');
      p.C_GenerateKey(s, { mechanism: p11.CKM_AES_KEY_GEN }, [
        { type: p11.CKA_CLASS, value: p11.CKO_SECRET_KEY }, { type: p11.CKA_KEY_TYPE, value: p11.CKK_AES }, { type: p11.CKA_VALUE_LEN, value: 32 },
        { type: p11.CKA_TOKEN, value: true }, { type: p11.CKA_LABEL, value: 'encrypt-only-kek' }, { type: p11.CKA_SENSITIVE, value: true },
        { type: p11.CKA_EXTRACTABLE, value: false }, { type: p11.CKA_ENCRYPT, value: true }, { type: p11.CKA_DECRYPT, value: false }]);
      p.C_Finalize();`;
    execFileSync(process.execPath, ['-e', script], { cwd: ROOT, env: { ...process.env, SOFTHSM2_CONF: conf, M: SOFTHSM_MODULE } });
    const { code, log } = await startExpectingFailure(serverEnv(wrappedKeys(), { PKCS11_KEK_LABEL: 'encrypt-only-kek' }), { database });
    assert.notEqual(code, 0);
    assert.match(log, /does not allow decryption \(CKA_DECRYPT\)/);
  });

  test('a KEK imported from a known value (not generated in the HSM) is refused', async () => {
    // Sensitive and not extractable now, but its value existed outside the HSM.
    const script = `
      const p11 = require('pkcs11js'); const p = new p11.PKCS11(); p.load(process.env.M); p.C_Initialize();
      const slot = p.C_GetSlotList(true).find((s) => p.C_GetTokenInfo(s).label.trim() === 'nexus-main');
      const s = p.C_OpenSession(slot, p11.CKF_SERIAL_SESSION | p11.CKF_RW_SESSION); p.C_Login(s, p11.CKU_USER, '12345678');
      p.C_CreateObject(s, [
        { type: p11.CKA_CLASS, value: p11.CKO_SECRET_KEY }, { type: p11.CKA_KEY_TYPE, value: p11.CKK_AES }, { type: p11.CKA_VALUE, value: Buffer.alloc(32, 7) },
        { type: p11.CKA_TOKEN, value: true }, { type: p11.CKA_LABEL, value: 'imported-kek' }, { type: p11.CKA_SENSITIVE, value: true },
        { type: p11.CKA_EXTRACTABLE, value: false }, { type: p11.CKA_ENCRYPT, value: true }, { type: p11.CKA_DECRYPT, value: true }]);
      p.C_Finalize();`;
    execFileSync(process.execPath, ['-e', script], { cwd: ROOT, env: { ...process.env, SOFTHSM2_CONF: conf, M: SOFTHSM_MODULE } });
    const { code, log } = await startExpectingFailure(serverEnv(wrappedKeys(), { PKCS11_KEK_LABEL: 'imported-kek' }), { database });
    assert.notEqual(code, 0);
    assert.match(log, /must have been generated in the HSM and never been extractable/);
  });

  test('plaintext keys next to MASTER_KEY_SOURCE=hsm are refused', async () => {
    const { code, log } = await startExpectingFailure(serverEnv(wrappedKeys(), { DEVICE_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64') }), { database });
    assert.notEqual(code, 0);
    assert.match(log, /must not be set in plaintext with MASTER_KEY_SOURCE=hsm/);
  });
});
