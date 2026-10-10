// SoftHSM2 tokens for HSM integration tests. Needs SOFTHSM2_MODULE (path of
// libsofthsm2.so) and SOFTHSM2_UTIL (path of softhsm2-util); without them the
// HSM suites are skipped.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT } from './harness.mjs';

export const SOFTHSM_MODULE = process.env.SOFTHSM2_MODULE;
const SOFTHSM_UTIL = process.env.SOFTHSM2_UTIL;

/** Auth Core signs evidence with CKM_ECDSA_SHA256 (the hash is computed inside
 * the HSM). A production HSM supports it, but some SoftHSM builds (notably the
 * ones packaged with Botan) do not, and then every sign and verify returns
 * CKR_MECHANISM_INVALID. Probe the module once, in a child process, so a build
 * that cannot run these tests skips them cleanly instead of failing. Any error
 * other than a clear "unsupported" leaves the suite enabled. */
function softHsmSupportsEcdsaSha256() {
  const script = `
    const pkcs11js = require('pkcs11js');
    const p = new pkcs11js.PKCS11();
    p.load(process.env.MODULE);
    p.C_Initialize();
    try {
      const slot = p.C_GetSlotList(false)[0];
      if (slot === undefined) { console.log('unknown'); return; }
      try { p.C_GetMechanismInfo(slot, pkcs11js.CKM_ECDSA_SHA256); console.log('yes'); }
      catch (e) { console.log(/MECHANISM_INVALID/.test(String(e)) ? 'no' : 'unknown'); }
    } finally { p.C_Finalize(); }
  `;
  const run = spawnSync(process.execPath, ['-e', script], { cwd: ROOT, env: { ...process.env, MODULE: SOFTHSM_MODULE }, encoding: 'utf8' });
  return run.stdout.trim() !== 'no'; // only a definite "no" disables the suite
}

export const skipWithoutSoftHsm = !(SOFTHSM_MODULE && SOFTHSM_UTIL)
  ? 'SOFTHSM2_MODULE and SOFTHSM2_UTIL are not set'
  : (softHsmSupportsEcdsaSha256() ? false
    : 'this SoftHSM build does not implement CKM_ECDSA_SHA256, which Auth Core uses to sign evidence; build SoftHSM 2.7+ against OpenSSL, or run these tests against a real HSM');

/** One SoftHSM configuration directory; tokens created in it share SOFTHSM2_CONF. */
export function softHsmDirectory() {
  const dir = mkdtempSync(join(tmpdir(), 'nexus-softhsm-'));
  mkdirSync(join(dir, 'tokens'));
  const conf = join(dir, 'softhsm2.conf');
  writeFileSync(conf, `directories.tokendir = ${join(dir, 'tokens')}\nobjectstore.backend = file\nlog.level = ERROR\n`);
  return conf;
}

export function initToken(conf, label, pin = '12345678') {
  execFileSync(SOFTHSM_UTIL, ['--init-token', '--free', '--label', label, '--so-pin', '87654321', '--pin', pin],
    { env: { ...process.env, SOFTHSM2_CONF: conf }, stdio: 'pipe' });
  return { label, pin };
}

/** Generates a P-256 key pair on the token, in a child process so the test
 * process's own PKCS#11 state is not affected. */
export function generateKeyPair(conf, token, { label, id = '01', sensitive = true, extractable = false }) {
  const script = `
    const pkcs11js = require('pkcs11js');
    const p = new pkcs11js.PKCS11();
    p.load(process.env.MODULE);
    p.C_Initialize();
    const slot = p.C_GetSlotList(true).find((s) => p.C_GetTokenInfo(s).label.trim() === process.env.TOKEN);
    const session = p.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    p.C_Login(session, pkcs11js.CKU_USER, process.env.PIN);
    const id = Buffer.from(process.env.KEY_ID, 'hex');
    p.C_GenerateKeyPair(session, { mechanism: pkcs11js.CKM_EC_KEY_PAIR_GEN }, [
      { type: pkcs11js.CKA_TOKEN, value: true }, { type: pkcs11js.CKA_LABEL, value: process.env.LABEL }, { type: pkcs11js.CKA_ID, value: id },
      { type: pkcs11js.CKA_VERIFY, value: true }, { type: pkcs11js.CKA_EC_PARAMS, value: Buffer.from('06082a8648ce3d030107', 'hex') },
    ], [
      { type: pkcs11js.CKA_TOKEN, value: true }, { type: pkcs11js.CKA_LABEL, value: process.env.LABEL }, { type: pkcs11js.CKA_ID, value: id },
      { type: pkcs11js.CKA_SIGN, value: true }, { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SENSITIVE, value: process.env.SENSITIVE === 'true' }, { type: pkcs11js.CKA_EXTRACTABLE, value: process.env.EXTRACTABLE === 'true' },
    ]);
    p.C_Logout(session); p.C_CloseSession(session); p.C_Finalize();
  `;
  const run = spawnSync(process.execPath, ['-e', script], {
    cwd: ROOT,
    env: { ...process.env, SOFTHSM2_CONF: conf, MODULE: SOFTHSM_MODULE, TOKEN: token.label, PIN: token.pin, LABEL: label, KEY_ID: id, SENSITIVE: String(sensitive), EXTRACTABLE: String(extractable) },
    encoding: 'utf8',
  });
  if (run.status !== 0) throw new Error(`key generation failed: ${run.stderr}`);
}
