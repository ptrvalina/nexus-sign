// FI-005, phase 9: could Auth Core stop holding plaintext master keys and
// decrypt stored secrets inside the HSM instead? This suite checks, on
// SoftHSM only, the three facts the design depends on. It changes nothing in
// Auth Core; it records what the PKCS#11 interface allows.
//
//  1. Format: a secret stored by secretBox (`k1$keyId$iv$tag$ct`, AES-256-GCM,
//     associated data `<purpose>:<owner>`) decrypts with C_Decrypt CKM_AES_GCM
//     under an HSM key object holding the same master key, and a wrong
//     associated data is refused by the HSM.
//  2. Migration: whether a wrapped master key (`w1$...`, AES-GCM under the
//     KEK) can be turned into a non-extractable HSM key object without the
//     plaintext leaving the HSM (C_UnwrapKey with CKM_AES_GCM).
//  3. Cost: time per C_Decrypt of a 32-byte secret (SoftHSM; a network HSM
//     adds its round trip).
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { ROOT } from './support/harness.mjs';
import { SOFTHSM_MODULE, initToken, skipWithoutSoftHsm, softHsmDirectory } from './support/softhsm.mjs';

const require = createRequire(`${ROOT}/package.json`);

describe('HSM in-place decryption of stored secrets (SoftHSM capability check)', { skip: skipWithoutSoftHsm }, () => {
  let p; let p11; let session; let kek; const masterKey = randomBytes(32);
  before(() => {
    const conf = softHsmDirectory();
    initToken(conf, 'nexus-cap');
    process.env.SOFTHSM2_CONF = conf;
    p11 = require('pkcs11js');
    p = new p11.PKCS11();
    p.load(SOFTHSM_MODULE);
    p.C_Initialize();
    const slot = p.C_GetSlotList(true).find((s) => p.C_GetTokenInfo(s).label.trim() === 'nexus-cap');
    session = p.C_OpenSession(slot, p11.CKF_SERIAL_SESSION | p11.CKF_RW_SESSION);
    p.C_Login(session, p11.CKU_USER, '12345678');
    kek = p.C_GenerateKey(session, { mechanism: p11.CKM_AES_KEY_GEN }, [
      { type: p11.CKA_CLASS, value: p11.CKO_SECRET_KEY }, { type: p11.CKA_KEY_TYPE, value: p11.CKK_AES }, { type: p11.CKA_VALUE_LEN, value: 32 },
      { type: p11.CKA_TOKEN, value: false }, { type: p11.CKA_SENSITIVE, value: true }, { type: p11.CKA_EXTRACTABLE, value: false },
      { type: p11.CKA_ENCRYPT, value: true }, { type: p11.CKA_DECRYPT, value: true }, { type: p11.CKA_WRAP, value: true }, { type: p11.CKA_UNWRAP, value: true }]);
  });
  after(() => { try { p.C_CloseSession(session); p.C_Finalize(); } catch { /* best effort */ } });

  const gcm = (iv, aad) => ({ mechanism: p11.CKM_AES_GCM, parameter: { type: p11.CK_PARAMS_AES_GCM, iv, aad, tagBits: 128 } });

  /** A stored secret exactly as secretBox writes it. */
  function stored(key, plaintext, aad) {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key, iv); c.setAAD(aad);
    const ct = Buffer.concat([c.update(plaintext), c.final()]);
    const id = createHash('sha256').update(key).digest('hex').slice(0, 16);
    return ['k1', id, iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join('$');
  }

  /** The master key as an HSM object. Test only: imported from a known value
   * (production would need it created without the plaintext, see test 2). */
  function importedMasterKey() {
    return p.C_CreateObject(session, [
      { type: p11.CKA_CLASS, value: p11.CKO_SECRET_KEY }, { type: p11.CKA_KEY_TYPE, value: p11.CKK_AES }, { type: p11.CKA_VALUE, value: masterKey },
      { type: p11.CKA_TOKEN, value: false }, { type: p11.CKA_SENSITIVE, value: true }, { type: p11.CKA_EXTRACTABLE, value: false },
      { type: p11.CKA_DECRYPT, value: true }, { type: p11.CKA_ENCRYPT, value: true }]);
  }

  const hsmOpen = (key, value, aad) => {
    const [, , ivB64, tagB64, ctB64] = value.split('$');
    p.C_DecryptInit(session, gcm(Buffer.from(ivB64, 'base64'), aad), key);
    const input = Buffer.concat([Buffer.from(ctB64, 'base64'), Buffer.from(tagB64, 'base64')]);
    return Buffer.from(p.C_Decrypt(session, input, Buffer.alloc(input.length)));
  };

  test('1. the existing k1 format decrypts inside the HSM; wrong associated data is refused there', () => {
    const key = importedMasterKey();
    const offlineKey = randomBytes(32);
    const value = stored(masterKey, offlineKey, Buffer.from('device:00000000-0000-4000-8000-000000000001'));
    assert.deepEqual(hsmOpen(key, value, Buffer.from('device:00000000-0000-4000-8000-000000000001')), offlineKey);
    assert.throws(() => hsmOpen(key, value, Buffer.from('device:00000000-0000-4000-8000-000000000002')), /CKR_ENCRYPTED_DATA_INVALID|CKR_/);
  });

  test('2. migration path: C_UnwrapKey with CKM_AES_GCM on this SoftHSM build', () => {
    // A wrapped master key as masterKeys.js makes it (AES-GCM under the KEK, AD = name).
    const iv = randomBytes(12); const aad = Buffer.from('nexus-sign/master-key/v1|DEVICE_SECRET_ENCRYPTION_KEY');
    p.C_EncryptInit(session, gcm(iv, aad), kek);
    const wrapped = Buffer.from(p.C_Encrypt(session, masterKey, Buffer.alloc(48)));
    let outcome;
    try {
      p.C_UnwrapKey(session, gcm(iv, aad), kek, wrapped, [
        { type: p11.CKA_CLASS, value: p11.CKO_SECRET_KEY }, { type: p11.CKA_KEY_TYPE, value: p11.CKK_AES },
        { type: p11.CKA_TOKEN, value: false }, { type: p11.CKA_SENSITIVE, value: true }, { type: p11.CKA_EXTRACTABLE, value: false }, { type: p11.CKA_DECRYPT, value: true }]);
      outcome = 'supported';
    } catch (error) {
      outcome = /CKR_[A-Z_]+/.exec(String(error))?.[0] ?? 'error';
    }
    // Recorded, not asserted to a value: the answer is vendor-specific.
    console.log(`# C_UnwrapKey(CKM_AES_GCM) on this SoftHSM: ${outcome}`);
    assert.ok(outcome === 'supported' || /^CKR_/.test(outcome));

    // The alternative mechanism, RFC 5649 key wrap with padding: encrypt the
    // key value with the KEK inside the HSM, then unwrap it into an object.
    let alternative;
    try {
      p.C_EncryptInit(session, { mechanism: p11.CKM_AES_KEY_WRAP_PAD }, kek);
      const kw = Buffer.from(p.C_Encrypt(session, masterKey, Buffer.alloc(48)));
      const object = p.C_UnwrapKey(session, { mechanism: p11.CKM_AES_KEY_WRAP_PAD }, kek, kw, [
        { type: p11.CKA_CLASS, value: p11.CKO_SECRET_KEY }, { type: p11.CKA_KEY_TYPE, value: p11.CKK_AES },
        { type: p11.CKA_TOKEN, value: false }, { type: p11.CKA_SENSITIVE, value: true }, { type: p11.CKA_EXTRACTABLE, value: false }, { type: p11.CKA_DECRYPT, value: true }]);
      const aad2 = Buffer.from('webhook:bank-1');
      const plaintext = randomBytes(32);
      alternative = hsmOpen(object, stored(masterKey, plaintext, aad2), aad2).equals(plaintext) ? 'supported, decrypts k1 secrets' : 'unwrapped, wrong key';
    } catch (error) {
      alternative = /CKR_[A-Z_]+/.exec(String(error))?.[0] ?? 'error';
    }
    console.log(`# CKM_AES_KEY_WRAP_PAD encrypt + C_UnwrapKey on this SoftHSM: ${alternative}`);
  });

  test('3. cost of one in-HSM decryption (SoftHSM, in-process)', () => {
    const key = importedMasterKey();
    const aad = Buffer.from('admin:operator-1');
    const value = stored(masterKey, randomBytes(20), aad);
    const n = 500; const start = process.hrtime.bigint();
    for (let i = 0; i < n; i += 1) hsmOpen(key, value, aad);
    const microseconds = Number(process.hrtime.bigint() - start) / 1000 / n;
    console.log(`# C_DecryptInit+C_Decrypt, 32-byte input: ${microseconds.toFixed(1)} µs per secret on SoftHSM`);
    assert.ok(microseconds > 0);
  });
});
