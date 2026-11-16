// PKCS#11 adapter deadline, session pool and evidence key provenance (audit
// findings B-01, B-02), against a
// PKCS#11 module double: the real module runs only in the SoftHSM suite
// (test/integration/hsm.test.mjs). The double signs with a Node P-256 key and
// can stall its synchronous C_SignInit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { loadTs } from './support/load-ts.mjs';

const C = {
  CKF_OS_LOCKING_OK: 2, CKF_SERIAL_SESSION: 4, CKF_RW_SESSION: 2, CKU_USER: 1,
  CKO_PRIVATE_KEY: 3, CKO_PUBLIC_KEY: 2, CKK_EC: 3, CKM_ECDSA_SHA256: 0x1044,
  CKA_CLASS: 0, CKA_LABEL: 3, CKA_ID: 0x102, CKA_KEY_TYPE: 0x100, CKA_SIGN: 0x108, CKA_SENSITIVE: 0x103,
  CKA_EXTRACTABLE: 0x162, CKA_EC_PARAMS: 0x180, CKA_EC_POINT: 0x181, CKA_TOKEN: 1, CKA_VERIFY: 0x10a,
  CKA_LOCAL: 0x163, CKA_NEVER_EXTRACTABLE: 0x164, CKA_ALWAYS_SENSITIVE: 0x165,
};
const busyWait = (ms) => { const end = Date.now() + ms; while (Date.now() < end) { /* a stalled native call */ } };

function moduleDouble({ signInitStallMs = 0, imported = false } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const point = publicKey.export({ type: 'spki', format: 'der' }).subarray(26);
  const calls = { open: 0, login: 0 };
  let findClass; let handles = 0;
  const ulong = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
  return {
    calls,
    load() {}, C_Initialize() {}, C_Finalize() {},
    C_GetSlotList: () => [Buffer.from([1])],
    C_GetTokenInfo: () => ({ label: 'nexus' }),
    C_OpenSession: () => { calls.open += 1; handles += 1; return Buffer.from([handles]); },
    C_Login: () => { calls.login += 1; },
    C_CloseSession() {},
    C_FindObjectsInit: (_s, template) => { findClass = template.find((t) => t.type === C.CKA_CLASS).value; },
    C_FindObjects: () => [Buffer.from([findClass])],
    C_FindObjectsFinal() {},
    C_GetAttributeValue: (_s, _k, template) => template.map(({ type }) => ({ type, value: {
      [C.CKA_KEY_TYPE]: ulong(C.CKK_EC), [C.CKA_SIGN]: Buffer.from([1]), [C.CKA_SENSITIVE]: Buffer.from([1]),
      [C.CKA_EXTRACTABLE]: Buffer.from([0]), [C.CKA_EC_PARAMS]: Buffer.from('06082a8648ce3d030107', 'hex'),
      [C.CKA_EC_POINT]: Buffer.concat([Buffer.from([0x04, 0x41]), point]),
      [C.CKA_LOCAL]: Buffer.from([imported ? 0 : 1]), [C.CKA_NEVER_EXTRACTABLE]: Buffer.from([imported ? 0 : 1]),
      [C.CKA_ALWAYS_SENSITIVE]: Buffer.from([imported ? 0 : 1]),
    }[type] })),
    C_SignInit: () => { if (signInitStallMs) busyWait(signInitStallMs); },
    C_SignAsync: async (_s, data) => sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }),
  };
}

const { Pkcs11HsmAdapter, HsmTimeoutError } = loadTs('crypto/pkcs11HsmAdapter.ts', { stubs: { pkcs11js: { ...C, PKCS11: class {} } } });
const options = (extra = {}) => ({ modulePath: 'x', pin: '1234', tokenLabel: 'nexus', slotIndex: 0, keyLabel: 'evidence', poolSize: 3, operationTimeoutMs: 100, keyVersion: 1, ...extra });

test('the health check fills the session pool, so requests do not open sessions', async () => {
  const module = moduleDouble();
  const hsm = new Pkcs11HsmAdapter(options(), module);
  await hsm.healthCheck();
  assert.equal(module.calls.open, 3);
  await Promise.all(Array.from({ length: 6 }, () => hsm.signEvidence(Buffer.alloc(32, 7))));
  assert.equal(module.calls.open, 3, 'no session opened on the request path');
  await hsm.close();
});

test('a stalled synchronous call counts against the deadline', async () => {
  const module = moduleDouble();
  const hsm = new Pkcs11HsmAdapter(options(), module);
  await hsm.healthCheck();
  module.C_SignInit = () => busyWait(250);
  await assert.rejects(hsm.signEvidence(Buffer.alloc(32, 1)), (error) => error instanceof HsmTimeoutError);
  await hsm.close();
});

test('an evidence key imported into the HSM is refused', async () => {
  const hsm = new Pkcs11HsmAdapter(options(), moduleDouble({ imported: true }));
  await assert.rejects(hsm.healthCheck(), /generated in the HSM \(CKA_LOCAL\)/);
  await hsm.close();
});
