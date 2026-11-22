// Creates the sandbox's evidence key pair (ECDSA P-256) on the SoftHSM token,
// private key sensitive and not extractable, as Auth Core's HSM tests do
// (auth-core/test/integration/support/softhsm.mjs). Runs once, at the first
// start of the sandbox. SoftHSM is the sandbox's TEST HSM, not a production HSM.
const pkcs11js = require('/app/node_modules/pkcs11js');

const { PKCS11_MODULE_PATH: module, PKCS11_PIN: pin, PKCS11_TOKEN_LABEL: tokenLabel, PKCS11_EVIDENCE_KEY_LABEL: label } = process.env;
const p = new pkcs11js.PKCS11();
p.load(module);
p.C_Initialize();
try {
  const slot = p.C_GetSlotList(true).find((s) => p.C_GetTokenInfo(s).label.trim() === tokenLabel);
  if (slot === undefined) throw new Error(`token ${tokenLabel} not found`);
  const session = p.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
  p.C_Login(session, pkcs11js.CKU_USER, pin);
  const id = Buffer.from('01', 'hex');
  p.C_GenerateKeyPair(session, { mechanism: pkcs11js.CKM_EC_KEY_PAIR_GEN }, [
    { type: pkcs11js.CKA_TOKEN, value: true }, { type: pkcs11js.CKA_LABEL, value: label }, { type: pkcs11js.CKA_ID, value: id },
    { type: pkcs11js.CKA_VERIFY, value: true }, { type: pkcs11js.CKA_EC_PARAMS, value: Buffer.from('06082a8648ce3d030107', 'hex') },
  ], [
    { type: pkcs11js.CKA_TOKEN, value: true }, { type: pkcs11js.CKA_LABEL, value: label }, { type: pkcs11js.CKA_ID, value: id },
    { type: pkcs11js.CKA_SIGN, value: true }, { type: pkcs11js.CKA_PRIVATE, value: true },
    { type: pkcs11js.CKA_SENSITIVE, value: true }, { type: pkcs11js.CKA_EXTRACTABLE, value: false },
  ]);
  p.C_Logout(session);
  p.C_CloseSession(session);
  console.log(`evidence key "${label}" created on SoftHSM token "${tokenLabel}"`);
} finally {
  p.C_Finalize();
}
