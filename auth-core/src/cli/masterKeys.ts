import { readFileSync } from 'node:fs';
import { env } from '../config/env';
import { masterKeyId } from '../crypto/secretBox';
import { MASTER_KEY_NAMES, MasterKeyError, openPkcs11Kek, parseWrapped, unwrapMasterKey, wrapMasterKey, type MasterKeyPurpose } from '../crypto/masterKeyVault';

/**
 * HSM-wrapped master keys (FI-005). Prints wrapped keys and key IDs only;
 * never a plaintext key. Uses PKCS11_MODULE_PATH, PKCS11_PIN,
 * PKCS11_TOKEN_LABEL (or PKCS11_SLOT_INDEX) and PKCS11_KEK_LABEL.
 *
 *   node dist/cli/masterKeys.js create-kek [--decrypt-only]
 *       Creates the KEK on the token: AES-256, CKA_TOKEN, CKA_SENSITIVE,
 *       not extractable, CKA_ENCRYPT and CKA_DECRYPT. For SoftHSM and test
 *       tokens; on a production HSM follow the vendor's key ceremony with the
 *       same attributes (KEY_MANAGEMENT.md).
 *   node dist/cli/masterKeys.js generate <webhook|device|admin>
 *       A new random master key (HSM generator XOR local generator), wrapped:
 *       prints <NAME>_WRAPPED=... and its key ID.
 *   node dist/cli/masterKeys.js wrap <webhook|device|admin>  < key.b64
 *       Migration from MASTER_KEY_SOURCE=env: wraps an existing base64 key
 *       read from standard input. Delete the plaintext copy afterwards.
 *   node dist/cli/masterKeys.js rewrap <webhook|device|admin> --to-label=<new KEK>  < wrapped.txt
 *       KEK rotation: unwraps with the KEK named in the value, wraps with
 *       the new KEK. The master key itself does not change.
 *   node dist/cli/masterKeys.js check
 *       Unwraps every configured *_WRAPPED / *_PREVIOUS_WRAPPED value and
 *       prints the key IDs, as Auth Core would at startup.
 */
const PURPOSES = Object.keys(MASTER_KEY_NAMES) as MasterKeyPurpose[];

function purposeOf(value: string | undefined): MasterKeyPurpose {
  if (!value || !PURPOSES.includes(value as MasterKeyPurpose)) throw new MasterKeyError('purpose must be webhook, device or admin');
  return value as MasterKeyPurpose;
}

const stdin = (): string => readFileSync(0, 'utf8').trim();

function createKek(decryptOnly: boolean): void {
  if (!env.PKCS11_MODULE_PATH || !env.PKCS11_PIN || !env.PKCS11_KEK_LABEL) throw new MasterKeyError('needs PKCS11_MODULE_PATH, PKCS11_PIN and PKCS11_KEK_LABEL');
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const Pkcs11js = require('pkcs11js') as typeof import('pkcs11js');
  const p = new Pkcs11js.PKCS11();
  p.load(env.PKCS11_MODULE_PATH);
  p.C_Initialize();
  try {
    const slots = p.C_GetSlotList(true);
    const slot = env.PKCS11_TOKEN_LABEL ? slots.find((s) => p.C_GetTokenInfo(s).label.trim() === env.PKCS11_TOKEN_LABEL) : slots[env.PKCS11_SLOT_INDEX];
    if (!slot) throw new MasterKeyError('the configured PKCS#11 token is not present');
    const session = p.C_OpenSession(slot, Pkcs11js.CKF_SERIAL_SESSION | Pkcs11js.CKF_RW_SESSION);
    p.C_Login(session, Pkcs11js.CKU_USER, env.PKCS11_PIN);
    p.C_FindObjectsInit(session, [{ type: Pkcs11js.CKA_CLASS, value: Pkcs11js.CKO_SECRET_KEY }, { type: Pkcs11js.CKA_LABEL, value: env.PKCS11_KEK_LABEL }]);
    const existing = p.C_FindObjects(session, 1);
    p.C_FindObjectsFinal(session);
    if (existing.length > 0) throw new MasterKeyError(`a key labelled '${env.PKCS11_KEK_LABEL}' already exists; a KEK is never replaced in place`);
    p.C_GenerateKey(session, { mechanism: Pkcs11js.CKM_AES_KEY_GEN }, [
      { type: Pkcs11js.CKA_CLASS, value: Pkcs11js.CKO_SECRET_KEY }, { type: Pkcs11js.CKA_KEY_TYPE, value: Pkcs11js.CKK_AES },
      { type: Pkcs11js.CKA_VALUE_LEN, value: 32 }, { type: Pkcs11js.CKA_TOKEN, value: true }, { type: Pkcs11js.CKA_PRIVATE, value: true },
      { type: Pkcs11js.CKA_LABEL, value: env.PKCS11_KEK_LABEL }, { type: Pkcs11js.CKA_SENSITIVE, value: true },
      { type: Pkcs11js.CKA_EXTRACTABLE, value: false }, { type: Pkcs11js.CKA_ENCRYPT, value: !decryptOnly },
      { type: Pkcs11js.CKA_DECRYPT, value: true }, { type: Pkcs11js.CKA_WRAP, value: false }, { type: Pkcs11js.CKA_UNWRAP, value: false },
    ]);
    p.C_Logout(session);
    p.C_CloseSession(session);
    console.log(`Created KEK '${env.PKCS11_KEK_LABEL}' (AES-256, sensitive, not extractable${decryptOnly ? ', decrypt only' : ''}).`);
  } finally {
    p.C_Finalize();
  }
}

async function main(): Promise<void> {
  const [command, arg, ...rest] = process.argv.slice(2);
  switch (command) {
    case 'create-kek':
      createKek(arg === '--decrypt-only');
      return;
    case 'generate': {
      const purpose = purposeOf(arg);
      const kek = openPkcs11Kek('both');
      try {
        const key = kek.random(32);
        const wrapped = wrapMasterKey(kek, MASTER_KEY_NAMES[purpose], key);
        unwrapMasterKey(kek, MASTER_KEY_NAMES[purpose], wrapped); // round trip before handing it out
        console.log(`${MASTER_KEY_NAMES[purpose]}_WRAPPED=${wrapped}`);
        console.log(`key id: ${masterKeyId(key)}`);
        key.fill(0);
      } finally { kek.close(); }
      return;
    }
    case 'wrap': {
      const purpose = purposeOf(arg);
      const key = Buffer.from(stdin(), 'base64');
      if (key.length !== 32) throw new MasterKeyError('standard input must be a 32-byte key in base64');
      const kek = openPkcs11Kek('both');
      try {
        const wrapped = wrapMasterKey(kek, MASTER_KEY_NAMES[purpose], key);
        unwrapMasterKey(kek, MASTER_KEY_NAMES[purpose], wrapped);
        console.log(`${MASTER_KEY_NAMES[purpose]}_WRAPPED=${wrapped}`);
        console.log(`key id: ${masterKeyId(key)}`);
      } finally { kek.close(); key.fill(0); }
      return;
    }
    case 'rewrap': {
      const purpose = purposeOf(arg);
      const to = rest.find((a) => a.startsWith('--to-label='))?.slice('--to-label='.length);
      if (!to) throw new MasterKeyError('usage: rewrap <purpose> --to-label=<new KEK label>  < wrapped value');
      const name = MASTER_KEY_NAMES[purpose];
      const input = stdin();
      const from = openPkcs11Kek('decrypt', parseWrapped(input, name).label);
      let key: Buffer;
      try { key = unwrapMasterKey(from, name, input); } finally { from.close(); }
      const target = openPkcs11Kek('both', to);
      try {
        const wrapped = wrapMasterKey(target, name, key);
        unwrapMasterKey(target, name, wrapped);
        console.log(`${name}_WRAPPED=${wrapped}`);
        console.log(`key id: ${masterKeyId(key)} (unchanged)`);
      } finally { target.close(); key.fill(0); }
      return;
    }
    case 'check': {
      const kek = openPkcs11Kek('decrypt');
      try {
        for (const purpose of PURPOSES) {
          const name = MASTER_KEY_NAMES[purpose];
          const c = env as Record<string, unknown>;
          const current = c[`${name}_WRAPPED`] as string | undefined;
          if (!current) { console.log(`${name}: not configured`); continue; }
          const ids = [masterKeyId(unwrapMasterKey(kek, name, current))];
          const previous = ((c[`${name}_PREVIOUS_WRAPPED`] as string | undefined) ?? '').split(',').filter((v) => v.trim());
          console.log(`${name}: current ${ids[0]}${previous.length ? `, previous ${previous.map((w) => masterKeyId(unwrapMasterKey(kek, name, w))).join(', ')}` : ''}`);
        }
      } finally { kek.close(); }
      return;
    }
    default:
      throw new MasterKeyError('usage: masterKeys.js create-kek | generate <purpose> | wrap <purpose> | rewrap <purpose> --to-label=<label> | check');
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
