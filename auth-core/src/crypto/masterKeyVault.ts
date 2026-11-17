import { randomBytes } from 'node:crypto';
import { env } from '../config/env';

/**
 * Where the master keys of secretBox.ts come from.
 *
 * MASTER_KEY_SOURCE=env (development default): `<NAME>` and `<NAME>_PREVIOUS`
 * hold the 32-byte keys in base64, as before.
 *
 * MASTER_KEY_SOURCE=hsm (required in production): the configuration holds
 * only wrapped keys, `<NAME>_WRAPPED` and `<NAME>_PREVIOUS_WRAPPED`
 * (comma-separated). A wrapped key is AES-256-GCM ciphertext made inside the
 * HSM with a key-encryption key (KEK) that never leaves it:
 *
 *   w1$<KEK label>$<iv, base64>$<ciphertext || tag, base64>
 *   associated data: "nexus-sign/master-key/v1|<NAME>"
 *
 * At startup Auth Core asks the HSM to decrypt them (C_Decrypt, CKM_AES_GCM)
 * and keeps the master keys only in process memory. A copy of the
 * configuration and the database is then not enough to read stored secrets:
 * the HSM (its PIN and the KEK object) is needed too. The associated data
 * binds each wrapped key to its purpose, so a wrapped webhook key cannot be
 * configured as the device key.
 *
 * What this does not do: the master keys are in the memory of every Auth
 * Core process and of the operator tools that need them. Whoever controls a
 * running process, or holds the PKCS#11 PIN and can reach the HSM, can still
 * use them (docs/engineering/KEY_MANAGEMENT.md).
 */
export type MasterKeyPurpose = 'webhook' | 'device' | 'admin';

export const MASTER_KEY_NAMES = {
  webhook: 'WEBHOOK_SECRET_ENCRYPTION_KEY',
  device: 'DEVICE_SECRET_ENCRYPTION_KEY',
  admin: 'ADMIN_SECRET_ENCRYPTION_KEY',
} as const;

const PURPOSES: MasterKeyPurpose[] = ['webhook', 'device', 'admin'];
const WRAP_FORMAT = 'w1';
const IV_LENGTH = 12;
const TAG_BITS = 128;
const KEY_LENGTH = 32;

export class MasterKeyError extends Error {
  constructor(message: string) { super(message); this.name = 'MasterKeyError'; }
}

export interface MasterKeyMaterial { current: Buffer; previous: Buffer[] }

/** The key-encryption key: an AES-256 secret key object in the HSM. */
export interface KeyEncryptionKey {
  readonly label: string;
  encrypt(plaintext: Buffer, aad: Buffer, iv: Buffer): Buffer;
  decrypt(ciphertext: Buffer, aad: Buffer, iv: Buffer): Buffer;
  random(length: number): Buffer;
  close(): void;
}

export const associatedDataFor = (name: string): Buffer => Buffer.from(`nexus-sign/master-key/v1|${name}`, 'utf8');

export function formatWrapped(label: string, iv: Buffer, ciphertext: Buffer): string {
  return [WRAP_FORMAT, label, iv.toString('base64'), ciphertext.toString('base64')].join('$');
}

export function parseWrapped(value: string, name: string): { label: string; iv: Buffer; ciphertext: Buffer } {
  const parts = value.trim().split('$');
  if (parts.length !== 4 || parts[0] !== WRAP_FORMAT || !parts[1]) throw new MasterKeyError(`${name}: not a wrapped master key (expected ${WRAP_FORMAT}$<KEK label>$<iv>$<ciphertext>)`);
  const iv = Buffer.from(parts[2], 'base64');
  const ciphertext = Buffer.from(parts[3], 'base64');
  if (iv.length !== IV_LENGTH || ciphertext.length !== KEY_LENGTH + TAG_BITS / 8) throw new MasterKeyError(`${name}: wrapped master key has the wrong length`);
  return { label: parts[1], iv, ciphertext };
}

/** Wraps a 32-byte master key with the KEK. */
export function wrapMasterKey(kek: KeyEncryptionKey, name: string, key: Buffer): string {
  if (key.length !== KEY_LENGTH) throw new MasterKeyError(`${name}: a master key is 32 bytes`);
  const iv = kek.random(IV_LENGTH);
  return formatWrapped(kek.label, iv, kek.encrypt(key, associatedDataFor(name), iv));
}

export function unwrapMasterKey(kek: KeyEncryptionKey, name: string, wrapped: string): Buffer {
  const { label, iv, ciphertext } = parseWrapped(wrapped, name);
  if (label !== kek.label) throw new MasterKeyError(`${name}: wrapped with KEK '${label}', but the configured KEK is '${kek.label}'`);
  let key: Buffer;
  try {
    key = kek.decrypt(ciphertext, associatedDataFor(name), iv);
  } catch (error) {
    // The PKCS#11 return code only (e.g. CKR_ENCRYPTED_DATA_INVALID): never
    // the input, which would help nobody and is not needed for diagnosis.
    const code = /CKR_[A-Z_]+/.exec(error instanceof Error ? error.message : String(error))?.[0] ?? 'decryption failed';
    throw new MasterKeyError(`${name}: the HSM could not unwrap it (${code}): wrong KEK, wrong key name, or a damaged value`);
  }
  if (key.length !== KEY_LENGTH) throw new MasterKeyError(`${name}: unwrapped key is not 32 bytes`);
  return key;
}

let loaded: Map<MasterKeyPurpose, MasterKeyMaterial> | null = null;

const listOf = (value: string | undefined): string[] => (value ?? '').split(',').map((v) => v.trim()).filter(Boolean);

function envMaterial(purpose: MasterKeyPurpose): MasterKeyMaterial | null {
  const name = MASTER_KEY_NAMES[purpose];
  const raw = (env as Record<string, unknown>)[name];
  if (typeof raw !== 'string' || raw === '') return null;
  const decode = (label: string, value: string) => {
    const key = Buffer.from(value.trim(), 'base64');
    if (key.length !== KEY_LENGTH) throw new Error(`${label} must decode to exactly 32 bytes`);
    return key;
  };
  return {
    current: decode(name, raw),
    previous: listOf((env as Record<string, unknown>)[`${name}_PREVIOUS`] as string | undefined).map((v) => decode(`${name}_PREVIOUS`, v)),
  };
}

/**
 * Loads the master keys once per process. With MASTER_KEY_SOURCE=hsm this
 * unwraps every configured key in the HSM and fails, without starting, if
 * any of them cannot be unwrapped. `kekFactory` is for tests.
 */
export async function loadMasterKeys(kekFactory: () => KeyEncryptionKey = openPkcs11Kek): Promise<void> {
  if (env.MASTER_KEY_SOURCE !== 'hsm') { loaded = null; return; }
  const kek = kekFactory();
  try {
    const material = new Map<MasterKeyPurpose, MasterKeyMaterial>();
    for (const purpose of PURPOSES) {
      const name = MASTER_KEY_NAMES[purpose];
      const wrapped = (env as Record<string, unknown>)[`${name}_WRAPPED`] as string | undefined;
      if (!wrapped) continue;
      material.set(purpose, {
        current: unwrapMasterKey(kek, name, wrapped),
        previous: listOf((env as Record<string, unknown>)[`${name}_PREVIOUS_WRAPPED`] as string | undefined).map((w) => unwrapMasterKey(kek, name, w)),
      });
    }
    loaded = material;
  } finally {
    kek.close();
  }
}

/** The master keys of a purpose, or null when none is configured. */
export function masterKeyMaterial(purpose: MasterKeyPurpose): MasterKeyMaterial | null {
  if (env.MASTER_KEY_SOURCE === 'hsm') {
    if (!loaded) throw new MasterKeyError('Master keys are not loaded: MASTER_KEY_SOURCE=hsm needs loadMasterKeys() at startup');
    return loaded.get(purpose) ?? null;
  }
  return envMaterial(purpose);
}

// --- PKCS#11 key-encryption key ----------------------------------------

/**
 * Opens the KEK named by PKCS11_KEK_LABEL on the token of PKCS11_TOKEN_LABEL
 * (or PKCS11_SLOT_INDEX), logged in with PKCS11_PIN. The KEK must be an
 * AES secret key with CKA_SENSITIVE true and CKA_EXTRACTABLE false, and
 * with CKA_NEVER_EXTRACTABLE and CKA_LOCAL true: generated in the HSM and never
 * exportable, so no copy of its value can exist outside (an AES key imported
 * from a known value would satisfy the first two checks). `need` names the
 * operation the caller will perform, and the key must allow it.
 */
export function openPkcs11Kek(need: 'decrypt' | 'encrypt' | 'both' = 'decrypt', labelOverride?: string): KeyEncryptionKey {
  if (!env.PKCS11_MODULE_PATH || !env.PKCS11_PIN) throw new MasterKeyError('MASTER_KEY_SOURCE=hsm needs PKCS11_MODULE_PATH and PKCS11_PIN');
  const label = labelOverride ?? env.PKCS11_KEK_LABEL;
  if (!label) throw new MasterKeyError('MASTER_KEY_SOURCE=hsm needs PKCS11_KEK_LABEL');
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const Pkcs11js = require('pkcs11js') as typeof import('pkcs11js');
  const p = new Pkcs11js.PKCS11();
  p.load(env.PKCS11_MODULE_PATH);
  try { p.C_Initialize({ flags: Pkcs11js.CKF_OS_LOCKING_OK }); } catch (error) {
    if (!/CKR_CRYPTOKI_ALREADY_INITIALIZED/.test(String(error))) throw new MasterKeyError(`HSM not available: ${/CKR_[A-Z_]+/.exec(String(error))?.[0] ?? 'C_Initialize failed'}`);
  }
  const slots = p.C_GetSlotList(true);
  const slot = env.PKCS11_TOKEN_LABEL
    ? slots.find((s) => p.C_GetTokenInfo(s).label.trim() === env.PKCS11_TOKEN_LABEL)
    : slots[env.PKCS11_SLOT_INDEX];
  if (!slot) throw new MasterKeyError('HSM not available: the configured PKCS#11 token is not present');
  const session = p.C_OpenSession(slot, Pkcs11js.CKF_SERIAL_SESSION);
  const fail = (message: string): never => {
    try { p.C_CloseSession(session); } catch { /* best effort */ }
    throw new MasterKeyError(message);
  };
  try {
    p.C_Login(session, Pkcs11js.CKU_USER, env.PKCS11_PIN);
  } catch (error) {
    if (!/CKR_USER_ALREADY_LOGGED_IN/.test(String(error))) fail(`HSM login refused (${/CKR_[A-Z_]+/.exec(String(error))?.[0] ?? 'C_Login failed'})`);
  }
  p.C_FindObjectsInit(session, [
    { type: Pkcs11js.CKA_CLASS, value: Pkcs11js.CKO_SECRET_KEY },
    { type: Pkcs11js.CKA_LABEL, value: label },
  ]);
  const handles = p.C_FindObjects(session, 2);
  p.C_FindObjectsFinal(session);
  if (handles.length !== 1) fail(handles.length === 0 ? `No KEK labelled '${label}' on the token` : `More than one key is labelled '${label}'`);
  const key = handles[0];
  const attributes = p.C_GetAttributeValue(session, key, [
    { type: Pkcs11js.CKA_KEY_TYPE }, { type: Pkcs11js.CKA_SENSITIVE }, { type: Pkcs11js.CKA_EXTRACTABLE },
    { type: Pkcs11js.CKA_ENCRYPT }, { type: Pkcs11js.CKA_DECRYPT }, { type: Pkcs11js.CKA_VALUE_LEN },
    { type: Pkcs11js.CKA_NEVER_EXTRACTABLE }, { type: Pkcs11js.CKA_LOCAL },
  ]);
  const flag = (i: number) => Buffer.isBuffer(attributes[i].value) && (attributes[i].value as Buffer)[0] === 1;
  // CK_ULONG: 8 bytes on 64-bit platforms, 4 on 32-bit ones, little-endian.
  const ulong = (i: number) => { const b = attributes[i].value as Buffer; return b.length >= 8 ? Number(b.readBigUInt64LE(0)) : b.readUInt32LE(0); };
  const keyType = ulong(0);
  const length = ulong(5);
  if (keyType !== Pkcs11js.CKK_AES || length !== 32) fail(`KEK '${label}' must be an AES-256 key`);
  if (!flag(1)) fail(`KEK '${label}' must be sensitive (CKA_SENSITIVE)`);
  if (flag(2)) fail(`KEK '${label}' must not be extractable (CKA_EXTRACTABLE)`);
  if (!flag(6) || !flag(7)) fail(`KEK '${label}' must have been generated in the HSM and never been extractable (CKA_LOCAL, CKA_NEVER_EXTRACTABLE)`);
  if ((need === 'decrypt' || need === 'both') && !flag(4)) fail(`KEK '${label}' does not allow decryption (CKA_DECRYPT): this process may not unwrap master keys`);
  if ((need === 'encrypt' || need === 'both') && !flag(3)) fail(`KEK '${label}' does not allow encryption (CKA_ENCRYPT): this process may not wrap master keys`);

  const mechanism = (iv: Buffer, aad: Buffer) => ({ mechanism: Pkcs11js.CKM_AES_GCM, parameter: { type: Pkcs11js.CK_PARAMS_AES_GCM, iv, aad, tagBits: TAG_BITS } });
  return {
    label,
    encrypt(plaintext, aad, iv) {
      p.C_EncryptInit(session, mechanism(iv, aad), key);
      return Buffer.from(p.C_Encrypt(session, plaintext, Buffer.alloc(plaintext.length + TAG_BITS / 8)));
    },
    decrypt(ciphertext, aad, iv) {
      p.C_DecryptInit(session, mechanism(iv, aad), key);
      return Buffer.from(p.C_Decrypt(session, ciphertext, Buffer.alloc(ciphertext.length)));
    },
    random(length) {
      // The HSM's generator; Node's as well, so neither alone decides.
      const fromHsm = Buffer.from(p.C_GenerateRandom(session, Buffer.alloc(length)));
      const local = randomBytes(length);
      return Buffer.from(fromHsm.map((b, i) => b ^ local[i]));
    },
    close() {
      try { p.C_CloseSession(session); } catch { /* best effort */ }
    },
  };
}
