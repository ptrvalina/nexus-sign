import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import Pkcs11js from 'pkcs11js';
import type { EvidenceSeal, HsmAdapter } from './hsmAdapter';
import { parseP256PublicKey } from './p256PublicKey';
import { derToRaw, rawToDer } from './ecdsaSignatureFormat';
import { env } from '../config/env';
import { HsmTimeoutError } from './hsmErrors';

/**
 * HSM adapter over PKCS#11 (pkcs11js). Tested with SoftHSM2
 * (test/integration/hsm.test.mjs); production modules are selected with
 * PKCS11_MODULE_PATH and need no code changes.
 *
 * Security properties:
 * - The evidence key is selected by token label, key label and optionally
 *   CKA_ID, and must be unique: two matching keys are an error, never a
 *   choice. The private key must be a P-256 signing key, sensitive and
 *   non-extractable, generated in the HSM and never extractable or
 *   non-sensitive (CKA_LOCAL, CKA_NEVER_EXTRACTABLE, CKA_ALWAYS_SENSITIVE); the public key with the same label and ID must belong to it
 *   (checked by the self-test).
 * - Sign and verify run on a pool of logged-in sessions. C_SignAsync and
 *   C_VerifyAsync run on libuv worker threads; every operation has a deadline
 *   (HSM_OPERATION_TIMEOUT_MS) that starts before its first PKCS#11 call. A
 *   session whose operation timed out is never reused; it is closed once the
 *   call returns.
 * - pkcs11js has no asynchronous form of C_OpenSession, C_Login,
 *   C_FindObjects*, C_GetAttributeValue, C_SignInit, C_VerifyInit,
 *   C_CreateObject or C_DestroyObject. In the service this adapter runs in a
 *   worker thread (pkcs11Worker.ts, hsmWorkerHost.ts), so a stall in one of
 *   them blocks that thread, not the event loop; the host bounds every call.
 *   healthCheck() fills the pool, so requests open a session only after one
 *   was retired.
 * - A lost session (HSM restart, failover) is discarded and the operation is
 *   retried once on a new session; a module that lost its initialisation is
 *   finalised and initialised again. Nothing falls back to software keys.
 *
 * CKM_ECDSA_SHA256 works on raw r || s signatures, so DER signatures are
 * converted (ecdsaSignatureFormat.ts).
 */
export interface Pkcs11Options {
  modulePath: string;
  pin: string;
  /** Token label (CKA_LABEL of the token). Preferred over slotIndex, whose
   * meaning can change when tokens are added or the HSM restarts. */
  tokenLabel?: string;
  slotIndex: number;
  keyLabel: string;
  /** Hex CKA_ID; required when several keys share the label. */
  keyId?: string;
  poolSize: number;
  operationTimeoutMs: number;
  keyVersion: number;
}

export { HsmTimeoutError };

interface PooledSession {
  handle: Buffer;
  privateKey: Buffer;
  generation: number;
}

const P256_PARAMS = Buffer.from('06082a8648ce3d030107', 'hex'); // OID prime256v1, DER
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

export function pkcs11OptionsFromEnv(): Pkcs11Options {
  if (!env.PKCS11_MODULE_PATH || !env.PKCS11_PIN || !env.PKCS11_EVIDENCE_KEY_LABEL) {
    throw new Error('PKCS11_MODULE_PATH, PKCS11_PIN and PKCS11_EVIDENCE_KEY_LABEL are required when HSM_ADAPTER=pkcs11');
  }
  return {
    modulePath: env.PKCS11_MODULE_PATH,
    pin: env.PKCS11_PIN,
    tokenLabel: env.PKCS11_TOKEN_LABEL,
    slotIndex: env.PKCS11_SLOT_INDEX,
    keyLabel: env.PKCS11_EVIDENCE_KEY_LABEL,
    keyId: env.PKCS11_EVIDENCE_KEY_ID,
    poolSize: env.HSM_SESSION_POOL_SIZE,
    operationTimeoutMs: env.HSM_OPERATION_TIMEOUT_MS,
    keyVersion: env.PKCS11_EVIDENCE_KEY_VERSION,
  };
}

export class Pkcs11HsmAdapter implements HsmAdapter {
  public readonly name = 'pkcs11';

  private readonly idle: PooledSession[] = [];
  private readonly waiting: Array<{ resolve: (s: PooledSession) => void; reject: (e: Error) => void }> = [];
  private openSessions = 0;
  /** Calls that timed out and are still running in the native module. */
  private stuckCalls = 0;
  /** Increments when the module is initialised again; older sessions are dead. */
  private generation = 0;
  /** Set while the module is being re-initialised; new calls wait for it. */
  private reinitializing: Promise<void> | null = null;
  private evidencePublicKey: { pem: string; keyId: string } | null = null;
  private closed = false;

  constructor(private readonly options: Pkcs11Options = pkcs11OptionsFromEnv(), private readonly pkcs11: Pkcs11js.PKCS11 = new Pkcs11js.PKCS11()) {
    this.pkcs11.load(options.modulePath);
    this.initialize();
  }

  async signEvidence(payload: Buffer): Promise<EvidenceSeal> {
    const { keyId } = await this.publicKey();
    return this.run('sign', async (session) => {
      this.pkcs11.C_SignInit(session.handle, { mechanism: Pkcs11js.CKM_ECDSA_SHA256 }, session.privateKey);
      const raw = await this.pkcs11.C_SignAsync(session.handle, payload, Buffer.alloc(64));
      if (raw.length !== 64) throw new Error('HSM returned an ECDSA signature of unexpected length');
      return { signature: rawToDer(Buffer.from(raw)), keyVersion: this.options.keyVersion, keyId };
    });
  }

  async verifySignature(publicKeyPem: string, payload: Buffer, signature: Buffer, format: 'der' | 'raw'): Promise<boolean> {
    let rawSignature: Buffer;
    let point: Buffer;
    try {
      // A malformed signature or key is an invalid signature (a counted
      // failed attempt), not an HSM fault.
      rawSignature = format === 'der' ? derToRaw(signature) : signature;
      if (rawSignature.length !== 64) return false;
      point = parseP256PublicKey(publicKeyPem).point;
    } catch {
      return false;
    }
    return this.run('verify', async (session) => {
      // Session object (CKA_TOKEN false): never persisted, gone with the session.
      const key = this.pkcs11.C_CreateObject(session.handle, [
        { type: Pkcs11js.CKA_CLASS, value: Pkcs11js.CKO_PUBLIC_KEY },
        { type: Pkcs11js.CKA_KEY_TYPE, value: Pkcs11js.CKK_EC },
        { type: Pkcs11js.CKA_TOKEN, value: false },
        { type: Pkcs11js.CKA_VERIFY, value: true },
        { type: Pkcs11js.CKA_EC_PARAMS, value: P256_PARAMS },
        { type: Pkcs11js.CKA_EC_POINT, value: Buffer.concat([Buffer.from([0x04, point.length]), point]) },
      ]);
      try {
        this.pkcs11.C_VerifyInit(session.handle, { mechanism: Pkcs11js.CKM_ECDSA_SHA256 }, key);
        return await this.pkcs11.C_VerifyAsync(session.handle, payload, rawSignature);
      } catch (error) {
        // An invalid signature ends the operation with one of these codes;
        // anything else is a real failure.
        if (/CKR_SIGNATURE_INVALID|CKR_SIGNATURE_LEN_RANGE/.test(messageOf(error))) return false;
        throw error;
      } finally {
        try { this.pkcs11.C_DestroyObject(session.handle, key); } catch { /* removed with the session */ }
      }
    });
  }

  async evidencePublicKeyPem(): Promise<string> {
    return (await this.publicKey()).pem;
  }

  async evidenceKeyId(): Promise<string> {
    return (await this.publicKey()).keyId;
  }

  /** Signs a probe and checks it with the published public key, so a wrong
   * key pairing or an unusable token is found before traffic arrives. */
  async healthCheck(): Promise<void> {
    this.fillPool();
    const probe = createHash('sha256').update('NEXUS-SIGN-HSM-HEALTH-CHECK').digest();
    const { signature } = await this.signEvidence(probe);
    if (!cryptoVerify('sha256', probe, { key: await this.evidencePublicKeyPem(), dsaEncoding: 'der' }, signature)) {
      throw new Error('HSM evidence key pair self-test failed: the signature does not verify with the published public key');
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const waiter of this.waiting.splice(0)) waiter.reject(new Error('HSM adapter closed'));
    for (const session of this.idle.splice(0)) this.closeSession(session);
    try { this.pkcs11.C_Finalize(); } catch { /* already finalised */ }
  }

  private initialize(): void {
    try {
      // Async operations run on libuv worker threads: the module must use
      // OS locking to be called from several threads.
      this.pkcs11.C_Initialize({ flags: Pkcs11js.CKF_OS_LOCKING_OK });
    } catch (error) {
      // Another component of this process may have initialised the module.
      if (!/CKR_CRYPTOKI_ALREADY_INITIALIZED/.test(messageOf(error))) throw error;
    }
  }

  /** Runs one operation on a pooled session with a deadline; retries once on
   * a fresh session when the HSM lost the session or the module state. */
  private async run<T>(operation: string, work: (session: PooledSession) => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      const session = await this.acquire();
      // The deadline starts before work() runs: its synchronous PKCS#11 calls
      // (C_SignInit, C_CreateObject, ...) count against it. A timer cannot
      // fire while they block the thread, so the time they took is measured.
      const started = Date.now();
      const pending = work(session);
      const remaining = this.options.operationTimeoutMs - (Date.now() - started);
      if (remaining <= 0) {
        pending.catch(() => { /* the session is retired either way */ });
        this.retire(session, pending);
        throw new HsmTimeoutError(operation, this.options.operationTimeoutMs);
      }
      let timer: NodeJS.Timeout | undefined;
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new HsmTimeoutError(operation, this.options.operationTimeoutMs)), remaining);
      });
      try {
        const result = await Promise.race([pending, deadline]);
        this.release(session);
        return result;
      } catch (error) {
        if (error instanceof HsmTimeoutError) {
          // The native call may still be running on this session: close it
          // only when it returns, and never hand it out again.
          this.retire(session, pending);
          throw error;
        }
        // A failed operation may leave the session with an active operation
        // or in an unknown state: it is not reused.
        this.retire(session);
        const message = messageOf(error);
        if (isModuleLost(message)) await this.reinitialize();
        if ((isSessionLost(message) || isModuleLost(message)) && attempt < 2) continue;
        throw error;
      } finally {
        clearTimeout(timer);
      }
    }
  }

  private async acquire(): Promise<PooledSession> {
    if (this.reinitializing) await this.reinitializing;
    if (this.closed) throw new Error('HSM adapter closed');
    // Every timed-out call still holds a libuv worker thread (shared with
    // DNS, file and scrypt work) until the HSM answers. Once as many calls as
    // the pool has sessions are stuck, fail fast instead of piling up more.
    if (this.stuckCalls >= this.options.poolSize) {
      throw new HsmTimeoutError('session acquisition (HSM not answering)', this.options.operationTimeoutMs);
    }
    const idle = this.idle.pop();
    if (idle) return idle;
    if (this.openSessions < this.options.poolSize) {
      this.openSessions += 1;
      try {
        return this.openSession();
      } catch (error) {
        this.openSessions -= 1;
        throw error;
      }
    }
    return new Promise<PooledSession>((resolve, reject) => {
      const waiter = { resolve, reject };
      const timer = setTimeout(() => {
        const index = this.waiting.indexOf(waiter);
        if (index >= 0) this.waiting.splice(index, 1);
        reject(new HsmTimeoutError('session acquisition', this.options.operationTimeoutMs));
      }, this.options.operationTimeoutMs);
      waiter.resolve = (session) => { clearTimeout(timer); resolve(session); };
      waiter.reject = (error) => { clearTimeout(timer); reject(error); };
      this.waiting.push(waiter);
    });
  }

  /** Opens idle sessions up to the pool size (synchronous PKCS#11 calls),
   * so request paths reuse them instead of opening one. */
  private fillPool(): void {
    while (!this.closed && this.openSessions < this.options.poolSize && this.stuckCalls === 0) {
      this.openSessions += 1;
      try {
        this.release(this.openSession());
      } catch (error) {
        this.openSessions -= 1;
        throw error;
      }
    }
  }

  private release(session: PooledSession): void {
    if (session.generation !== this.generation) {
      this.retire(session);
      return;
    }
    const waiter = this.waiting.shift();
    if (waiter) waiter.resolve(session);
    else this.idle.push(session);
  }

  /** Takes a session out of the pool for good and lets a waiting caller open
   * a replacement. */
  private retire(session: PooledSession, pending?: Promise<unknown>): void {
    this.openSessions -= 1;
    if (pending) {
      this.stuckCalls += 1;
      const done = () => { this.stuckCalls -= 1; this.closeSession(session); };
      pending.then(done, done);
    } else {
      this.closeSession(session);
    }
    const waiter = this.waiting.shift();
    if (waiter) this.acquire().then(waiter.resolve, waiter.reject);
  }

  private closeSession(session: PooledSession): void {
    if (session.generation !== this.generation) return; // finalised with the module
    try { this.pkcs11.C_CloseSession(session.handle); } catch { /* already gone */ }
  }

  /**
   * Finalises and initialises the module again after it reported itself lost.
   * C_Finalize while other threads are inside the module is undefined
   * behaviour (PKCS#11 v2.40 §5.4; vendor modules can crash the process), so
   * new calls wait and the calls in flight are drained first (finding B-08).
   * If they do not return within the operation timeout, the module is not
   * finalised: the call fails, and the readiness check reports the HSM.
   */
  private reinitialize(): Promise<void> {
    if (this.reinitializing) return this.reinitializing;
    this.generation += 1;
    // Idle sessions die with the module; sessions in use are retired when
    // they come back (generation check in release()).
    this.openSessions -= this.idle.length;
    this.idle.splice(0);
    this.reinitializing = (async () => {
      const deadline = Date.now() + this.options.operationTimeoutMs;
      while (this.openSessions > 0 || this.stuckCalls > 0) {
        if (Date.now() >= deadline) {
          throw new HsmTimeoutError('module re-initialisation (calls still in the module)', this.options.operationTimeoutMs);
        }
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      try { this.pkcs11.C_Finalize(); } catch { /* not initialised */ }
      this.initialize();
    })().finally(() => { this.reinitializing = null; });
    return this.reinitializing;
  }

  private openSession(): PooledSession {
    const slot = this.selectSlot();
    const handle = this.pkcs11.C_OpenSession(slot, Pkcs11js.CKF_SERIAL_SESSION | Pkcs11js.CKF_RW_SESSION);
    try {
      try {
        this.pkcs11.C_Login(handle, Pkcs11js.CKU_USER, this.options.pin);
      } catch (error) {
        // Login is per application: another session already logged in.
        if (!/CKR_USER_ALREADY_LOGGED_IN/.test(messageOf(error))) throw error;
      }
      const privateKey = this.findUniqueKey(handle, Pkcs11js.CKO_PRIVATE_KEY);
      this.assertEvidencePrivateKey(handle, privateKey);
      const publicKey = this.readPublicKey(handle);
      if (this.evidencePublicKey && this.evidencePublicKey.keyId !== publicKey.keyId) {
        throw new Error('The HSM evidence key changed while the service was running; restart after a key rotation');
      }
      this.evidencePublicKey = publicKey;
      return { handle, privateKey, generation: this.generation };
    } catch (error) {
      try { this.pkcs11.C_CloseSession(handle); } catch { /* best effort */ }
      throw error;
    }
  }

  private selectSlot(): Buffer {
    const slots = this.pkcs11.C_GetSlotList(true);
    if (this.options.tokenLabel) {
      const matching = slots.filter((slot) => this.pkcs11.C_GetTokenInfo(slot).label.trim() === this.options.tokenLabel);
      if (matching.length !== 1) {
        throw new Error(matching.length === 0
          ? `No PKCS#11 token labelled '${this.options.tokenLabel}' is present`
          : `More than one PKCS#11 token is labelled '${this.options.tokenLabel}'`);
      }
      return matching[0];
    }
    const slot = slots[this.options.slotIndex];
    if (!slot) throw new Error('No PKCS#11 slot with a present token was found at PKCS11_SLOT_INDEX');
    return slot;
  }

  private findUniqueKey(session: Buffer, keyClass: number): Buffer {
    const template: Pkcs11js.Template = [
      { type: Pkcs11js.CKA_CLASS, value: keyClass },
      { type: Pkcs11js.CKA_LABEL, value: this.options.keyLabel },
    ];
    if (this.options.keyId) template.push({ type: Pkcs11js.CKA_ID, value: Buffer.from(this.options.keyId, 'hex') });
    this.pkcs11.C_FindObjectsInit(session, template);
    let handles: Buffer[];
    try {
      handles = this.pkcs11.C_FindObjects(session, 2);
    } finally {
      this.pkcs11.C_FindObjectsFinal(session);
    }
    const kind = keyClass === Pkcs11js.CKO_PRIVATE_KEY ? 'private' : 'public';
    if (handles.length === 0) throw new Error(`HSM evidence ${kind} key '${this.options.keyLabel}' was not found`);
    if (handles.length > 1) {
      throw new Error(`More than one HSM ${kind} key is labelled '${this.options.keyLabel}'; set PKCS11_EVIDENCE_KEY_ID to select one`);
    }
    return handles[0];
  }

  private assertEvidencePrivateKey(session: Buffer, key: Buffer): void {
    const attributes = this.pkcs11.C_GetAttributeValue(session, key, [
      { type: Pkcs11js.CKA_KEY_TYPE }, { type: Pkcs11js.CKA_SIGN }, { type: Pkcs11js.CKA_SENSITIVE },
      { type: Pkcs11js.CKA_EXTRACTABLE }, { type: Pkcs11js.CKA_EC_PARAMS },
      { type: Pkcs11js.CKA_LOCAL }, { type: Pkcs11js.CKA_NEVER_EXTRACTABLE }, { type: Pkcs11js.CKA_ALWAYS_SENSITIVE },
    ]);
    const [keyType, canSign, sensitive, extractable, params, local, neverExtractable, alwaysSensitive] = attributes.map((a) => a.value as Buffer);
    if (!keyType || ulong(keyType) !== Pkcs11js.CKK_EC) throw new Error('The HSM evidence key is not an EC key');
    if (!params || !params.equals(P256_PARAMS)) throw new Error('The HSM evidence key is not on curve P-256');
    if (!isTrue(canSign)) throw new Error('The HSM evidence key is not allowed to sign (CKA_SIGN)');
    if (!isTrue(sensitive)) throw new Error('The HSM evidence key must be sensitive (CKA_SENSITIVE)');
    if (isTrue(extractable)) throw new Error('The HSM evidence key must not be extractable (CKA_EXTRACTABLE)');
    // Provenance (audit finding B-02): a key generated inside the HSM and
    // never exportable, not one imported from a copy that may exist elsewhere.
    if (!isTrue(local)) throw new Error('The HSM evidence key must be generated in the HSM (CKA_LOCAL), not imported');
    if (!isTrue(neverExtractable)) throw new Error('The HSM evidence key must never have been extractable (CKA_NEVER_EXTRACTABLE)');
    if (!isTrue(alwaysSensitive)) throw new Error('The HSM evidence key must always have been sensitive (CKA_ALWAYS_SENSITIVE)');
  }

  private readPublicKey(session: Buffer): { pem: string; keyId: string } {
    const handle = this.findUniqueKey(session, Pkcs11js.CKO_PUBLIC_KEY);
    const [attribute] = this.pkcs11.C_GetAttributeValue(session, handle, [{ type: Pkcs11js.CKA_EC_POINT }]);
    const encoded = attribute?.value as Buffer | undefined;
    // CKA_EC_POINT is a DER OCTET STRING (04 41 || 04 X Y) on most modules;
    // some return the bare point.
    const point = encoded && encoded.length === 67 && encoded[0] === 0x04 && encoded[1] === 0x41 ? encoded.subarray(2) : encoded;
    if (!point || point.length !== 65 || point[0] !== 0x04) throw new Error('HSM evidence key is not an uncompressed P-256 point');
    const spki = Buffer.concat([P256_SPKI_PREFIX, point]);
    const pem = parseP256PublicKey(createPublicKey({ key: spki, format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }).toString()).pem;
    return { pem, keyId: createHash('sha256').update(spki).digest('hex') };
  }

  private async publicKey(): Promise<{ pem: string; keyId: string }> {
    if (!this.evidencePublicKey) {
      // Opening a session reads and checks the key pair.
      this.release(await this.acquire());
    }
    if (!this.evidencePublicKey) throw new Error('HSM evidence public key is not available');
    return this.evidencePublicKey;
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** A CK_ULONG attribute value in the platform's byte order (little-endian on
 * the platforms Auth Core supports). */
function ulong(value: Buffer): number {
  return value.length >= 8 ? Number(value.readBigUInt64LE(0)) : value.readUInt32LE(0);
}

function isTrue(value: Buffer | undefined): boolean {
  return Boolean(value && value.length > 0 && value[0] !== 0);
}

function isSessionLost(message: string): boolean {
  return /CKR_(SESSION_HANDLE_INVALID|SESSION_CLOSED|USER_NOT_LOGGED_IN|DEVICE_REMOVED|DEVICE_ERROR|TOKEN_NOT_PRESENT|OBJECT_HANDLE_INVALID|KEY_HANDLE_INVALID)/.test(message);
}

function isModuleLost(message: string): boolean {
  return /CKR_(CRYPTOKI_NOT_INITIALIZED|DEVICE_REMOVED)/.test(message);
}
