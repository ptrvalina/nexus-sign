import type { EvidenceSeal, HsmAdapter } from './hsmAdapter';
import { HsmBusyError, HsmTimeoutError, HsmUnavailableError } from './hsmErrors';

export { HsmBusyError, HsmTimeoutError, HsmUnavailableError };

/**
 * Runs an HSM adapter in a worker thread and talks to it by messages (audit
 * finding B-01).
 *
 * pkcs11js has no asynchronous form of C_OpenSession, C_Login,
 * C_FindObjects*, C_GetAttributeValue, C_SignInit, C_VerifyInit or
 * C_CreateObject. Run on the main thread, an HSM that stalls inside one of
 * them froze the whole process: HTTP, health endpoints and workers. Here the
 * PKCS#11 module lives in its own thread (pkcs11Worker.ts), so a stalled call
 * blocks only that thread, and the main thread:
 *
 * - bounds every call, whatever PKCS#11 function it is stuck in, by
 *   HSM_OPERATION_TIMEOUT_MS (HsmTimeoutError);
 * - limits how many calls wait (HSM_QUEUE_LIMIT; HsmBusyError beyond);
 * - opens a circuit breaker after HSM_BREAKER_THRESHOLD consecutive timeouts
 *   or a worker crash: calls fail at once (HsmUnavailableError, fail closed,
 *   readiness reports the HSM down) for HSM_BREAKER_COOLDOWN_MS; the stuck
 *   worker is terminated, and the next call after the cooldown starts a fresh
 *   worker and probes it with a health check before traffic resumes;
 * - on close(), lets calls in flight finish up to the timeout, then stops the
 *   worker.
 *
 * Nothing falls back to software keys.
 */


/** The part of worker_threads.Worker the host uses (a test double implements it too). */
export interface WorkerLike {
  postMessage(message: unknown): void;
  on(event: 'message', listener: (message: WorkerReply) => void): unknown;
  on(event: 'error', listener: (error: Error) => void): unknown;
  on(event: 'exit', listener: (code: number) => void): unknown;
  terminate(): Promise<number> | void;
  unref?(): void;
}

export type WorkerOperation = 'sign' | 'verify' | 'publicKey' | 'keyId' | 'health' | 'close';
export interface WorkerRequest { id: number; op: WorkerOperation; args: unknown[] }
export type WorkerReply = { id: number; ok: true; result: unknown } | { id: number; ok: false; error: { name: string; message: string } };

export interface HsmWorkerHostOptions {
  name: string;
  timeoutMs: number;
  queueLimit: number;
  breakerThreshold: number;
  breakerCooldownMs: number;
  now?: () => number;
}

interface Pending { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: NodeJS.Timeout; op: WorkerOperation }

export type BreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export class HsmWorkerHost implements HsmAdapter {
  public readonly name: string;
  private worker: WorkerLike | null = null;
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  private consecutiveTimeouts = 0;
  private breaker: BreakerState = 'CLOSED';
  private openedAt = 0;
  private openReason = '';
  private probing: Promise<void> | null = null;
  private closed = false;
  private cachedKey: { pem: string; keyId: string } | null = null;
  private readonly now: () => number;

  constructor(private readonly createWorker: () => WorkerLike, private readonly options: HsmWorkerHostOptions) {
    this.name = options.name;
    this.now = options.now ?? Date.now;
  }

  /** Circuit breaker state, for metrics and readiness. */
  state(): { breaker: BreakerState; inFlight: number; reason: string | null } {
    return { breaker: this.breaker, inFlight: this.pending.size, reason: this.breaker === 'CLOSED' ? null : this.openReason };
  }

  async signEvidence(payload: Buffer): Promise<EvidenceSeal> {
    const r = await this.call('sign', [payload]) as { signature: Uint8Array; keyVersion: number; keyId: string };
    return { signature: Buffer.from(r.signature), keyVersion: r.keyVersion, keyId: r.keyId };
  }

  async verifySignature(publicKeyPem: string, payload: Buffer, signature: Buffer, format: 'der' | 'raw'): Promise<boolean> {
    return (await this.call('verify', [publicKeyPem, payload, signature, format])) === true;
  }

  async evidencePublicKeyPem(): Promise<string> { return (await this.key()).pem; }
  async evidenceKeyId(): Promise<string> { return (await this.key()).keyId; }

  async healthCheck(): Promise<void> {
    await this.call('health', []);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const worker = this.worker;
    if (!worker) return;
    // Calls in flight finish (each is bounded by its own timeout), then the
    // module is finalised in the worker and the worker stops.
    await Promise.allSettled([...this.pending.values()].map((p) => new Promise((done) => { const { resolve, reject } = p; p.resolve = (v) => { resolve(v); done(undefined); }; p.reject = (e) => { reject(e); done(undefined); }; })));
    await this.send(worker, 'close', []).catch(() => undefined);
    this.worker = null;
    await worker.terminate();
  }

  private async key(): Promise<{ pem: string; keyId: string }> {
    // The evidence key is fixed for the process (the adapter refuses a key
    // change); keep it, so evidence verification does not need the HSM.
    if (!this.cachedKey) {
      const [pem, keyId] = await Promise.all([this.call('publicKey', []), this.call('keyId', [])]);
      this.cachedKey = { pem: pem as string, keyId: keyId as string };
    }
    return this.cachedKey;
  }

  private async call(op: WorkerOperation, args: unknown[]): Promise<unknown> {
    if (this.closed) throw new HsmUnavailableError('adapter closed');
    if (this.breaker === 'OPEN') {
      if (this.now() - this.openedAt < this.options.breakerCooldownMs) throw new HsmUnavailableError(this.openReason);
      await this.probe();
    } else if (this.breaker === 'HALF_OPEN' && this.probing) {
      await this.probing;
    }
    if (this.pending.size >= this.options.queueLimit) throw new HsmBusyError(this.options.queueLimit);
    return this.send(this.ensureWorker(), op, args);
  }

  /** After the cooldown: a fresh worker must pass a health check before traffic. */
  private async probe(): Promise<void> {
    if (!this.probing) {
      this.breaker = 'HALF_OPEN';
      this.probing = (async () => {
        try {
          await this.send(this.ensureWorker(), 'health', []);
          this.breaker = 'CLOSED';
          this.consecutiveTimeouts = 0;
        } catch (error) {
          this.open(`health check after cooldown failed: ${error instanceof Error ? error.message : String(error)}`);
          throw new HsmUnavailableError(this.openReason);
        } finally {
          this.probing = null;
        }
      })();
    }
    await this.probing;
  }

  private ensureWorker(): WorkerLike {
    if (this.worker) return this.worker;
    const worker = this.createWorker();
    worker.on('message', (reply) => this.onReply(reply));
    worker.on('error', (error) => this.onWorkerGone(worker, `worker error: ${error.message}`));
    worker.on('exit', (code) => this.onWorkerGone(worker, `worker exited (${code})`));
    this.worker = worker;
    return worker;
  }

  private send(worker: WorkerLike, op: WorkerOperation, args: unknown[]): Promise<unknown> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (!this.pending.delete(id)) return;
        reject(new HsmTimeoutError(op, this.options.timeoutMs));
        this.onTimeout();
      }, this.options.timeoutMs);
      this.pending.set(id, { resolve, reject, timer, op });
      worker.postMessage({ id, op, args } satisfies WorkerRequest);
    });
  }

  private onReply(reply: WorkerReply): void {
    const p = this.pending.get(reply.id);
    if (!p) return; // answered after its timeout: already rejected
    this.pending.delete(reply.id);
    clearTimeout(p.timer);
    this.consecutiveTimeouts = 0;
    if (reply.ok) p.resolve(reply.result);
    else p.reject(Object.assign(new Error(reply.error.message), { name: reply.error.name }));
  }

  private onTimeout(): void {
    this.consecutiveTimeouts += 1;
    if (this.consecutiveTimeouts >= this.options.breakerThreshold) {
      this.open(`${this.consecutiveTimeouts} consecutive calls timed out`);
    }
  }

  private onWorkerGone(worker: WorkerLike, reason: string): void {
    if (this.worker !== worker) return;
    this.worker = null;
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new HsmUnavailableError(reason));
      this.pending.delete(id);
    }
    if (!this.closed) this.open(reason);
  }

  /** Fail closed: stop the (possibly stuck) worker; a new one is started after the cooldown. */
  private open(reason: string): void {
    this.breaker = 'OPEN';
    this.openedAt = this.now();
    this.openReason = reason;
    const worker = this.worker;
    this.worker = null;
    if (worker) {
      for (const [id, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new HsmUnavailableError(reason));
        this.pending.delete(id);
      }
      void Promise.resolve(worker.terminate()).catch(() => undefined);
    }
  }
}
