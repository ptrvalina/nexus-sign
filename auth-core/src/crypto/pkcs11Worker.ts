import { parentPort, workerData } from 'node:worker_threads';
import { Pkcs11HsmAdapter, type Pkcs11Options } from './pkcs11HsmAdapter';
import type { WorkerReply, WorkerRequest } from './hsmWorkerHost';

/**
 * Worker thread that owns the PKCS#11 module (audit finding B-01). Every
 * PKCS#11 call, synchronous or not, runs here; the main thread only exchanges
 * messages with it (hsmWorkerHost.ts) and bounds each call with a timeout.
 * Errors are returned by name and message only: no PKCS#11 handles, PINs or
 * key material leave the thread.
 */
if (!parentPort) throw new Error('pkcs11Worker must run as a worker thread');
const port = parentPort;
const adapter = new Pkcs11HsmAdapter(workerData.options as Pkcs11Options);

async function handle(request: WorkerRequest): Promise<unknown> {
  const [a, b, c, d] = request.args;
  switch (request.op) {
    case 'sign': {
      const seal = await adapter.signEvidence(Buffer.from(a as Uint8Array));
      return { signature: seal.signature, keyVersion: seal.keyVersion, keyId: seal.keyId };
    }
    case 'verify':
      return adapter.verifySignature(a as string, Buffer.from(b as Uint8Array), Buffer.from(c as Uint8Array), d as 'der' | 'raw');
    case 'publicKey': return adapter.evidencePublicKeyPem();
    case 'keyId': return adapter.evidenceKeyId();
    case 'health': await adapter.healthCheck(); return null;
    case 'close': await adapter.close(); return null;
    default: throw new Error(`unknown HSM operation ${String(request.op)}`);
  }
}

port.on('message', (request: WorkerRequest) => {
  handle(request).then(
    (result) => port.postMessage({ id: request.id, ok: true, result } satisfies WorkerReply),
    (error: unknown) => {
      const e = error instanceof Error ? error : new Error(String(error));
      port.postMessage({ id: request.id, ok: false, error: { name: e.name, message: e.message } } satisfies WorkerReply);
    },
  );
});
