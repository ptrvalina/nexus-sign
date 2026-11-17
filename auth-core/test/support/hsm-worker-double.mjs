// A worker thread that speaks the HSM worker protocol (src/crypto/pkcs11Worker.ts)
// and can misbehave like a stalled or crashing PKCS#11 module. Test use only.
import { parentPort, workerData } from 'node:worker_threads';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const keyId = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
const behaviour = workerData?.behaviour ?? {};
const busyWait = (ms) => { const end = Date.now() + ms; while (Date.now() < end) { /* a synchronous native call that does not return */ } };

parentPort.on('message', ({ id, op, args }) => {
  if (behaviour.stallOn === op) busyWait(behaviour.stallMs);
  if (behaviour.exitOn === op) process.exit(3);
  const reply = (result) => parentPort.postMessage({ id, ok: true, result });
  if (op === 'sign') reply({ signature: sign('sha256', Buffer.from(args[0]), { key: privateKey, dsaEncoding: 'der' }), keyVersion: 1, keyId });
  else if (op === 'publicKey') reply(pem);
  else if (op === 'keyId') reply(keyId);
  else if (op === 'health' || op === 'close') reply(null);
  else if (op === 'verify') reply(true);
  else parentPort.postMessage({ id, ok: false, error: { name: 'Error', message: `unknown ${op}` } });
});
