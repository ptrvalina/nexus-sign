// The call code of the operator console (public/admin/call-code.js) against
// the shared vectors that the iOS and Android SDKs also run (finding A2-11).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const vectors = JSON.parse(readFileSync(new URL('../test-vectors/call-code-v1.json', import.meta.url), 'utf8'));
const context = vm.createContext({ crypto: globalThis.crypto, TextEncoder, DataView, Uint8Array, String });
vm.runInContext(readFileSync(new URL('../public/admin/call-code.js', import.meta.url), 'utf8'), context);

test('the console computes the call code of every vector', async () => {
  for (const v of vectors.valid) {
    assert.equal(context.sdpFingerprint(v.offer), v.offerFingerprint, v.name);
    assert.equal(context.sdpFingerprint(v.answer), v.answerFingerprint, v.name);
    assert.equal(await context.callCode(v.offer, v.answer), v.code, v.name);
  }
});

test('a substituted operator certificate changes the code', async () => {
  const [genuine, , , substituted] = vectors.valid;
  assert.equal(genuine.offer, substituted.offer);
  assert.notEqual(genuine.code, substituted.code);
});

test('no code without a fingerprint on both sides', async () => {
  for (const v of vectors.noFingerprint) assert.equal(await context.callCode(v.offer, v.answer), null, v.name);
});
