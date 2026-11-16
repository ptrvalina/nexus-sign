// The HSM worker host (audit finding B-01): PKCS#11 runs in a worker thread,
// so a synchronous call that stalls (C_Login, C_OpenSession, C_FindObjects,
// C_SignInit ...) blocks that thread, never the event loop. Each call is
// bounded, the queue is limited, consecutive timeouts or a crash open a
// circuit breaker that fails closed, and a fresh worker is probed after the
// cooldown. Real worker threads; the PKCS#11 module is a double
// (test/support/hsm-worker-double.mjs).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { verify } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadTs } from './support/load-ts.mjs';

const { HsmWorkerHost, HsmTimeoutError, HsmBusyError, HsmUnavailableError } = loadTs('crypto/hsmWorkerHost.ts');
const DOUBLE = fileURLToPath(new URL('./support/hsm-worker-double.mjs', import.meta.url));

function host(behaviours, options = {}) {
  let started = 0;
  let clock = 0;
  const h = new HsmWorkerHost(() => new Worker(DOUBLE, { workerData: { behaviour: behaviours[Math.min(started++, behaviours.length - 1)] } }), {
    name: 'pkcs11', timeoutMs: 300, queueLimit: 8, breakerThreshold: 2, breakerCooldownMs: 1000, now: () => clock, ...options,
  });
  return { h, started: () => started, advance: (ms) => { clock += ms; } };
}

test('signing and key lookup go through the worker', async () => {
  const { h } = host([{}]);
  const payload = Buffer.alloc(32, 9);
  const seal = await h.signEvidence(payload);
  assert.ok(verify('sha256', payload, { key: await h.evidencePublicKeyPem(), dsaEncoding: 'der' }, seal.signature));
  assert.equal(seal.keyId, await h.evidenceKeyId());
  await h.close();
});

test('a stalled synchronous PKCS#11 call times out and the event loop keeps running', async () => {
  const { h } = host([{ stallOn: 'sign', stallMs: 1500 }], { breakerThreshold: 10 });
  await h.healthCheck();
  let worstGap = 0; let last = Date.now();
  const ticker = setInterval(() => { const t = Date.now(); worstGap = Math.max(worstGap, t - last); last = t; }, 10);
  const started = Date.now();
  await assert.rejects(h.signEvidence(Buffer.alloc(32)), (e) => e instanceof HsmTimeoutError);
  clearInterval(ticker);
  assert.ok(Date.now() - started < 600, `the call was bounded (${Date.now() - started} ms)`);
  assert.ok(worstGap < 100, `the event loop was never blocked (worst gap ${worstGap} ms)`);
  await h.close();
});

test('consecutive timeouts open the breaker: calls fail at once, then a fresh worker is probed after the cooldown', async () => {
  const { h, started, advance } = host([{ stallOn: 'sign', stallMs: 2000 }, {}]);
  await assert.rejects(h.signEvidence(Buffer.alloc(32)), HsmTimeoutError);
  await assert.rejects(h.signEvidence(Buffer.alloc(32)), HsmTimeoutError);
  assert.equal(h.state().breaker, 'OPEN');
  const t0 = Date.now();
  await assert.rejects(h.signEvidence(Buffer.alloc(32)), (e) => e instanceof HsmUnavailableError && /consecutive/.test(e.message));
  await assert.rejects(h.healthCheck(), HsmUnavailableError, 'readiness reports the HSM down');
  assert.ok(Date.now() - t0 < 50, 'fails closed without waiting');
  advance(1001);
  const seal = await h.signEvidence(Buffer.alloc(32, 1));
  assert.ok(seal.signature.length > 0);
  assert.equal(h.state().breaker, 'CLOSED');
  assert.equal(started(), 2, 'the stuck worker was replaced');
  await h.close();
});

test('the queue is bounded', async () => {
  const { h } = host([{ stallOn: 'sign', stallMs: 800 }], { queueLimit: 2, timeoutMs: 1500, breakerThreshold: 10 });
  await h.healthCheck();
  const calls = [h.signEvidence(Buffer.alloc(32)), h.signEvidence(Buffer.alloc(32))];
  await assert.rejects(h.signEvidence(Buffer.alloc(32)), HsmBusyError);
  await Promise.allSettled(calls);
  await h.close();
});

test('a crashed worker fails its calls and opens the breaker', async () => {
  const { h } = host([{ exitOn: 'sign' }, {}]);
  await h.healthCheck();
  await assert.rejects(h.signEvidence(Buffer.alloc(32)), (e) => e instanceof HsmUnavailableError && /exited/.test(e.message));
  assert.equal(h.state().breaker, 'OPEN');
  await h.close();
});

test('close lets a call in flight finish, then refuses new calls', async () => {
  const { h } = host([{ stallOn: 'sign', stallMs: 150 }], { breakerThreshold: 10 });
  await h.healthCheck();
  const inFlight = h.signEvidence(Buffer.alloc(32));
  await h.close();
  assert.ok((await inFlight).signature.length > 0);
  await assert.rejects(h.signEvidence(Buffer.alloc(32)), /closed/);
});
