// The PKCS#11 adapter against a real PKCS#11 module (SoftHSM2): sealing,
// verification, key selection rules, concurrency, timeouts and session loss.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { ROOT } from './support/harness.mjs';
import { SOFTHSM_MODULE, generateKeyPair, initToken, skipWithoutSoftHsm, softHsmDirectory } from './support/softhsm.mjs';

const require = createRequire(import.meta.url);

describe('PKCS#11 HSM adapter on SoftHSM2', { skip: skipWithoutSoftHsm }, () => {
  let Pkcs11HsmAdapter;
  let pkcs11js;
  const adapters = [];
  const options = (overrides = {}) => ({
    modulePath: SOFTHSM_MODULE, pin: '12345678', tokenLabel: 'nexus-main', slotIndex: 0,
    keyLabel: 'nexus-evidence', keyId: undefined, poolSize: 3, operationTimeoutMs: 2000, keyVersion: 1, ...overrides,
  });
  const adapter = (overrides, pkcs11) => {
    const instance = new Pkcs11HsmAdapter(options(overrides), pkcs11);
    adapters.push(instance);
    return instance;
  };

  before(() => {
    const conf = softHsmDirectory();
    process.env.SOFTHSM2_CONF = conf;
    generateKeyPair(conf, initToken(conf, 'nexus-main'), { label: 'nexus-evidence' });
    const duplicate = initToken(conf, 'nexus-duplicate');
    generateKeyPair(conf, duplicate, { label: 'nexus-evidence', id: '01' });
    generateKeyPair(conf, duplicate, { label: 'nexus-evidence', id: '02' });
    generateKeyPair(conf, initToken(conf, 'nexus-extractable'), { label: 'nexus-evidence', sensitive: false, extractable: true });

    process.env.NODE_ENV ??= 'test';
    process.env.DATABASE_URL ??= 'postgres://unused:unused@127.0.0.1:1/unused';
    process.env.REDIS_URL ??= 'redis://127.0.0.1:1';
    process.env.PKCS11_MODULE_PATH = SOFTHSM_MODULE;
    process.env.PKCS11_PIN = '12345678';
    process.env.PKCS11_TOKEN_LABEL = 'nexus-main';
    process.env.PKCS11_EVIDENCE_KEY_LABEL = 'nexus-evidence';
    ({ Pkcs11HsmAdapter } = require(join(ROOT, 'dist/crypto/pkcs11HsmAdapter.js')));
    pkcs11js = require('pkcs11js');
  });
  after(async () => {
    for (const a of adapters.reverse()) await a.close();
  });

  test('seals evidence with the token key, and the seal verifies with the published key', async () => {
    const hsm = adapter();
    await hsm.healthCheck();
    const hash = createHash('sha256').update('evidence').digest();
    const sealed = await hsm.signEvidence(hash);
    const publicKeyPem = await hsm.evidencePublicKeyPem();
    assert.ok(verify('sha256', hash, { key: publicKeyPem, dsaEncoding: 'der' }, sealed.signature));
    const spki = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
    assert.equal(sealed.keyId, createHash('sha256').update(spki).digest('hex'));
    assert.equal(await hsm.evidenceKeyId(), sealed.keyId);
  });

  test('verifies customer signatures: valid, wrong data, wrong key, malformed', async () => {
    const hsm = adapter();
    const customer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem = customer.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const data = Buffer.from('{"amount_minor":"100"}');
    const der = sign('sha256', data, { key: customer.privateKey, dsaEncoding: 'der' });
    const raw = sign('sha256', data, { key: customer.privateKey, dsaEncoding: 'ieee-p1363' });
    assert.equal(await hsm.verifySignature(pem, data, der, 'der'), true);
    assert.equal(await hsm.verifySignature(pem, data, raw, 'raw'), true);
    assert.equal(await hsm.verifySignature(pem, Buffer.from('{"amount_minor":"1"}'), der, 'der'), false);
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'pem' }).toString();
    assert.equal(await hsm.verifySignature(other, data, der, 'der'), false);
    assert.equal(await hsm.verifySignature(pem, data, Buffer.from('not a signature'), 'der'), false);
  });

  test('100 parallel seals all complete and verify', async () => {
    const hsm = adapter();
    const publicKeyPem = await hsm.evidencePublicKeyPem();
    const hashes = Array.from({ length: 100 }, (_, i) => createHash('sha256').update(`record ${i}`).digest());
    const seals = await Promise.all(hashes.map((h) => hsm.signEvidence(h)));
    seals.forEach((s, i) => assert.ok(verify('sha256', hashes[i], { key: publicKeyPem, dsaEncoding: 'der' }, s.signature), `seal ${i}`));
  });

  test('two keys with the evidence label are refused instead of picking one', async () => {
    const hsm = adapter({ tokenLabel: 'nexus-duplicate' });
    await assert.rejects(() => hsm.healthCheck(), /more than one/i);
    const byId = adapter({ tokenLabel: 'nexus-duplicate', keyId: '02' });
    await byId.healthCheck();
  });

  test('an extractable or non-sensitive evidence key is refused', async () => {
    const hsm = adapter({ tokenLabel: 'nexus-extractable' });
    await assert.rejects(() => hsm.healthCheck(), /extractable|sensitive/i);
  });

  test('an unknown token label is refused', async () => {
    const hsm = adapter({ tokenLabel: 'no-such-token' });
    await assert.rejects(() => hsm.healthCheck(), /token/i);
  });

  test('a hung HSM operation times out and does not block other operations', async () => {
    const real = new pkcs11js.PKCS11();
    let hang = true;
    const slow = new Proxy(real, {
      get(target, property) {
        const value = target[property];
        if (property === 'C_SignAsync') {
          return (...args) => (hang ? new Promise(() => {}) : value.apply(target, args));
        }
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const hsm = adapter({ operationTimeoutMs: 300, poolSize: 2 }, slow);
    const started = Date.now();
    await assert.rejects(() => hsm.signEvidence(createHash('sha256').update('x').digest()), /timed out/i);
    assert.ok(Date.now() - started < 2000, 'the caller is released after the timeout');
    hang = false;
    const sealed = await hsm.signEvidence(createHash('sha256').update('y').digest());
    assert.ok(sealed.signature.length > 0, 'later operations use a fresh session');
  });

  test('a lost session is reopened and the operation retried once', async () => {
    const real = new pkcs11js.PKCS11();
    let failures = 1;
    const flaky = new Proxy(real, {
      get(target, property) {
        const value = target[property];
        if (property === 'C_SignAsync') {
          return (...args) => {
            if (failures > 0) {
              failures -= 1;
              const error = new Error('CKR_SESSION_HANDLE_INVALID:179');
              return Promise.reject(error);
            }
            return value.apply(target, args);
          };
        }
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const hsm = adapter({}, flaky);
    const sealed = await hsm.signEvidence(createHash('sha256').update('z').digest());
    assert.ok(sealed.signature.length > 0);
  });

  test('when as many calls as sessions are stuck, new operations fail fast (red-team RT-05)', async () => {
    const real = new pkcs11js.PKCS11();
    const stuck = new Proxy(real, {
      get(target, property) {
        const value = target[property];
        if (property === 'C_SignAsync') return () => new Promise(() => {});
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const hsm = adapter({ operationTimeoutMs: 200, poolSize: 2 }, stuck);
    const digest = createHash('sha256').update('stuck').digest();
    await Promise.all([1, 2].map(() => assert.rejects(() => hsm.signEvidence(digest), /timed out/i)));
    const started = Date.now();
    await assert.rejects(() => hsm.signEvidence(digest), /not answering/);
    assert.ok(Date.now() - started < 100, 'refused without waiting for another timeout');
  });

  test('re-initialising the module does not shrink the session pool (red-team RT-04)', async () => {
    const real = new pkcs11js.PKCS11();
    let lose = false;
    const losing = new Proxy(real, {
      get(target, property) {
        const value = target[property];
        if (property === 'C_SignAsync') {
          return (...args) => {
            if (lose) { lose = false; return Promise.reject(new Error('CKR_CRYPTOKI_NOT_INITIALIZED:400')); }
            return value.apply(target, args);
          };
        }
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const hsm = adapter({ poolSize: 2, operationTimeoutMs: 2000 }, losing);
    const digest = (n) => createHash('sha256').update(String(n)).digest();
    await Promise.all([1, 2].map((n) => hsm.signEvidence(digest(n)))); // two idle sessions
    lose = true;
    await hsm.signEvidence(digest(3)); // re-initialises, retries on a new session
    const results = await Promise.all([4, 5, 6, 7].map((n) => hsm.signEvidence(digest(n))));
    assert.equal(results.length, 4);
    // Every session the pool counts exists: none was lost with the old module.
    assert.equal(hsm.idle.length, hsm.openSessions, `idle ${hsm.idle.length}, counted ${hsm.openSessions}`);
    assert.equal(hsm.openSessions, 2, 'both sessions are usable again');
  });
});
