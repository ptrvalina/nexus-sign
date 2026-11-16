// A recovery phrase recovers an identity once (audit finding A2-02), on
// PostgreSQL with the full schema. Before, the phrase stayed valid after a
// recovery, so whoever phished it could take the identity back each time the
// owner recovered it, and the old device lost its credential with no notice.
//
// Service level: the services run in this process against a real database;
// Redis (the issued setup salt) is replaced by a map, metrics are stubbed.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';
import { loadTs } from '../support/load-ts.mjs';
import { createRecoveryKey, openRecoveryKey, proofSigningInput, setupSigningInput, signDerB64 } from './support/recovery.mjs';

class Metric { inc() {} observe() {} set() {} labels() { return this; } startTimer() { return () => {}; } }
const memory = new Map();
const stubs = {
  'prom-client': { Registry: class { registerMetric() {} metrics() { return ''; } }, Counter: Metric, Histogram: Metric, Gauge: Metric, collectDefaultMetrics() {} },
  ioredis: class { on() { return this; } },
  '../db/redis': { redis: { async set(k, v) { memory.set(k, v); return 'OK'; }, async getdel(k) { const v = memory.get(k) ?? null; memory.delete(k); return v; } } },
};
const PHRASE = ['legal', 'winner', 'thank', 'year', 'wave', 'sausage', 'worth', 'useful', 'legal', 'winner', 'thank', 'yellow'];
const OTHER = ['wave', 'sausage', 'worth', 'useful', 'legal', 'winner', 'thank', 'year', 'legal', 'winner', 'thank', 'yellow'];
const keyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), publicKey };
};

describe('recovery phrase is single use, and failures are limited per identity (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let admin; let s; let hsm; const clientId = `bank-${randomBytes(4).toString('hex')}`;

  before(async () => {
    db = await createDatabase();
    process.env.DATABASE_URL = db.url;
    process.env.DEVICE_SECRET_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
    const cache = new Map();
    s = {
      credentials: loadTs('services/credentialService.ts', { stubs, cache }),
      recovery: loadTs('services/recoveryService.ts', { stubs, cache }),
      identities: loadTs('services/nexusIdentityService.ts', { stubs, cache }),
      db: loadTs('db/pool.ts', { stubs, cache }),
    };
    const { SoftwareHsmAdapter } = loadTs('crypto/softwareHsmAdapter.ts', { stubs, cache });
    hsm = new SoftwareHsmAdapter();
    loadTs('services/credentialIntegrity.ts', { stubs, cache }).configureEvidenceKeyring?.(hsm);
    admin = new pg.Client({ connectionString: db.url });
    await admin.connect();
    await admin.query(`INSERT INTO bank_clients (client_id, client_secret_hash) VALUES ($1, 'x')`, [clientId]);
  });
  after(async () => { await s?.db.pool.end(); await admin?.end(); await db?.drop(); });

  async function setUp(device, words) {
    const parameters = await s.recovery.beginRecoverySetup(device.nexusId, clientId, device.credentialId);
    const key = createRecoveryKey(words, parameters.salt, parameters.iterations, device.nexusId);
    const signatureB64 = signDerB64(device.signing.privateKey, setupSigningInput({
      nexusId: device.nexusId, credentialId: device.credentialId, saltB64: parameters.salt, recoveryPublicKey: key.publicKey, wrapped: key.wrapped,
    }));
    const credential = await s.credentials.getCredentialForClient(device.credentialId, clientId);
    await s.recovery.completeRecoverySetup({
      nexusId: device.nexusId, clientId, credential, saltB64: parameters.salt, recoveryPublicKeyPem: key.publicKeyPem,
      wrappedRecoveryKeyB64: key.wrapped.toString('base64'), signatureB64, hsm,
    });
  }

  async function recover(bankCustomerRef, words) {
    const session = await s.recovery.createRecoverySession(bankCustomerRef, clientId);
    const signing = keyPair();
    const proofB64 = signDerB64(openRecoveryKey(words, { ...session, salt: session.parameters.salt, iterations: session.parameters.iterations }), proofSigningInput({
      sessionId: session.sessionId, nonceB64: session.nonce, nexusId: session.nexusId, newSigningPublicKey: signing.publicKey,
    }));
    const result = await s.recovery.completeRecovery({
      sessionId: session.sessionId, accessToken: session.accessToken, proofB64, newPublicKeyPem: signing.publicKeyPem,
      platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', attestationStatus: 'UNKNOWN', attestation: { status: 'UNKNOWN', bindingSha256: null, material: { format: 'none' } }, hsm,
    });
    return { nexusId: result.nexusId, credentialId: result.credentialId, signing };
  }

  test('after a recovery the same phrase is refused until the recovered device sets up a new one', async () => {
    const bankCustomerRef = `cust-${randomBytes(4).toString('hex')}`;
    const identity = await s.identities.createNexusIdentity(clientId, bankCustomerRef);
    const signing = keyPair();
    const enrolled = await s.credentials.createCredential({
      nexusId: identity.nexusId, publicKeyPem: signing.publicKeyPem, platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', attestationStatus: 'VERIFIED', clientId, hsm,
      enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    const device = { nexusId: identity.nexusId, credentialId: enrolled.credentialId, signing };
    await setUp(device, PHRASE);

    const recovered = await recover(bankCustomerRef, PHRASE);
    const states = (await admin.query(`SELECT credential_id, state FROM credentials WHERE nexus_id = $1`, [identity.nexusId])).rows;
    assert.deepEqual(states.filter((r) => r.state === 'ACTIVE').map((r) => r.credential_id), [recovered.credentialId]);

    // The phished phrase cannot take the identity back.
    await assert.rejects(s.recovery.createRecoverySession(bankCustomerRef, clientId), (e) => e.code === 'RECOVERY_PHRASE_USED');

    // A new phrase set up on the recovered device works, once.
    await setUp(recovered, OTHER);
    const again = await recover(bankCustomerRef, OTHER);
    assert.notEqual(again.credentialId, recovered.credentialId);
    await assert.rejects(s.recovery.createRecoverySession(bankCustomerRef, clientId), (e) => e.code === 'RECOVERY_PHRASE_USED');
  });

  test('a session opened before the recovery cannot complete after it', async () => {
    const bankCustomerRef = `cust-${randomBytes(4).toString('hex')}`;
    const identity = await s.identities.createNexusIdentity(clientId, bankCustomerRef);
    const signing = keyPair();
    const enrolled = await s.credentials.createCredential({
      nexusId: identity.nexusId, publicKeyPem: signing.publicKeyPem, platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', attestationStatus: 'VERIFIED', clientId, hsm,
      enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    await setUp({ nexusId: identity.nexusId, credentialId: enrolled.credentialId, signing }, PHRASE);
    const early = await s.recovery.createRecoverySession(bankCustomerRef, clientId);
    await recover(bankCustomerRef, PHRASE);
    const next = keyPair();
    const proofB64 = signDerB64(openRecoveryKey(PHRASE, { ...early, salt: early.parameters.salt, iterations: early.parameters.iterations }), proofSigningInput({
      sessionId: early.sessionId, nonceB64: early.nonce, nexusId: early.nexusId, newSigningPublicKey: next.publicKey,
    }));
    await assert.rejects(s.recovery.completeRecovery({
      sessionId: early.sessionId, accessToken: early.accessToken, proofB64, newPublicKeyPem: next.publicKeyPem,
      platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', attestationStatus: 'UNKNOWN', attestation: { status: 'UNKNOWN', bindingSha256: null, material: { format: 'none' } }, hsm,
    }), (e) => e.code === 'RECOVERY_PHRASE_USED');
  });

  test('sessions opened in parallel share the limit of 10 failed proofs per identity (finding A2-04)', async () => {
    const bankCustomerRef = `cust-${randomBytes(4).toString('hex')}`;
    const identity = await s.identities.createNexusIdentity(clientId, bankCustomerRef);
    const signing = keyPair();
    const enrolled = await s.credentials.createCredential({
      nexusId: identity.nexusId, publicKeyPem: signing.publicKeyPem, platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', attestationStatus: 'VERIFIED', clientId, hsm,
      enrolment: { reason: 'ENROLMENT', attestation: { status: 'VERIFIED', bindingSha256: null, material: { format: 'none' } } },
    });
    await setUp({ nexusId: identity.nexusId, credentialId: enrolled.credentialId, signing }, PHRASE);
    // Three sessions opened before any failure: each allows 5 attempts, 15 in all.
    const sessions = [];
    for (let i = 0; i < 3; i += 1) sessions.push(await s.recovery.createRecoverySession(bankCustomerRef, clientId));
    const attempt = (session, words) => {
      const next = keyPair();
      // words === null: a proof signed by a key that is not the recovery key.
      const signer = words === null ? keyPair().privateKey : openRecoveryKey(words, { ...session, salt: session.parameters.salt, iterations: session.parameters.iterations });
      const proofB64 = signDerB64(signer, proofSigningInput({
        sessionId: session.sessionId, nonceB64: session.nonce, nexusId: session.nexusId, newSigningPublicKey: next.publicKey,
      }));
      return s.recovery.completeRecovery({
        sessionId: session.sessionId, accessToken: session.accessToken, proofB64, newPublicKeyPem: next.publicKeyPem,
        platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', attestationStatus: 'UNKNOWN', attestation: { status: 'UNKNOWN', bindingSha256: null, material: { format: 'none' } }, hsm,
      });
    };
    for (const [session, count] of [[sessions[0], 4], [sessions[1], 4], [sessions[2], 2]]) {
      for (let i = 0; i < count; i += 1) await assert.rejects(attempt(session, null), (e) => e.code !== 'RECOVERY_LOCKED');
    }
    // Ten failures in all: the third session still has attempts, but the identity is locked, even for the right phrase.
    await assert.rejects(attempt(sessions[2], PHRASE), (e) => e.code === 'RECOVERY_LOCKED');
    const active = (await admin.query(`SELECT credential_id FROM credentials WHERE nexus_id = $1 AND state = 'ACTIVE'`, [identity.nexusId])).rows;
    assert.deepEqual(active.map((r) => r.credential_id), [enrolled.credentialId], 'the enrolled device is untouched');
  });
});
