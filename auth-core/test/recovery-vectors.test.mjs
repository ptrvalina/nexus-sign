import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, createPublicKey, hkdfSync, pbkdf2Sync, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { loadTs } from './support/load-ts.mjs';

const stubs = {
  '../db/pool': { pool: {}, withTransaction: async () => { throw new Error('no database in unit tests'); } },
  '../db/redis': { redis: {} },
};
const service = loadTs('services/recoveryService.ts', { stubs });
const original = readFileSync(new URL('../test-vectors/recovery-v2.json', import.meta.url), 'utf8');
const v = JSON.parse(original);
const spki = (pem) => createPublicKey(pem).export({ type: 'spki', format: 'der' });

test('Auth Core builds the same recovery v2 signing inputs and associated data as the vectors', () => {
  const recoverySpki = spki(v.recovery_public_key_pem);
  assert.equal(service.recoveryWrapAssociatedData(v.nexus_id, recoverySpki).toString('utf8'), v.wrap_aad_utf8);
  assert.equal(service.recoverySetupSigningInput({
    nexusId: v.nexus_id, credentialId: v.credential_id, saltB64: v.salt_b64, recoveryPublicKeySpki: recoverySpki,
    wrappedRecoveryKey: Buffer.from(v.wrapped_recovery_key_b64, 'base64'),
  }).toString('utf8'), v.setup_signing_input_utf8);
  const input = service.recoveryProofSigningInput({
    sessionId: v.proof.session_id, nonceB64: v.proof.nonce_b64, nexusId: v.nexus_id, newSigningKeySpki: spki(v.proof.new_signing_public_key_pem),
  });
  assert.equal(input.toString('utf8'), v.proof.signing_input_utf8);
  assert.ok(verify('sha256', input, v.recovery_public_key_pem, Buffer.from(v.proof.signature_der_b64, 'base64')));
  assert.equal(service.RECOVERY_WRAP_SALT, 'NEXUS-SIGN/RECOVERY-WRAP/v2');
});

test('the wrapped recovery key in the vectors opens with the phrase and nothing else', () => {
  const derive = (phrase, nexusId = v.nexus_id) => Buffer.from(hkdfSync('sha256', pbkdf2Sync(phrase.join(' '), Buffer.from(v.salt_b64, 'base64'), Number(v.iterations), 32, 'sha256'),
    Buffer.from(service.RECOVERY_WRAP_SALT), Buffer.from(nexusId), 32));
  const open = (key, aad = Buffer.from(v.wrap_aad_utf8)) => {
    const wrapped = Buffer.from(v.wrapped_recovery_key_b64, 'base64');
    const decipher = createDecipheriv('aes-256-gcm', key, wrapped.subarray(0, 12));
    decipher.setAAD(aad);
    decipher.setAuthTag(wrapped.subarray(wrapped.length - 16));
    return Buffer.concat([decipher.update(wrapped.subarray(12, wrapped.length - 16)), decipher.final()]);
  };
  assert.equal(derive(v.phrase).toString('hex'), v.wrap_key_hex);
  assert.equal(open(derive(v.phrase)).toString('hex'), v.recovery_private_scalar_hex);
  assert.equal(v.invalid.length, 2);
  for (const invalid of v.invalid) {
    if (invalid.phrase) {
      assert.throws(() => open(derive(invalid.phrase)), /unable to authenticate|auth/i, invalid.name);
    } else {
      // The right phrase, but the identity in the derivation and associated data is another one.
      assert.ok(invalid.nexus_id && invalid.nexus_id !== v.nexus_id, invalid.name);
      const aad = service.recoveryWrapAssociatedData(invalid.nexus_id, spki(v.recovery_public_key_pem));
      assert.throws(() => open(derive(v.phrase, invalid.nexus_id), aad), /unable to authenticate|auth/i, invalid.name);
      assert.throws(() => open(derive(v.phrase), aad), /unable to authenticate|auth/i, `${invalid.name} (associated data only)`);
    }
  }
});
