// Plays a fully compromised Auth Core: its own compiled code, run with its
// configuration (database owner, the evidence key in the HSM), outside every
// API check. Used to show what the bank can still detect on its own.
import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { ROOT } from './harness.mjs';

const SCRIPT = `
const { pool, withTransaction } = require(${JSON.stringify(join(ROOT, 'dist/db/pool.js'))});
const { selectHsmAdapter } = require(${JSON.stringify(join(ROOT, 'dist/crypto/selectHsmAdapter.js'))});
const { createCredential } = require(${JSON.stringify(join(ROOT, 'dist/services/credentialService.js'))});
const { sealCredentialEnrolment } = require(${JSON.stringify(join(ROOT, 'dist/services/evidenceService.js'))});
(async () => {
  const op = JSON.parse(process.argv[1]);
  const hsm = await selectHsmAdapter();
  let result;
  if (op.kind === 'enrol') {
    // Enrolment without a bank token, the bank's replacement authorization
    // invented, the customer's approval of it forged in the database (the
    // hold of audit finding A2-01 does not stop a compromised Auth Core),
    // attestation claimed as verified.
    const replacementId = require('node:crypto').randomUUID();
    // (Inside SCRIPT, itself a template literal: the SQL is a plain string.)
    await pool.query("INSERT INTO device_replacements (replacement_id, nexus_id, client_id, method, reference, state, not_before, expires_at) " +
      "VALUES ($1, $2, $3, 'OTHER', 'not-issued-by-the-bank', 'APPROVED', now() - interval '1 hour', now() + interval '1 hour')", [replacementId, op.nexusId, op.clientId]);
    const c = await createCredential({
      nexusId: op.nexusId, publicKeyPem: op.signingPublicKeyPem, platform: 'IOS', securityLevel: 'SECURE_ENCLAVE',
      attestationStatus: 'VERIFIED', clientId: op.clientId, replacement: { method: 'OTHER', reference: 'not-issued-by-the-bank', replacementId },
      deviceKeys: { authPublicKeyPem: op.authPublicKeyPem, offlinePublicKeyPem: op.offlinePublicKeyPem },
      hsm, enrolment: { reason: 'REPLACEMENT', attestation: { status: 'VERIFIED' } },
    });
    result = { credentialId: c.credentialId };
  } else if (op.kind === 'substitute-keys') {
    // The keys of an existing credential replaced, and a new enrolment record
    // sealed for them with the real evidence key.
    result = await withTransaction(async (tx) => {
      await tx.query('ALTER TABLE credentials DISABLE TRIGGER credential_lifecycle');
      await tx.query('UPDATE credentials SET public_key_pem = $2, auth_public_key_pem = $3, offline_public_key_pem = $4, enrolment_evidence_id = NULL WHERE credential_id = $1',
        [op.credentialId, op.signingPublicKeyPem, op.authPublicKeyPem, op.offlinePublicKeyPem]);
      const position = await sealCredentialEnrolment(tx, hsm, {
        nexusId: op.nexusId, credentialId: op.credentialId, reason: 'ENROLMENT', platform: 'IOS', securityLevel: 'SECURE_ENCLAVE',
        signingPublicKeyPem: op.signingPublicKeyPem, authPublicKeyPem: op.authPublicKeyPem, offlinePublicKeyPem: op.offlinePublicKeyPem,
        attestation: { status: 'VERIFIED' }, replacedCredentialIds: [], replacementAuthorization: null,
      });
      await tx.query('ALTER TABLE credentials ENABLE TRIGGER credential_lifecycle');
      return { evidenceId: position.evidenceId };
    });
  } else if (op.kind === 'seal-enrolment') {
    // A credential row and a sealed enrolment for it, next to the customer's
    // device and without touching it (no replacement, nothing revoked).
    result = await withTransaction(async (tx) => {
      const credentialId = require('node:crypto').randomUUID();
      await tx.query("INSERT INTO credentials (credential_id, nexus_id, key_algorithm, public_key_pem, platform, security_level, attestation_status, state, revoked_at, auth_public_key_pem) VALUES ($1, $2, 'ES256', $3, 'IOS', 'SECURE_ENCLAVE', 'VERIFIED', 'REVOKED', now(), $4)",
        [credentialId, op.nexusId, op.signingPublicKeyPem, op.authPublicKeyPem]);
      const position = await sealCredentialEnrolment(tx, hsm, {
        nexusId: op.nexusId, credentialId, reason: 'ENROLMENT', platform: 'IOS', securityLevel: 'SECURE_ENCLAVE',
        signingPublicKeyPem: op.signingPublicKeyPem, authPublicKeyPem: op.authPublicKeyPem, offlinePublicKeyPem: null,
        attestation: { status: 'VERIFIED' }, replacedCredentialIds: [], replacementAuthorization: null,
      });
      return { credentialId, evidenceId: position.evidenceId };
    });
  } else {
    throw new Error('unknown operation ' + op.kind);
  }
  await pool.end();
  await hsm.close?.();
  process.stdout.write(JSON.stringify(result));
  process.exit(0);
})().catch((e) => { console.error(e.stack || e.message); process.exit(1); });
`;

/** Runs one operation as the compromised Auth Core of `server`. */
export function asCompromisedAuthCore(server, op) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['-e', SCRIPT, JSON.stringify(op)], { env: server.env, cwd: ROOT, timeout: 30_000 }, (error, stdout, stderr) => {
      if (error) reject(new Error(`${error.message}\n${stderr}`));
      else resolve(JSON.parse(stdout));
    });
  });
}
