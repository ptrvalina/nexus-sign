import { pool, withTransaction } from '../db/pool';
import { redis } from '../db/redis';
import { selectHsmAdapter } from '../crypto/selectHsmAdapter';
import { configureEvidenceKeyring } from '../services/credentialIntegrity';
import { sealCredentialEnrolment } from '../services/evidenceService';
import { recordAuditEvent } from '../services/auditService';

/**
 * One-time upgrade step to evidence schema 3 (migration 013): seals a
 * CREDENTIAL_ENROLLED record, reason BASELINE, for every credential enrolled
 * before the upgrade. Auth Core refuses to use a credential's keys without a
 * sealed enrolment, so run this right after the migration, before traffic.
 *
 * A baseline record states the keys the database held when it ran; it cannot
 * prove how they got there (they were enrolled before enrolments were
 * sealed). Run it in the controlled upgrade window, and keep the run's
 * output with the change record.
 *
 * Usage: node dist/cli/sealCredentialBaseline.js
 */
async function main(): Promise<void> {
  const hsm = await selectHsmAdapter();
  await hsm.healthCheck();
  configureEvidenceKeyring(hsm);
  const pending = await pool.query<{ credential_id: string; nexus_id: string; platform: string; security_level: string; attestation_status: 'UNKNOWN' | 'VERIFIED' | 'FAILED' | 'EXPIRED'; public_key_pem: string; auth_public_key_pem: string | null; offline_public_key_pem: string | null }>(
    `SELECT credential_id, nexus_id, platform, security_level, attestation_status, public_key_pem, auth_public_key_pem, offline_public_key_pem
     FROM credentials WHERE enrolment_evidence_id IS NULL AND state = 'ACTIVE' ORDER BY created_at`);
  for (const c of pending.rows) {
    await withTransaction(async (tx) => {
      const locked = await tx.query(`SELECT 1 FROM credentials WHERE credential_id = $1 AND enrolment_evidence_id IS NULL FOR UPDATE`, [c.credential_id]);
      if (!locked.rows[0]) return;
      const position = await sealCredentialEnrolment(tx, hsm, {
        nexusId: c.nexus_id,
        credentialId: c.credential_id,
        reason: 'BASELINE',
        platform: c.platform,
        securityLevel: c.security_level,
        signingPublicKeyPem: c.public_key_pem,
        authPublicKeyPem: c.auth_public_key_pem,
        offlinePublicKeyPem: c.offline_public_key_pem,
        attestation: { status: c.attestation_status, bindingSha256: null, material: { format: 'none', note: 'enrolled before evidence schema 3' } },
        replacedCredentialIds: [],
        replacementAuthorization: null,
      });
      await recordAuditEvent('credential_baseline_sealed', { nexusId: c.nexus_id, actor: 'cli:sealCredentialBaseline' },
        { credentialId: c.credential_id, chainSequence: position.chainSequence, evidenceHash: position.evidenceHash }, tx);
      console.log(`sealed ${c.credential_id} (NEXUS ID ${c.nexus_id}) at chain position ${position.chainSequence}: ${position.evidenceHash}`);
    });
  }
  console.log(`Baseline complete: ${pending.rows.length} credential(s) sealed.`);
  await hsm.close?.();
}

main()
  .catch((error: unknown) => {
    console.error('Baseline sealing failed:', error);
    process.exitCode = 1;
  })
  .finally(() => {
    void pool.end();
    redis.disconnect();
  });
