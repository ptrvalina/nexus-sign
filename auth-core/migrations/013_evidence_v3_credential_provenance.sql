-- 013: evidence schema 3 (docs/adr/0009-evidence-v3-credential-provenance.md).
--
-- * evidence_records holds three record types in one chain per NEXUS ID:
--   AUTHORIZATION (as before), CREDENTIAL_ENROLLED (the keys of a credential
--   and the attestation that admitted them) and RECOVERY_CONFIGURED (the
--   recovery public key a device registered).
-- * chain_sequence numbers each chain from 1, sealed in schema 3 records, so
--   a missing record or a fork is visible; seal_key_id names the HSM key.
-- * credentials.enrolment_evidence_id and nexus_identities.recovery_evidence_id
--   point at the sealed record Auth Core checks the row against before use.

ALTER TABLE evidence_records ADD COLUMN IF NOT EXISTS record_type VARCHAR(32) NOT NULL DEFAULT 'AUTHORIZATION';
ALTER TABLE evidence_records ADD COLUMN IF NOT EXISTS chain_sequence BIGINT;
ALTER TABLE evidence_records ADD COLUMN IF NOT EXISTS seal_key_id CHAR(64);

ALTER TABLE evidence_records ALTER COLUMN authorization_id DROP NOT NULL;
ALTER TABLE evidence_records ALTER COLUMN transaction_reference DROP NOT NULL;
ALTER TABLE evidence_records ALTER COLUMN canonical_payload_hash DROP NOT NULL;
ALTER TABLE evidence_records ALTER COLUMN signature DROP NOT NULL;
ALTER TABLE evidence_records ALTER COLUMN signature_algorithm DROP NOT NULL;
ALTER TABLE evidence_records ALTER COLUMN key_version DROP NOT NULL;
ALTER TABLE evidence_records ALTER COLUMN policy_version DROP NOT NULL;
ALTER TABLE evidence_records ALTER COLUMN verified_at DROP NOT NULL;
ALTER TABLE evidence_records ALTER COLUMN result DROP NOT NULL;

ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS evidence_records_record_type_check;
ALTER TABLE evidence_records ADD CONSTRAINT evidence_records_record_type_check
    CHECK (record_type IN ('AUTHORIZATION','CREDENTIAL_ENROLLED','RECOVERY_CONFIGURED'));
ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS evidence_records_authorization_fields_check;
ALTER TABLE evidence_records ADD CONSTRAINT evidence_records_authorization_fields_check
    CHECK (record_type <> 'AUTHORIZATION' OR (authorization_id IS NOT NULL AND transaction_reference IS NOT NULL
           AND canonical_payload_hash IS NOT NULL AND signature IS NOT NULL AND verified_at IS NOT NULL));

-- Number the chains that exist. Evidence is append-only; this one-time
-- numbering of the new column is the only update the migration makes, with
-- the trigger disabled for this statement and enabled again in the same
-- transaction. Records sealed before schema 3 do not seal their number.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM evidence_records WHERE chain_sequence IS NULL) THEN
    ALTER TABLE evidence_records DISABLE TRIGGER trg_evidence_append_only;
    UPDATE evidence_records e SET chain_sequence = numbered.n
    FROM (SELECT evidence_id, row_number() OVER (PARTITION BY nexus_id ORDER BY created_at, evidence_id) AS n FROM evidence_records) numbered
    WHERE e.evidence_id = numbered.evidence_id AND e.chain_sequence IS NULL;
    ALTER TABLE evidence_records ENABLE TRIGGER trg_evidence_append_only;
  END IF;
END $$;
ALTER TABLE evidence_records ALTER COLUMN chain_sequence SET NOT NULL;

-- One record per position, one successor per record, one first record per chain.
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_chain_sequence ON evidence_records(nexus_id, chain_sequence);
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_chain_link ON evidence_records(nexus_id, previous_evidence_hash) WHERE previous_evidence_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_chain_genesis ON evidence_records(nexus_id) WHERE previous_evidence_hash IS NULL;
DROP INDEX IF EXISTS idx_evidence_nexus_created;

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS enrolment_evidence_id UUID REFERENCES evidence_records(evidence_id);
ALTER TABLE nexus_identities ADD COLUMN IF NOT EXISTS recovery_evidence_id UUID REFERENCES evidence_records(evidence_id);
