-- 009: evidence schema version 2 and schema alignment.
--
-- * evidence_records.sealed_payload stores the exact object whose canonical
--   JSON is hashed and sealed, so evidence can be re-verified offline
--   (docs/architecture/evidence-format.md, scripts/verify-evidence.mjs).
-- * evidence_records becomes append-only at the database level: UPDATE,
--   DELETE and TRUNCATE are rejected for every role, including the owner.
-- * Brings schema.sql and the migration chain to the same end state.

ALTER TABLE evidence_records ADD COLUMN IF NOT EXISTS sealed_payload JSONB;

CREATE OR REPLACE FUNCTION nexus_evidence_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'evidence_records is append-only (% rejected)', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_evidence_append_only ON evidence_records;
CREATE TRIGGER trg_evidence_append_only
  BEFORE UPDATE OR DELETE ON evidence_records
  FOR EACH ROW EXECUTE FUNCTION nexus_evidence_append_only();

DROP TRIGGER IF EXISTS trg_evidence_no_truncate ON evidence_records;
CREATE TRIGGER trg_evidence_no_truncate
  BEFORE TRUNCATE ON evidence_records
  FOR EACH STATEMENT EXECUTE FUNCTION nexus_evidence_append_only();

CREATE INDEX IF NOT EXISTS idx_evidence_nexus_created ON evidence_records(nexus_id, created_at);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_authorization ON authorization_attempts(authorization_id, occurred_at);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'authorization_attempts_result_check') THEN
    ALTER TABLE authorization_attempts ADD CONSTRAINT authorization_attempts_result_check
      CHECK (result IN ('INVALID_SIGNATURE','VERIFIED','EXPIRED','REJECTED','CREDENTIAL_INVALID'));
  END IF;
END $$;

ALTER TABLE webhook_deliveries
  ADD COLUMN IF NOT EXISTS event_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS delivery_attempt_id UUID;
