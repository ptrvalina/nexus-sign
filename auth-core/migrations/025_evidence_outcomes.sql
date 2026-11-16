-- Evidence for every outcome, not only confirmations (audit finding B-04).
--
-- A declined, rejected, expired, cancelled or unsigned authorization, and a
-- revoked credential, are recorded in evidence_outcomes by a trigger in the
-- same transaction as the state change, so no code path can change the state
-- without the record. A worker then seals each outcome into the NEXUS ID's
-- evidence chain with the HSM (record types AUTHORIZATION_OUTCOME and
-- CREDENTIAL_REVOKED) and links the row to that record, once.

ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS evidence_records_record_type_check;
ALTER TABLE evidence_records ADD CONSTRAINT evidence_records_record_type_check
  CHECK (record_type IN ('AUTHORIZATION','CREDENTIAL_ENROLLED','RECOVERY_CONFIGURED','AUTHORIZATION_OUTCOME','CREDENTIAL_REVOKED'));
ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS evidence_records_outcome_fields_check;
ALTER TABLE evidence_records ADD CONSTRAINT evidence_records_outcome_fields_check
  CHECK (record_type <> 'AUTHORIZATION_OUTCOME' OR (authorization_id IS NOT NULL AND transaction_reference IS NOT NULL
         AND canonical_payload_hash IS NOT NULL AND result IS NOT NULL));

CREATE TABLE IF NOT EXISTS evidence_outcomes (
    outcome_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject                    VARCHAR(16) NOT NULL CHECK (subject IN ('AUTHORIZATION','CREDENTIAL')),
    authorization_id           UUID REFERENCES authorization_requests(authorization_id),
    credential_id              UUID NOT NULL REFERENCES credentials(credential_id),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    outcome                    VARCHAR(24) NOT NULL
                               CHECK (outcome IN ('REJECTED','EXPIRED','CANCELLED','OFFLINE_UNSIGNED','REVOKED')),
    reason                     VARCHAR(64) NOT NULL,
    occurred_at                TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    evidence_id                UUID UNIQUE REFERENCES evidence_records(evidence_id),
    sealed_at                  TIMESTAMPTZ,
    CHECK ((subject = 'AUTHORIZATION') = (authorization_id IS NOT NULL)),
    CHECK ((evidence_id IS NULL) = (sealed_at IS NULL))
);
-- One outcome per authorization (its final state) and per credential revocation.
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_outcomes_authorization ON evidence_outcomes(authorization_id) WHERE subject = 'AUTHORIZATION';
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_outcomes_credential ON evidence_outcomes(credential_id) WHERE subject = 'CREDENTIAL';
CREATE INDEX IF NOT EXISTS idx_evidence_outcomes_unsealed ON evidence_outcomes(occurred_at) WHERE evidence_id IS NULL;

-- Rows are never deleted; only evidence_id and sealed_at change, once.
CREATE OR REPLACE FUNCTION evidence_outcomes_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'evidence_outcomes rows are kept (DELETE refused)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.evidence_id IS NOT NULL
     OR (NEW.outcome_id, NEW.subject, NEW.authorization_id, NEW.credential_id, NEW.nexus_id, NEW.outcome, NEW.reason, NEW.occurred_at)
        IS DISTINCT FROM (OLD.outcome_id, OLD.subject, OLD.authorization_id, OLD.credential_id, OLD.nexus_id, OLD.outcome, OLD.reason, OLD.occurred_at) THEN
    RAISE EXCEPTION 'evidence outcome %: only the sealing record is set, once', OLD.outcome_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_outcomes_guard ON evidence_outcomes;
CREATE TRIGGER evidence_outcomes_guard BEFORE UPDATE OR DELETE ON evidence_outcomes
  FOR EACH ROW EXECUTE FUNCTION evidence_outcomes_guard();
DROP TRIGGER IF EXISTS evidence_outcomes_no_truncate ON evidence_outcomes;
CREATE TRIGGER evidence_outcomes_no_truncate BEFORE TRUNCATE ON evidence_outcomes
  FOR EACH STATEMENT EXECUTE FUNCTION nexus_evidence_append_only();

-- The reason comes from the transaction that changed the state
-- (set_config('nexus.outcome_reason', ..., true)), or a default per state.
CREATE OR REPLACE FUNCTION record_authorization_outcome() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE given TEXT := nullif(current_setting('nexus.outcome_reason', true), '');
BEGIN
  IF NEW.state IN ('REJECTED','EXPIRED','CANCELLED','OFFLINE_UNSIGNED') AND NEW.state IS DISTINCT FROM OLD.state THEN
    INSERT INTO evidence_outcomes (subject, authorization_id, credential_id, nexus_id, outcome, reason)
    VALUES ('AUTHORIZATION', NEW.authorization_id, NEW.credential_id, NEW.nexus_id, NEW.state,
            left(coalesce(given, CASE NEW.state WHEN 'OFFLINE_UNSIGNED' THEN coalesce(NEW.offline_unsigned_reason, 'offline_unsigned')
                                                WHEN 'EXPIRED' THEN 'expired'
                                                WHEN 'CANCELLED' THEN 'cancelled'
                                                ELSE 'rejected' END), 64));
  END IF;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS authorization_outcome_evidence ON authorization_requests;
CREATE TRIGGER authorization_outcome_evidence AFTER UPDATE ON authorization_requests
  FOR EACH ROW EXECUTE FUNCTION record_authorization_outcome();

CREATE OR REPLACE FUNCTION record_credential_revocation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.state = 'REVOKED' AND OLD.state IS DISTINCT FROM 'REVOKED' THEN
    INSERT INTO evidence_outcomes (subject, credential_id, nexus_id, outcome, reason)
    VALUES ('CREDENTIAL', NEW.credential_id, NEW.nexus_id, 'REVOKED',
            left(coalesce(nullif(current_setting('nexus.outcome_reason', true), ''), 'revoked'), 64));
  END IF;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS credential_revocation_evidence ON credentials;
CREATE TRIGGER credential_revocation_evidence AFTER UPDATE ON credentials
  FOR EACH ROW EXECUTE FUNCTION record_credential_revocation();
