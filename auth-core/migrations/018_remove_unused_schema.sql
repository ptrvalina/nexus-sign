-- 018: removes schema that Auth Core never used (2.0.0-rc.2).
--
-- - Tables attestation_records and policy_decisions: never written or read.
-- - Authorization states CREATED, DELIVERING, SIGNED and CONSUMED: an
--   authorization is created in PENDING_USER and ends in VERIFIED, EXPIRED,
--   CANCELLED or REJECTED.
-- - Credential states PENDING and SUSPENDED: a credential is created ACTIVE
--   and ends REVOKED; suspension is a state of the identity, not of a key.
-- - nexus_identities.recovery_verifier: recovery protocol 1 verifiers, which
--   work as passwords (NXS-003). Protocol 1 is no longer accepted; identities
--   still on it are refused with RECOVERY_PROTOCOL_RETIRED and set up a new
--   phrase, so the stored verifiers have no remaining use.
--
-- The migration stops, naming the rows, if existing data uses anything it
-- removes. Resolve those rows first (revoke such credentials; an operator
-- decides about rows in the two tables), then re-run.

DO $$
DECLARE
  found TEXT;
  rows_present BOOLEAN;
  dead_table TEXT;
BEGIN
  FOREACH dead_table IN ARRAY ARRAY['attestation_records', 'policy_decisions'] LOOP
    IF to_regclass(dead_table) IS NOT NULL THEN
      EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I)', dead_table) INTO rows_present;
      IF rows_present THEN
        RAISE EXCEPTION '% is not empty; Auth Core never wrote it. Export the rows if they are needed, empty the table, then re-run', dead_table;
      END IF;
    END IF;
  END LOOP;
  SELECT string_agg(authorization_id::text || ' (' || state || ')', ', ') INTO found FROM (
    SELECT authorization_id, state FROM authorization_requests
    WHERE state IN ('CREATED','DELIVERING','SIGNED','CONSUMED') LIMIT 20) a;
  IF found IS NOT NULL THEN
    RAISE EXCEPTION 'authorizations in a state that no longer exists: %', found;
  END IF;
  SELECT string_agg(credential_id::text || ' (' || state || ')', ', ') INTO found FROM (
    SELECT credential_id, state FROM credentials WHERE state IN ('PENDING','SUSPENDED') LIMIT 20) c;
  IF found IS NOT NULL THEN
    RAISE EXCEPTION 'credentials in a state that no longer exists: % (revoke them, then re-run)', found;
  END IF;
END $$;

DROP TABLE IF EXISTS attestation_records;
DROP TABLE IF EXISTS policy_decisions;

ALTER TABLE authorization_requests DROP CONSTRAINT IF EXISTS authorization_requests_state_check;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_state_check
  CHECK (state IN ('PENDING_USER','VERIFIED','EXPIRED','CANCELLED','REJECTED'));
ALTER TABLE authorization_requests ALTER COLUMN state SET DEFAULT 'PENDING_USER';

ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_state_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_state_check CHECK (state IN ('ACTIVE','REVOKED'));
ALTER TABLE credentials ALTER COLUMN state SET DEFAULT 'ACTIVE';
ALTER TABLE credentials DROP COLUMN IF EXISTS suspended_at;

ALTER TABLE nexus_identities DROP COLUMN IF EXISTS recovery_verifier;

-- Authorization lifecycle: PENDING_USER -> VERIFIED | EXPIRED | CANCELLED |
-- REJECTED, all final. Otherwise unchanged from 017.
CREATE OR REPLACE FUNCTION authorization_lifecycle() RETURNS trigger AS $$
DECLARE
  allowed BOOLEAN;
BEGIN
  IF NEW.authorization_id IS DISTINCT FROM OLD.authorization_id
     OR NEW.client_id IS DISTINCT FROM OLD.client_id
     OR NEW.nexus_id IS DISTINCT FROM OLD.nexus_id
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.transaction_reference IS DISTINCT FROM OLD.transaction_reference
     OR NEW.operation_type IS DISTINCT FROM OLD.operation_type
     OR NEW.amount_minor IS DISTINCT FROM OLD.amount_minor
     OR NEW.currency IS DISTINCT FROM OLD.currency
     OR NEW.beneficiary IS DISTINCT FROM OLD.beneficiary
     OR NEW.canonical_payload_hash IS DISTINCT FROM OLD.canonical_payload_hash
     OR NEW.nonce IS DISTINCT FROM OLD.nonce
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'authorization % : the authorized transaction is immutable', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  IF NEW.state IS DISTINCT FROM OLD.state THEN
    allowed := OLD.state = 'PENDING_USER' AND NEW.state IN ('VERIFIED','EXPIRED','CANCELLED','REJECTED');
    IF NOT allowed THEN
      RAISE EXCEPTION 'authorization % : % -> % is not a permitted transition', OLD.authorization_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;

  IF (NEW.signature IS DISTINCT FROM OLD.signature
      OR NEW.signature_format IS DISTINCT FROM OLD.signature_format
      OR NEW.confirmation_method IS DISTINCT FROM OLD.confirmation_method
      OR NEW.verified_at IS DISTINCT FROM OLD.verified_at)
     AND NOT (NEW.state = 'VERIFIED' AND OLD.state = 'PENDING_USER') THEN
    RAISE EXCEPTION 'authorization % : signature fields are set once, on verification', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'VERIFIED' AND (NEW.signature IS NULL OR NEW.verified_at IS NULL) THEN
    RAISE EXCEPTION 'authorization % : VERIFIED needs a signature and verified_at', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.expires_at IS DISTINCT FROM OLD.expires_at AND OLD.state <> 'PENDING_USER' THEN
    RAISE EXCEPTION 'authorization % : expiry of a final authorization is immutable', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  IF NEW.bank_transaction_state IS DISTINCT FROM OLD.bank_transaction_state THEN
    allowed := CASE OLD.bank_transaction_state
      WHEN 'PENDING'          THEN NEW.bank_transaction_state = 'COMMIT_REQUESTED' AND NEW.state = 'VERIFIED'
      WHEN 'COMMIT_REQUESTED' THEN NEW.bank_transaction_state IN ('COMMITTED','FAILED','CANCELLED')
      ELSE FALSE
    END;
    IF NOT allowed THEN
      RAISE EXCEPTION 'authorization % : bank transaction % -> % is not a permitted transition', OLD.authorization_id, OLD.bank_transaction_state, NEW.bank_transaction_state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSIF NEW.bank_transaction_reference IS DISTINCT FROM OLD.bank_transaction_reference THEN
    RAISE EXCEPTION 'authorization % : the bank transaction reference is set with the commit request', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Credential lifecycle: ACTIVE -> REVOKED (final). Otherwise unchanged from 017.
CREATE OR REPLACE FUNCTION credential_lifecycle() RETURNS trigger AS $$
BEGIN
  IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.nexus_id IS DISTINCT FROM OLD.nexus_id
     OR NEW.key_algorithm IS DISTINCT FROM OLD.key_algorithm
     OR NEW.public_key_pem IS DISTINCT FROM OLD.public_key_pem
     OR NEW.auth_public_key_pem IS DISTINCT FROM OLD.auth_public_key_pem
     OR NEW.offline_public_key_pem IS DISTINCT FROM OLD.offline_public_key_pem
     OR NEW.offline_server_public_key_pem IS DISTINCT FROM OLD.offline_server_public_key_pem
     OR NEW.offline_secret_encrypted IS DISTINCT FROM OLD.offline_secret_encrypted
     OR NEW.platform IS DISTINCT FROM OLD.platform
     OR NEW.key_version IS DISTINCT FROM OLD.key_version THEN
    RAISE EXCEPTION 'credential % : keys and identity binding are immutable', OLD.credential_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.enrolment_evidence_id IS NOT NULL AND NEW.enrolment_evidence_id IS DISTINCT FROM OLD.enrolment_evidence_id THEN
    RAISE EXCEPTION 'credential % : the enrolment record is attached once', OLD.credential_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (OLD.state = 'ACTIVE' AND NEW.state = 'REVOKED') THEN
    RAISE EXCEPTION 'credential % : % -> % is not a permitted transition', OLD.credential_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
