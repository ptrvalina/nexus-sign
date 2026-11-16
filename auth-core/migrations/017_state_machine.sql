-- 017: lifecycle state machines enforced by the database, and at
-- most one ACTIVE credential per identity.
--
-- The application already performs only these transitions; the triggers make
-- any other write (a defect, or a direct write by an application-role
-- session) fail instead of silently changing what was authorized. A database
-- owner can disable triggers; that is covered by the sealed evidence and the
-- runtime credential integrity check, not by these triggers.

-- Authorization lifecycle:
--   CREATED -> DELIVERING -> PENDING_USER -> VERIFIED -> CONSUMED
--   any non-final state -> EXPIRED | CANCELLED | REJECTED
-- The transaction it binds never changes; the signature fields change only on
-- the transition to VERIFIED. Bank transaction lifecycle of a VERIFIED
-- authorization: PENDING -> COMMIT_REQUESTED -> COMMITTED | FAILED | CANCELLED.
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
    allowed := CASE OLD.state
      WHEN 'CREATED'      THEN NEW.state IN ('DELIVERING','PENDING_USER','EXPIRED','CANCELLED','REJECTED')
      WHEN 'DELIVERING'   THEN NEW.state IN ('PENDING_USER','EXPIRED','CANCELLED','REJECTED')
      WHEN 'PENDING_USER' THEN NEW.state IN ('SIGNED','VERIFIED','EXPIRED','CANCELLED','REJECTED')
      WHEN 'SIGNED'       THEN NEW.state IN ('VERIFIED','EXPIRED','CANCELLED','REJECTED')
      WHEN 'VERIFIED'     THEN NEW.state = 'CONSUMED'
      ELSE FALSE
    END;
    IF NOT allowed THEN
      RAISE EXCEPTION 'authorization % : % -> % is not a permitted transition', OLD.authorization_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;

  IF (NEW.signature IS DISTINCT FROM OLD.signature
      OR NEW.signature_format IS DISTINCT FROM OLD.signature_format
      OR NEW.confirmation_method IS DISTINCT FROM OLD.confirmation_method
      OR NEW.verified_at IS DISTINCT FROM OLD.verified_at)
     AND NOT (NEW.state = 'VERIFIED' AND OLD.state IN ('PENDING_USER','SIGNED')) THEN
    RAISE EXCEPTION 'authorization % : signature fields are set once, on verification', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'VERIFIED' AND (NEW.signature IS NULL OR NEW.verified_at IS NULL) THEN
    RAISE EXCEPTION 'authorization % : VERIFIED needs a signature and verified_at', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.expires_at IS DISTINCT FROM OLD.expires_at AND OLD.state NOT IN ('CREATED','DELIVERING','PENDING_USER') THEN
    RAISE EXCEPTION 'authorization % : expiry of a final authorization is immutable', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  IF NEW.bank_transaction_state IS DISTINCT FROM OLD.bank_transaction_state THEN
    allowed := CASE OLD.bank_transaction_state
      WHEN 'PENDING'          THEN NEW.bank_transaction_state = 'COMMIT_REQUESTED' AND NEW.state IN ('VERIFIED','CONSUMED')
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
DROP TRIGGER IF EXISTS authorization_lifecycle ON authorization_requests;
CREATE TRIGGER authorization_lifecycle BEFORE UPDATE ON authorization_requests
  FOR EACH ROW EXECUTE FUNCTION authorization_lifecycle();

-- Credential lifecycle: PENDING -> ACTIVE -> SUSPENDED <-> ACTIVE, any -> REVOKED
-- (final). The keys of a credential never change, and its sealed enrolment
-- record is attached once.
CREATE OR REPLACE FUNCTION credential_lifecycle() RETURNS trigger AS $$
DECLARE
  allowed BOOLEAN;
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
  allowed := CASE OLD.state
      WHEN 'PENDING'   THEN NEW.state IN ('ACTIVE','REVOKED')
      WHEN 'ACTIVE'    THEN NEW.state IN ('SUSPENDED','REVOKED')
      WHEN 'SUSPENDED' THEN NEW.state IN ('ACTIVE','REVOKED')
      ELSE FALSE
    END;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT allowed THEN
    RAISE EXCEPTION 'credential % : % -> % is not a permitted transition', OLD.credential_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS credential_lifecycle ON credentials;
CREATE TRIGGER credential_lifecycle BEFORE UPDATE ON credentials
  FOR EACH ROW EXECUTE FUNCTION credential_lifecycle();

-- Identity lifecycle: ACTIVE <-> SUSPENDED, any -> REVOKED (final).
CREATE OR REPLACE FUNCTION identity_lifecycle() RETURNS trigger AS $$
DECLARE
  allowed BOOLEAN;
BEGIN
  IF NEW.nexus_id IS DISTINCT FROM OLD.nexus_id OR NEW.client_id IS DISTINCT FROM OLD.client_id
     OR NEW.bank_customer_ref IS DISTINCT FROM OLD.bank_customer_ref THEN
    RAISE EXCEPTION 'identity % : the bank binding is immutable', OLD.nexus_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.recovery_evidence_id IS NOT NULL AND NEW.recovery_evidence_id IS NULL THEN
    RAISE EXCEPTION 'identity % : the recovery configuration record cannot be detached', OLD.nexus_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  allowed := CASE OLD.status
      WHEN 'ACTIVE'    THEN NEW.status IN ('SUSPENDED','REVOKED')
      WHEN 'SUSPENDED' THEN NEW.status IN ('ACTIVE','REVOKED')
      ELSE FALSE
    END;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT allowed THEN
    RAISE EXCEPTION 'identity % : % -> % is not a permitted transition', OLD.nexus_id, OLD.status, NEW.status USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_lifecycle ON nexus_identities;
CREATE TRIGGER identity_lifecycle BEFORE UPDATE ON nexus_identities
  FOR EACH ROW EXECUTE FUNCTION identity_lifecycle();

-- Recovery sessions: attempt counters only grow, a session is used once, and
-- what it was issued for never changes, so the per-session and per-identity
-- recovery limits cannot be reset by rewriting rows.
CREATE OR REPLACE FUNCTION recovery_session_lifecycle() RETURNS trigger AS $$
BEGIN
  IF NEW.recovery_session_id IS DISTINCT FROM OLD.recovery_session_id OR NEW.nexus_id IS DISTINCT FROM OLD.nexus_id
     OR NEW.client_id IS DISTINCT FROM OLD.client_id OR NEW.nonce IS DISTINCT FROM OLD.nonce OR NEW.nonce_hash IS DISTINCT FROM OLD.nonce_hash
     OR NEW.kdf_salt IS DISTINCT FROM OLD.kdf_salt OR NEW.access_token_hash IS DISTINCT FROM OLD.access_token_hash
     OR NEW.protocol IS DISTINCT FROM OLD.protocol OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at > OLD.expires_at OR NEW.access_token_expires_at > OLD.access_token_expires_at THEN
    RAISE EXCEPTION 'recovery session % : issued fields are immutable', OLD.recovery_session_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.attempt_count < OLD.attempt_count OR NEW.failed_attempt_count < OLD.failed_attempt_count THEN
    RAISE EXCEPTION 'recovery session % : attempt counters only grow', OLD.recovery_session_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.used_at IS NOT NULL AND NEW.used_at IS DISTINCT FROM OLD.used_at THEN
    RAISE EXCEPTION 'recovery session % : a session is used once', OLD.recovery_session_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS recovery_session_lifecycle ON recovery_sessions;
CREATE TRIGGER recovery_session_lifecycle BEFORE UPDATE ON recovery_sessions
  FOR EACH ROW EXECUTE FUNCTION recovery_session_lifecycle();

-- Rows that carry security history are never deleted by the application:
-- removing recovery sessions would reset the per-identity recovery lockout,
-- removing approvals would hide who decided what, and identities, credentials
-- and authorizations are referenced by sealed evidence.
CREATE OR REPLACE FUNCTION refuse_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% rows are not deleted (% refused)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS recovery_sessions_no_delete ON recovery_sessions;
CREATE TRIGGER recovery_sessions_no_delete BEFORE DELETE ON recovery_sessions FOR EACH ROW EXECUTE FUNCTION refuse_delete();
DROP TRIGGER IF EXISTS admin_approvals_no_delete ON admin_approvals;
CREATE TRIGGER admin_approvals_no_delete BEFORE DELETE ON admin_approvals FOR EACH ROW EXECUTE FUNCTION refuse_delete();
DROP TRIGGER IF EXISTS credentials_no_delete ON credentials;
CREATE TRIGGER credentials_no_delete BEFORE DELETE ON credentials FOR EACH ROW EXECUTE FUNCTION refuse_delete();
DROP TRIGGER IF EXISTS identities_no_delete ON nexus_identities;
CREATE TRIGGER identities_no_delete BEFORE DELETE ON nexus_identities FOR EACH ROW EXECUTE FUNCTION refuse_delete();
DROP TRIGGER IF EXISTS authorizations_no_delete ON authorization_requests;
CREATE TRIGGER authorizations_no_delete BEFORE DELETE ON authorization_requests FOR EACH ROW EXECUTE FUNCTION refuse_delete();

-- One ACTIVE credential per identity. An upgrade stops here, naming the
-- identities, if existing data has more (resolve by revoking the extra
-- credentials before applying this migration).
DO $$
DECLARE duplicates TEXT;
BEGIN
  SELECT string_agg(nexus_id, ', ') INTO duplicates FROM (
    SELECT nexus_id FROM credentials WHERE state = 'ACTIVE' GROUP BY nexus_id HAVING count(*) > 1 LIMIT 20) d;
  IF duplicates IS NOT NULL THEN
    RAISE EXCEPTION 'identities with more than one ACTIVE credential: % (revoke the extra credentials, then re-run)', duplicates;
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_one_active ON credentials(nexus_id) WHERE state = 'ACTIVE';
