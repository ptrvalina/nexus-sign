-- 022: offline confirmation v2, deferred device signature (FI-004). Re-runnable, additive.
--
-- An accepted offline code (an HMAC under a key Auth Core also holds) no
-- longer confirms an authorization by itself when OFFLINE_CONFIRMATION_MODE is
-- deferred_signature: the authorization becomes OFFLINE_PROVISIONAL until the
-- device uploads its ECDSA signature over the same canonical bytes, then
-- VERIFIED (confirmation_method OFFLINE_SIGNED), or OFFLINE_UNSIGNED when the
-- deadline passes. docs/protocol/offline-confirmation-v2-deferred-signature.md.
--
-- Also: policy_reference and policy_version are now part of the immutable
-- terms in the trigger (they are in the signed bytes).
--
-- Rolling Auth Core back below this version after OFFLINE_PROVISIONAL rows
-- exist is not supported: the older code does not know the states.

ALTER TABLE authorization_requests ALTER COLUMN state TYPE VARCHAR(24);
ALTER TABLE authorization_requests DROP CONSTRAINT IF EXISTS authorization_requests_state_check;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_state_check
  CHECK (state IN ('PENDING_USER','VERIFIED','EXPIRED','CANCELLED','REJECTED','OFFLINE_PROVISIONAL','OFFLINE_UNSIGNED'));
ALTER TABLE authorization_requests DROP CONSTRAINT IF EXISTS authorization_requests_confirmation_method_check;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_confirmation_method_check
  CHECK (confirmation_method IS NULL OR confirmation_method IN ('DEVICE_SIGNATURE','OFFLINE_CODE','OFFLINE_SIGNED'));
-- base64 HMAC tag of the accepted code, when it was accepted, and (v2) until
-- when the device signature may arrive.
ALTER TABLE authorization_requests ADD COLUMN IF NOT EXISTS offline_code_tag TEXT;
ALTER TABLE authorization_requests ADD COLUMN IF NOT EXISTS offline_code_accepted_at TIMESTAMPTZ;
ALTER TABLE authorization_requests ADD COLUMN IF NOT EXISTS offline_signature_deadline TIMESTAMPTZ;
-- OFFLINE_UNSIGNED: deadline | credential_not_active | identity_not_active.
ALTER TABLE authorization_requests ADD COLUMN IF NOT EXISTS offline_unsigned_reason VARCHAR(32);
CREATE INDEX IF NOT EXISTS idx_auth_offline_provisional
    ON authorization_requests(offline_signature_deadline) WHERE state = 'OFFLINE_PROVISIONAL';
CREATE INDEX IF NOT EXISTS idx_auth_offline_accepted
    ON authorization_requests(credential_id, offline_code_accepted_at) WHERE offline_code_accepted_at IS NOT NULL;

-- The device's ECDSA signature over the canonical bytes, uploaded after an
-- offline confirmation; at most one per authorization, never changed.
CREATE TABLE IF NOT EXISTS offline_deferred_signatures (
    authorization_id           UUID PRIMARY KEY REFERENCES authorization_requests(authorization_id),
    credential_id              UUID NOT NULL REFERENCES credentials(credential_id),
    signature                  TEXT NOT NULL,
    signature_format           VARCHAR(8) NOT NULL CHECK (signature_format IN ('der','raw')),
    received_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION offline_deferred_signatures_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'offline_deferred_signatures is append-only (% rejected)', TG_OP USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_offline_deferred_signatures_append_only ON offline_deferred_signatures;
CREATE TRIGGER trg_offline_deferred_signatures_append_only BEFORE UPDATE OR DELETE ON offline_deferred_signatures
  FOR EACH ROW EXECUTE FUNCTION offline_deferred_signatures_append_only();

-- Authorization lifecycle (migrations 017, 018, 022):
--   PENDING_USER -> VERIFIED | EXPIRED | CANCELLED | REJECTED | OFFLINE_PROVISIONAL
--   OFFLINE_PROVISIONAL -> VERIFIED | OFFLINE_UNSIGNED
-- VERIFIED, EXPIRED, CANCELLED, REJECTED and OFFLINE_UNSIGNED are final. The
-- transaction it binds never changes; the signature fields change only on the
-- transition to VERIFIED and the offline code fields only when a code is
-- accepted. Bank transaction lifecycle of a VERIFIED authorization:
-- PENDING -> COMMIT_REQUESTED -> COMMITTED | FAILED | CANCELLED.
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
     OR NEW.policy_reference IS DISTINCT FROM OLD.policy_reference
     OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
     OR NEW.canonical_payload_hash IS DISTINCT FROM OLD.canonical_payload_hash
     OR NEW.nonce IS DISTINCT FROM OLD.nonce
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'authorization % : the authorized transaction is immutable', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  IF NEW.state IS DISTINCT FROM OLD.state THEN
    allowed := (OLD.state = 'PENDING_USER' AND NEW.state IN ('VERIFIED','EXPIRED','CANCELLED','REJECTED','OFFLINE_PROVISIONAL'))
            OR (OLD.state = 'OFFLINE_PROVISIONAL' AND NEW.state IN ('VERIFIED','OFFLINE_UNSIGNED'));
    IF NOT allowed THEN
      RAISE EXCEPTION 'authorization % : % -> % is not a permitted transition', OLD.authorization_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;

  IF (NEW.signature IS DISTINCT FROM OLD.signature
      OR NEW.signature_format IS DISTINCT FROM OLD.signature_format
      OR NEW.confirmation_method IS DISTINCT FROM OLD.confirmation_method
      OR NEW.verified_at IS DISTINCT FROM OLD.verified_at)
     AND NOT (NEW.state = 'VERIFIED' AND OLD.state IN ('PENDING_USER','OFFLINE_PROVISIONAL')) THEN
    RAISE EXCEPTION 'authorization % : signature fields are set once, on verification', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'VERIFIED' AND (NEW.signature IS NULL OR NEW.verified_at IS NULL) THEN
    RAISE EXCEPTION 'authorization % : VERIFIED needs a signature and verified_at', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  -- The accepted offline code: written once, when the code is accepted.
  IF (NEW.offline_code_tag IS DISTINCT FROM OLD.offline_code_tag
      OR NEW.offline_code_accepted_at IS DISTINCT FROM OLD.offline_code_accepted_at
      OR NEW.offline_signature_deadline IS DISTINCT FROM OLD.offline_signature_deadline)
     AND NOT (OLD.state = 'PENDING_USER' AND NEW.state IN ('VERIFIED','OFFLINE_PROVISIONAL')
              AND OLD.offline_code_tag IS NULL AND OLD.offline_code_accepted_at IS NULL AND OLD.offline_signature_deadline IS NULL) THEN
    RAISE EXCEPTION 'authorization % : the offline code fields are set once, when the code is accepted', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'OFFLINE_PROVISIONAL'
     AND (NEW.offline_code_tag IS NULL OR NEW.offline_code_accepted_at IS NULL OR NEW.offline_signature_deadline IS NULL) THEN
    RAISE EXCEPTION 'authorization % : OFFLINE_PROVISIONAL needs the accepted code and its signature deadline', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.confirmation_method = 'OFFLINE_SIGNED' AND NEW.offline_code_tag IS NULL THEN
    RAISE EXCEPTION 'authorization % : OFFLINE_SIGNED needs the accepted code', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.offline_unsigned_reason IS DISTINCT FROM OLD.offline_unsigned_reason
     AND NOT (OLD.state = 'OFFLINE_PROVISIONAL' AND NEW.state = 'OFFLINE_UNSIGNED') THEN
    RAISE EXCEPTION 'authorization % : the unsigned reason is set once, on OFFLINE_UNSIGNED', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'OFFLINE_UNSIGNED' AND NEW.offline_unsigned_reason IS NULL THEN
    RAISE EXCEPTION 'authorization % : OFFLINE_UNSIGNED needs a reason', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
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
DROP TRIGGER IF EXISTS authorization_lifecycle ON authorization_requests;
CREATE TRIGGER authorization_lifecycle BEFORE UPDATE ON authorization_requests
  FOR EACH ROW EXECUTE FUNCTION authorization_lifecycle();
