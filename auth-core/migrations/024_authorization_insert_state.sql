-- Authorizations are created PENDING_USER / PENDING (audit finding C-05).
-- The lifecycle trigger (017) checks UPDATE only, so a session with the
-- application's database role could INSERT a row that is already VERIFIED
-- and COMMITTED, with no signature, or with any bank_transaction_state text.
DO $$
DECLARE bad TEXT;
BEGIN
  SELECT string_agg(authorization_id::text || ' (' || bank_transaction_state || ')', ', ') INTO bad
    FROM authorization_requests
   WHERE bank_transaction_state NOT IN ('PENDING','COMMIT_REQUESTED','COMMITTED','FAILED','CANCELLED');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'authorizations with an unknown bank_transaction_state: %', bad;
  END IF;
END $$;

ALTER TABLE authorization_requests DROP CONSTRAINT IF EXISTS authorization_requests_bank_state_check;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_bank_state_check
  CHECK (bank_transaction_state IN ('PENDING','COMMIT_REQUESTED','COMMITTED','FAILED','CANCELLED'));

CREATE OR REPLACE FUNCTION authorization_insert_state() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.state <> 'PENDING_USER' OR NEW.bank_transaction_state <> 'PENDING'
     OR NEW.signature IS NOT NULL OR NEW.signature_format IS NOT NULL OR NEW.confirmation_method IS NOT NULL
     OR NEW.verified_at IS NOT NULL OR NEW.consumed_at IS NOT NULL
     OR NEW.bank_transaction_reference IS NOT NULL OR NEW.bank_commit_at IS NOT NULL
     OR NEW.offline_code_tag IS NOT NULL OR NEW.offline_code_accepted_at IS NOT NULL
     OR NEW.offline_signature_deadline IS NOT NULL OR NEW.offline_unsigned_reason IS NOT NULL THEN
    RAISE EXCEPTION 'authorization %: an authorization is created PENDING_USER with bank transaction PENDING and nothing confirmed', NEW.authorization_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authorization_insert_state ON authorization_requests;
CREATE TRIGGER authorization_insert_state BEFORE INSERT ON authorization_requests
  FOR EACH ROW EXECUTE FUNCTION authorization_insert_state();
