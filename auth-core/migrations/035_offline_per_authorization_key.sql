-- Offline confirmation v3 (audit finding D-01). A credential enrolled with
-- offline_key_agreement = 'PER_AUTHORIZATION' has no key agreed at enrolment:
-- for each offline confirmation Auth Core generates a P-256 key, keeps its
-- private half encrypted in offline_challenges and puts the public half in the
-- QR code. The phone's Secure Enclave agrees a secret with it that serves that
-- one authorization. The iOS SDK enrols this way; STATIC stays for Android,
-- which keeps its key in the Keystore.
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS offline_key_agreement VARCHAR(20) NOT NULL DEFAULT 'STATIC';
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_offline_key_agreement_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_offline_key_agreement_check
  CHECK (offline_key_agreement IN ('STATIC', 'PER_AUTHORIZATION')
         AND (offline_key_agreement = 'STATIC' OR (offline_secret_encrypted IS NULL AND offline_server_public_key_pem IS NULL)));

CREATE OR REPLACE FUNCTION credential_offline_key_agreement_fixed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF NEW.offline_key_agreement IS DISTINCT FROM OLD.offline_key_agreement THEN
    RAISE EXCEPTION 'credential % : the offline key agreement is fixed at enrolment', OLD.credential_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS credential_offline_key_agreement_fixed ON credentials;
CREATE TRIGGER credential_offline_key_agreement_fixed BEFORE UPDATE ON credentials
  FOR EACH ROW EXECUTE FUNCTION credential_offline_key_agreement_fixed();

CREATE TABLE IF NOT EXISTS offline_challenges (
    authorization_id              UUID PRIMARY KEY REFERENCES authorization_requests(authorization_id),
    credential_id                 UUID NOT NULL REFERENCES credentials(credential_id),
    server_public_key_pem         TEXT NOT NULL,
    server_private_key_encrypted  TEXT NOT NULL,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A challenge key is written once. Only its ciphertext may change, by the
-- master key rotation (secret_rewrap_allowed, migration 033); rows are never deleted.
CREATE OR REPLACE FUNCTION offline_challenges_fixed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'offline_challenges rows are not deleted (DELETE refused)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.authorization_id IS DISTINCT FROM OLD.authorization_id OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.server_public_key_pem IS DISTINCT FROM OLD.server_public_key_pem OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR (NEW.server_private_key_encrypted IS DISTINCT FROM OLD.server_private_key_encrypted AND NOT secret_rewrap_allowed()) THEN
    RAISE EXCEPTION 'offline challenge % : the key is written once', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS offline_challenges_fixed ON offline_challenges;
CREATE TRIGGER offline_challenges_fixed BEFORE UPDATE OR DELETE ON offline_challenges
  FOR EACH ROW EXECUTE FUNCTION offline_challenges_fixed();
