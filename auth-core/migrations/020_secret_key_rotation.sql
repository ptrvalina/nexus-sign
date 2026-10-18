-- 020: master key rotation for stored secrets (FI-005). Re-runnable.
--
-- Secrets encrypted by Auth Core (webhook signing keys, offline and push keys,
-- admin TOTP secrets) now name the master key that encrypted them, and
-- cli/rotateSecretKeys.js re-encrypts them under the current key. Only the
-- credential's offline key is protected by a trigger; this lets that tool,
-- and only within its own transaction, replace the ciphertext. Everything
-- else about a credential stays immutable.

-- Re-encryption of a stored secret under a new master key (FI-005,
-- cli/rotateSecretKeys.js): the ciphertext of the offline key may change, its
-- presence may not. The tool sets nexus.secret_rewrap for its own transaction
-- and checks that the new ciphertext decrypts to the same key.
CREATE OR REPLACE FUNCTION secret_rewrap_allowed() RETURNS boolean AS $$
  SELECT coalesce(current_setting('nexus.secret_rewrap', true), '') = 'on';
$$ LANGUAGE sql STABLE;

-- Credential lifecycle: unchanged from 018 except the offline key ciphertext.
CREATE OR REPLACE FUNCTION credential_lifecycle() RETURNS trigger AS $$
BEGIN
  IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.nexus_id IS DISTINCT FROM OLD.nexus_id
     OR NEW.key_algorithm IS DISTINCT FROM OLD.key_algorithm
     OR NEW.public_key_pem IS DISTINCT FROM OLD.public_key_pem
     OR NEW.auth_public_key_pem IS DISTINCT FROM OLD.auth_public_key_pem
     OR NEW.offline_public_key_pem IS DISTINCT FROM OLD.offline_public_key_pem
     OR NEW.offline_server_public_key_pem IS DISTINCT FROM OLD.offline_server_public_key_pem
     OR (NEW.offline_secret_encrypted IS DISTINCT FROM OLD.offline_secret_encrypted
         AND NOT (secret_rewrap_allowed() AND OLD.offline_secret_encrypted IS NOT NULL AND NEW.offline_secret_encrypted IS NOT NULL))
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
