-- 003: recovery verifier, credential rotation and HSM evidence.
ALTER TABLE nexus_identities
  ADD COLUMN IF NOT EXISTS recovery_verifier BYTEA,
  ADD COLUMN IF NOT EXISTS recovery_kdf_salt BYTEA,
  ADD COLUMN IF NOT EXISTS recovery_kdf_iterations INTEGER,
  ADD COLUMN IF NOT EXISTS recovery_updated_at TIMESTAMPTZ;

ALTER TABLE recovery_sessions
  ADD COLUMN IF NOT EXISTS nonce BYTEA;

ALTER TABLE evidence_records
  ADD COLUMN IF NOT EXISTS hsm_key_version INTEGER;

CREATE INDEX IF NOT EXISTS idx_recovery_sessions_active
  ON recovery_sessions(client_id, nexus_id, expires_at)
  WHERE used_at IS NULL;

-- runtime application role must not update/delete evidence records.
-- Enforce this with a dedicated DB role in the production deployment.
