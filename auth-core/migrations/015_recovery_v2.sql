-- 015: recovery protocol 2 (docs/architecture/recovery-protocol-v2.md).
--
-- The identity keeps the public half of a recovery key and the private half
-- encrypted under a key derived from the recovery phrase; no stored value is
-- enough to complete a recovery. Identities set up with protocol 1 (an HMAC
-- verifier) keep it, marked protocol 1, until the customer sets up a new
-- phrase; protocol 1 recovery is accepted only while RECOVERY_V1_ACCEPTED is set.

ALTER TABLE nexus_identities ADD COLUMN IF NOT EXISTS recovery_protocol SMALLINT;
ALTER TABLE nexus_identities ADD COLUMN IF NOT EXISTS recovery_public_key_pem TEXT;
ALTER TABLE nexus_identities ADD COLUMN IF NOT EXISTS recovery_wrapped_key BYTEA;
ALTER TABLE nexus_identities DROP CONSTRAINT IF EXISTS nexus_identities_recovery_protocol_check;
ALTER TABLE nexus_identities ADD CONSTRAINT nexus_identities_recovery_protocol_check
    CHECK (recovery_protocol IS NULL OR recovery_protocol IN (1, 2));
UPDATE nexus_identities SET recovery_protocol = 1 WHERE recovery_verifier IS NOT NULL AND recovery_protocol IS NULL;

ALTER TABLE recovery_sessions ADD COLUMN IF NOT EXISTS protocol SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE recovery_sessions ADD COLUMN IF NOT EXISTS failed_attempt_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE recovery_sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS idx_recovery_sessions_identity_recent ON recovery_sessions(nexus_id, created_at);
