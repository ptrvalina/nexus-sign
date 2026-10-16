-- 006: recovery sessions get their own short-lived access token.
ALTER TABLE recovery_sessions
  ADD COLUMN IF NOT EXISTS access_token_hash BYTEA,
  ADD COLUMN IF NOT EXISTS access_token_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_recovery_sessions_token_expiry
  ON recovery_sessions(access_token_expires_at)
  WHERE used_at IS NULL;
