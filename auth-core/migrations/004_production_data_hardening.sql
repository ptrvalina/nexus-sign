-- 004: production data hardening.
-- Apply after migrations 002 and 003.

ALTER TABLE authorization_requests
  ADD COLUMN IF NOT EXISTS bank_transaction_state VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  ADD COLUMN IF NOT EXISTS bank_transaction_reference VARCHAR(128),
  ADD COLUMN IF NOT EXISTS bank_commit_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS bank_commit_error VARCHAR(256);

CREATE INDEX IF NOT EXISTS ix_auth_bank_transaction_reference
  ON authorization_requests(client_id, bank_transaction_reference);

ALTER TABLE evidence_records
  ADD COLUMN IF NOT EXISTS evidence_hash_algorithm VARCHAR(32) NOT NULL DEFAULT 'SHA-256';

-- Idempotency is scoped to bank tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_idempotency_required
  ON authorization_requests(client_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
