-- 005: bank transaction tracking and webhook delivery security.
ALTER TABLE authorization_requests
  ADD COLUMN IF NOT EXISTS bank_transaction_state VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  ADD COLUMN IF NOT EXISTS bank_transaction_reference VARCHAR(128),
  ADD COLUMN IF NOT EXISTS bank_commit_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS bank_commit_error VARCHAR(256);

ALTER TABLE webhook_deliveries
  ADD COLUMN IF NOT EXISTS event_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS delivery_attempt_id UUID,
  ADD COLUMN IF NOT EXISTS last_http_status INTEGER;

CREATE INDEX IF NOT EXISTS ix_auth_bank_state ON authorization_requests(client_id, bank_transaction_state);
