-- Webhook secret rotation with an overlap (audit finding A2-08). When a
-- bank's webhook secret is rotated, the previous one stays until
-- webhook_secret_previous_until, and every delivery carries a signature with
-- each secret, so the bank can switch its verifier at any time in between.
ALTER TABLE bank_clients ADD COLUMN IF NOT EXISTS webhook_secret_previous_encrypted TEXT;
ALTER TABLE bank_clients ADD COLUMN IF NOT EXISTS webhook_secret_previous_until TIMESTAMPTZ;
ALTER TABLE bank_clients DROP CONSTRAINT IF EXISTS bank_clients_webhook_previous_check;
ALTER TABLE bank_clients ADD CONSTRAINT bank_clients_webhook_previous_check
  CHECK ((webhook_secret_previous_encrypted IS NULL) = (webhook_secret_previous_until IS NULL));
