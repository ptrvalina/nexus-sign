-- Removes two indexes that duplicate idx_auth_bank_state (005) and
-- uq_auth_idempotency (002), so upgraded databases match schema.sql.
DROP INDEX IF EXISTS ix_auth_bank_state;
DROP INDEX IF EXISTS uq_auth_idempotency_required;
