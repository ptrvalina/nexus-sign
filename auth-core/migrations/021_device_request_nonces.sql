-- 021: device request nonces in PostgreSQL (FI-008). Re-runnable.
--
-- A signed device request carries a one-time nonce. Until 2.0.0 nonces were
-- remembered only in Redis, so a failover to an asynchronous replica or a
-- restore from a snapshot could forget nonces that were still inside the
-- timestamp window, and a captured request could be replayed. With
-- DEVICE_NONCE_STORE=postgres (the default) the primary key below refuses a
-- second use within the same durability guarantees as the rest of the data.
-- Rows past expires_at are deleted by the expiry sweep.

CREATE TABLE IF NOT EXISTS device_request_nonces (
    credential_id              UUID NOT NULL,
    nonce                      VARCHAR(64) NOT NULL,
    expires_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (credential_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_device_request_nonces_expires_at ON device_request_nonces(expires_at);

-- The application deletes expired nonces (and nothing else here).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexus_app') THEN
    GRANT DELETE ON device_request_nonces TO nexus_app;
  END IF;
END $$;
