-- 016: audit attribution and append-only audit log (NXS-010), admin scope,
-- MFA and four-eyes approvals (NXS-011), bank client certificate binding
-- (NXS-012).

-- Audit log: who acted and for which bank. Existing rows keep NULL client and
-- actor where they cannot be derived; the actor recorded in details is copied.
-- The append-only triggers are (re)created after the backfill.
DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS client_id TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor TEXT;
UPDATE audit_logs a SET client_id = i.client_id
  FROM nexus_identities i
 WHERE a.client_id IS NULL AND a.nexus_id = i.nexus_id;
UPDATE audit_logs SET actor = details->>'actor' WHERE actor IS NULL AND details ? 'actor';
CREATE INDEX IF NOT EXISTS idx_audit_logs_client_time ON audit_logs(client_id, "timestamp");

-- Audit records are written once. Retention is handled by export and
-- archival under a separate database role, not by the application.
CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only (% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_logs_no_update BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only();

-- Admin accounts: NULL client_id = platform operator (all banks); otherwise
-- the account sees and acts on that bank's identities only.
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS client_id TEXT REFERENCES bank_clients(client_id);
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_secret_encrypted TEXT;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT;
-- Bumped whenever the password or TOTP secret is reset; older sessions end (NXS-032).
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1;

-- Revocation and reactivation need a second admin.
CREATE TABLE IF NOT EXISTS admin_approvals (
    approval_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action                     VARCHAR(16) NOT NULL CHECK (action IN ('REVOKE','REACTIVATE')),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    reason                     VARCHAR(256) NOT NULL,
    requested_by               TEXT NOT NULL REFERENCES admin_users(username),
    requested_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                 TIMESTAMPTZ NOT NULL,
    status                     VARCHAR(16) NOT NULL DEFAULT 'PENDING'
                               CHECK (status IN ('PENDING','EXECUTED','REJECTED','EXPIRED')),
    decided_by                 TEXT REFERENCES admin_users(username),
    decided_at                 TIMESTAMPTZ,
    CONSTRAINT admin_approvals_two_people CHECK (status <> 'EXECUTED' OR (decided_by IS NOT NULL AND decided_by <> requested_by)),
    CONSTRAINT admin_approvals_decided CHECK ((status = 'PENDING') = (decided_at IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_admin_approvals_pending ON admin_approvals(client_id, status, requested_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_approvals_one_pending
  ON admin_approvals(nexus_id, action) WHERE status = 'PENDING';

-- Bank client certificate binding: SHA-256 fingerprints (hex) of the client
-- certificates the gateway may present for this bank.
ALTER TABLE bank_clients ADD COLUMN IF NOT EXISTS mtls_cert_sha256 TEXT[] NOT NULL DEFAULT '{}';
