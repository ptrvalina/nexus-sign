-- NEXUS-SIGN Auth Core: database schema
-- PostgreSQL 14+. Creates the current schema on an empty database and is safe
-- to apply again. Existing databases are upgraded with migrations/.
-- Install and upgrade with `npm run migrate` (src/cli/migrate.ts), which keeps
-- the migration ledger. This file contains every migration up to:
-- schema-version: 030

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS bank_clients (
    client_id                  TEXT PRIMARY KEY,
    client_secret_hash         TEXT NOT NULL,
    webhook_url                TEXT,
    webhook_secret_encrypted   TEXT,
    status                     VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
                               CHECK (status IN ('ACTIVE','DISABLED')),
    -- BANK: the bank's own push system delivers authorization requests.
    -- NEXUS: Auth Core delivers them, and bank messages, through secure push.
    push_mode                  VARCHAR(16) NOT NULL DEFAULT 'BANK'
                               CHECK (push_mode IN ('BANK','NEXUS')),
    -- SHA-256 fingerprints (hex) of the client certificates the mTLS gateway
    -- may present for this bank; tokens are usable only with one of them.
    mtls_cert_sha256           TEXT[] NOT NULL DEFAULT '{}',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nexus_identities (
    nexus_id                   VARCHAR(9) PRIMARY KEY CHECK (nexus_id ~ '^[0-9]{9}$'),
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    bank_customer_ref          VARCHAR(128) NOT NULL,
    status                     VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
                               CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
    -- Recovery protocol 2: the recovery public key and the private key
    -- wrapped under a phrase-derived key. Identities with protocol 1 (an HMAC
    -- verifier, removed by migration 018) must set up a new phrase.
    recovery_protocol          SMALLINT CHECK (recovery_protocol IS NULL OR recovery_protocol IN (1, 2)),
    recovery_public_key_pem    TEXT,
    recovery_wrapped_key       BYTEA,
    recovery_kdf_salt          BYTEA,
    recovery_kdf_iterations    INTEGER,
    recovery_updated_at        TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at               TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_nexus_identity_customer
    ON nexus_identities(client_id, bank_customer_ref)
    WHERE status <> 'REVOKED';

CREATE TABLE IF NOT EXISTS credentials (
    credential_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    key_algorithm              VARCHAR(32) NOT NULL CHECK (key_algorithm IN ('ES256')),
    public_key_pem             TEXT NOT NULL,
    platform                   VARCHAR(16) NOT NULL CHECK (platform IN ('IOS','ANDROID','OTHER')),
    security_level             VARCHAR(32) NOT NULL,
    attestation_status         VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN'
                               CHECK (attestation_status IN ('UNKNOWN','VERIFIED','FAILED','EXPIRED')),
    state                      VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
                               CHECK (state IN ('ACTIVE','REVOKED')),
    key_version                INTEGER NOT NULL DEFAULT 1,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at               TIMESTAMPTZ,
    revoked_at                 TIMESTAMPTZ,
    last_used_at               TIMESTAMPTZ,
    -- Device authentication and offline confirmation keys.
    auth_public_key_pem        TEXT,
    offline_public_key_pem     TEXT,
    offline_server_public_key_pem TEXT,
    offline_secret_encrypted   TEXT,
    CONSTRAINT credentials_offline_keys_check
        CHECK ((offline_secret_encrypted IS NULL) = (offline_server_public_key_pem IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_credentials_nexus_id ON credentials(nexus_id);
CREATE INDEX IF NOT EXISTS idx_credentials_state ON credentials(state);

CREATE TABLE IF NOT EXISTS authorization_requests (
    authorization_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    credential_id              UUID REFERENCES credentials(credential_id),
    transaction_reference      VARCHAR(128) NOT NULL,
    operation_type             VARCHAR(32) NOT NULL,
    amount_minor               NUMERIC(30,0) NOT NULL CHECK (amount_minor >= 0),
    currency                   CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    beneficiary                JSONB NOT NULL,
    protocol_version           VARCHAR(16) NOT NULL DEFAULT '1',
    domain                     VARCHAR(128) NOT NULL DEFAULT 'NEXUS-SIGN/TRANSACTION-AUTH',
    policy_reference           VARCHAR(128) NOT NULL,
    policy_version             VARCHAR(64) NOT NULL,
    risk_context_reference     VARCHAR(128),
    policy_decision            VARCHAR(24),
    canonical_payload_hash     CHAR(64) NOT NULL,
    nonce                      VARCHAR(128) NOT NULL,
    issued_at                  TIMESTAMPTZ NOT NULL,
    expires_at                 TIMESTAMPTZ NOT NULL,
    state                      VARCHAR(16) NOT NULL DEFAULT 'PENDING_USER'
                               CHECK (state IN ('PENDING_USER','VERIFIED','EXPIRED','CANCELLED','REJECTED')),
    signature                  TEXT,
    signature_algorithm        VARCHAR(32) NOT NULL DEFAULT 'ES256',
    signature_format           VARCHAR(8)
                               CHECK (signature_format IS NULL OR signature_format IN ('der', 'raw', 'hmac')),
    confirmation_method        VARCHAR(16)
                               CHECK (confirmation_method IS NULL OR confirmation_method IN ('DEVICE_SIGNATURE', 'OFFLINE_CODE')),
    verified_at                TIMESTAMPTZ,
    consumed_at                TIMESTAMPTZ,
    correlation_id             VARCHAR(128),
    idempotency_key            VARCHAR(128),
    bank_transaction_state     VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    bank_transaction_reference VARCHAR(128),
    bank_commit_at             TIMESTAMPTZ,
    bank_commit_error          VARCHAR(256),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_idempotency
    ON authorization_requests(client_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_transaction_reference
    ON authorization_requests(client_id, transaction_reference);
CREATE INDEX IF NOT EXISTS idx_auth_nexus_state ON authorization_requests(nexus_id, state);
CREATE INDEX IF NOT EXISTS idx_auth_expiry ON authorization_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_bank_state ON authorization_requests(client_id, bank_transaction_state);
CREATE INDEX IF NOT EXISTS ix_auth_bank_transaction_reference
    ON authorization_requests(client_id, bank_transaction_reference);

CREATE TABLE IF NOT EXISTS authorization_attempts (
    attempt_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    authorization_id           UUID NOT NULL REFERENCES authorization_requests(authorization_id),
    credential_id              UUID REFERENCES credentials(credential_id),
    attempt_number             INTEGER NOT NULL,
    result                     VARCHAR(32) NOT NULL
                               CHECK (result IN ('INVALID_SIGNATURE','VERIFIED','EXPIRED','REJECTED','CREDENTIAL_INVALID')),
    reason_code                VARCHAR(128),
    occurred_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_ip                  INET,
    user_agent                 TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_authorization ON authorization_attempts(authorization_id, occurred_at);

CREATE TABLE IF NOT EXISTS recovery_sessions (
    recovery_session_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    nonce                      BYTEA NOT NULL,
    nonce_hash                 CHAR(64) NOT NULL,
    kdf_salt                   BYTEA NOT NULL,
    kdf_algorithm              VARCHAR(64) NOT NULL,
    access_token_hash          BYTEA NOT NULL,
    access_token_expires_at    TIMESTAMPTZ NOT NULL,
    expires_at                 TIMESTAMPTZ NOT NULL,
    used_at                    TIMESTAMPTZ,
    attempt_count              INTEGER NOT NULL DEFAULT 0,
    protocol                   SMALLINT NOT NULL DEFAULT 1,
    failed_attempt_count       INTEGER NOT NULL DEFAULT 0,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_recovery_sessions_identity_recent ON recovery_sessions(nexus_id, created_at);
CREATE INDEX IF NOT EXISTS idx_recovery_sessions_active
    ON recovery_sessions(client_id, nexus_id, expires_at) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_recovery_sessions_token_expiry
    ON recovery_sessions(access_token_expires_at) WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- AUTHORIZATION: a confirmed transaction. CREDENTIAL_ENROLLED: the keys of
    -- a credential and the attestation that admitted them. RECOVERY_CONFIGURED:
    -- the recovery public key a device registered (schema 3, ADR 0009).
    record_type                VARCHAR(32) NOT NULL DEFAULT 'AUTHORIZATION'
                               CHECK (record_type IN ('AUTHORIZATION','CREDENTIAL_ENROLLED','RECOVERY_CONFIGURED')),
    authorization_id           UUID UNIQUE REFERENCES authorization_requests(authorization_id),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    credential_id              UUID NOT NULL REFERENCES credentials(credential_id),
    chain_sequence             BIGINT NOT NULL,
    transaction_reference      VARCHAR(128),
    canonical_payload_hash     CHAR(64),
    signature                  TEXT,
    signature_algorithm        VARCHAR(32),
    key_version                INTEGER,
    policy_version             VARCHAR(64),
    attestation_verdict        VARCHAR(32),
    verified_at                TIMESTAMPTZ,
    consumed_at                TIMESTAMPTZ,
    result                     VARCHAR(24),
    correlation_id             VARCHAR(128),
    previous_evidence_hash     CHAR(64),
    evidence_hash              CHAR(64) NOT NULL,
    evidence_hash_algorithm    VARCHAR(32) NOT NULL DEFAULT 'SHA-256',
    hsm_signature              TEXT,
    hsm_key_version            INTEGER,
    -- SHA-256 of the sealing key's SubjectPublicKeyInfo (schema 3).
    seal_key_id                CHAR(64),
    schema_version             VARCHAR(16) NOT NULL DEFAULT '1',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    verification_factors       JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Schema 2 and 3: the exact sealed document.
    sealed_payload             JSONB,
    CONSTRAINT evidence_records_authorization_fields_check
        CHECK (record_type <> 'AUTHORIZATION' OR (authorization_id IS NOT NULL AND transaction_reference IS NOT NULL
               AND canonical_payload_hash IS NOT NULL AND signature IS NOT NULL AND verified_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_evidence_nexus ON evidence_records(nexus_id);
CREATE INDEX IF NOT EXISTS idx_evidence_transaction ON evidence_records(transaction_reference);
-- One record per position, one successor per record, one first record per chain.
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_chain_sequence ON evidence_records(nexus_id, chain_sequence);
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_chain_link ON evidence_records(nexus_id, previous_evidence_hash) WHERE previous_evidence_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_chain_genesis ON evidence_records(nexus_id) WHERE previous_evidence_hash IS NULL;

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS enrolment_evidence_id UUID REFERENCES evidence_records(evidence_id);
ALTER TABLE nexus_identities ADD COLUMN IF NOT EXISTS recovery_evidence_id UUID REFERENCES evidence_records(evidence_id);

-- Evidence records are append-only, enforced in the database as well.
CREATE OR REPLACE FUNCTION nexus_evidence_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'evidence_records is append-only (% rejected)', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_evidence_append_only ON evidence_records;
CREATE TRIGGER trg_evidence_append_only
    BEFORE UPDATE OR DELETE ON evidence_records
    FOR EACH ROW EXECUTE FUNCTION nexus_evidence_append_only();

DROP TRIGGER IF EXISTS trg_evidence_no_truncate ON evidence_records;
CREATE TRIGGER trg_evidence_no_truncate
    BEFORE TRUNCATE ON evidence_records
    FOR EACH STATEMENT EXECUTE FUNCTION nexus_evidence_append_only();

CREATE TABLE IF NOT EXISTS audit_logs (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id                   UUID NOT NULL,
    timestamp                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type                 VARCHAR(64) NOT NULL,
    nexus_id                   VARCHAR(9),
    bank_customer_id           VARCHAR(128),
    details                    JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address                 INET,
    user_agent                 TEXT,
    -- Bank the event belongs to, and the operator, bank client or system
    -- component that performed it.
    client_id                  TEXT,
    actor                      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_nexus_id ON audit_logs(nexus_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_client_time ON audit_logs(client_id, "timestamp");

-- Audit records are written once. Retention is handled by export and
-- archival under a separate database role, not by the application.
CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only (% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
CREATE TRIGGER audit_logs_no_update BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();
DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs;
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only();

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id                   UUID NOT NULL UNIQUE,
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    event_type                 VARCHAR(64) NOT NULL,
    payload                    JSONB NOT NULL,
    status                     VARCHAR(16) NOT NULL DEFAULT 'PENDING'
                               CHECK (status IN ('PENDING','DELIVERED','FAILED')),
    retry_count                INTEGER NOT NULL DEFAULT 0,
    next_attempt_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error                 TEXT,
    last_http_status           INTEGER,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at               TIMESTAMPTZ,
    event_created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivery_attempt_id        UUID
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending ON webhook_deliveries(next_attempt_at) WHERE status='PENDING';

CREATE TABLE IF NOT EXISTS admin_users (
    username                   TEXT PRIMARY KEY,
    password_hash              TEXT NOT NULL,
    role                       VARCHAR(16) NOT NULL CHECK (role IN ('administrator','operator','auditor')),
    status                     VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at              TIMESTAMPTZ,
    -- NULL: platform operator (all banks); otherwise this bank only.
    client_id                  TEXT REFERENCES bank_clients(client_id),
    -- TOTP (RFC 6238) secret, encrypted with ADMIN_SECRET_ENCRYPTION_KEY, and
    -- the last accepted time step (a code is accepted once).
    totp_secret_encrypted      TEXT,
    totp_last_step             BIGINT,
    -- Bumped whenever the password or TOTP secret is reset; older sessions end.
    session_version            INTEGER NOT NULL DEFAULT 1
);

-- Revocation and reactivation of an identity need a second admin.
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

-- Adaptive verification: the factors each authorization requires, and the
-- audio or video sessions that satisfy them.

CREATE TABLE IF NOT EXISTS authorization_verification_plans (
    authorization_id           UUID PRIMARY KEY REFERENCES authorization_requests(authorization_id) ON DELETE CASCADE,
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    policy_version             VARCHAR(64) NOT NULL,
    required_step              VARCHAR(16) NOT NULL CHECK (required_step IN ('PUSH','AUDIO','VIDEO')),
    current_step               VARCHAR(16) NOT NULL CHECK (current_step IN ('PUSH','AUDIO','VIDEO')),
    allowed_steps              VARCHAR(16)[] NOT NULL,
    audio_enabled              BOOLEAN NOT NULL DEFAULT FALSE,
    video_enabled              BOOLEAN NOT NULL DEFAULT FALSE,
    push_timeout_seconds       INTEGER NOT NULL CHECK (push_timeout_seconds BETWEEN 10 AND 300),
    high_amount_threshold_minor NUMERIC(30,0),
    client_escalation_allowed  BOOLEAN NOT NULL DEFAULT TRUE,
    status                     VARCHAR(16) NOT NULL
                               CHECK (status IN ('PENDING','IN_PROGRESS','VERIFIED','FAILED','EXPIRED','CANCELLED')),
    last_escalation_reason     VARCHAR(32),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS verification_sessions (
    session_id                 UUID PRIMARY KEY,
    authorization_id           UUID NOT NULL REFERENCES authorization_requests(authorization_id) ON DELETE CASCADE,
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    channel                    VARCHAR(16) NOT NULL CHECK (channel IN ('PUSH','AUDIO','VIDEO')),
    nonce_hash                 CHAR(64) NOT NULL,
    expires_at                 TIMESTAMPTZ NOT NULL,
    status                     VARCHAR(16) NOT NULL
                               CHECK (status IN ('IN_PROGRESS','VERIFIED','FAILED','EXPIRED','CANCELLED')),
    provider_reference         VARCHAR(128),
    assertion_hash             CHAR(64),
    completed_at               TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_verification_sessions_authorization ON verification_sessions(authorization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_verification_sessions_expiry ON verification_sessions(expires_at) WHERE status='IN_PROGRESS';

-- Secure push (docs/protocol/secure-push.md): one registration per device
-- credential, and the outbox of sealed messages. Message content is stored
-- only as the envelope encrypted for the device.

CREATE TABLE IF NOT EXISTS push_registrations (
    credential_id              UUID PRIMARY KEY REFERENCES credentials(credential_id),
    provider                   VARCHAR(8) NOT NULL CHECK (provider IN ('APNS','FCM')),
    apns_environment           VARCHAR(16)
                               CHECK (apns_environment IS NULL OR apns_environment IN ('PRODUCTION','DEVELOPMENT')),
    device_token               TEXT NOT NULL,
    push_key_encrypted         TEXT NOT NULL,
    push_key_id                CHAR(22) NOT NULL,
    status                     VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INVALID')),
    last_error                 VARCHAR(256),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    invalidated_at             TIMESTAMPTZ,
    CONSTRAINT push_registrations_provider_environment_check
        CHECK ((provider = 'APNS') = (apns_environment IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS push_messages (
    message_id                 UUID PRIMARY KEY,
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    credential_id              UUID REFERENCES credentials(credential_id),
    category                   VARCHAR(32) NOT NULL
                               CHECK (category IN ('AUTHORIZATION_REQUEST','INCOMING_PAYMENT','OUTGOING_PAYMENT','CARD_TRANSACTION','ACCOUNT','SECURITY','GENERAL')),
    authorization_id           UUID REFERENCES authorization_requests(authorization_id),
    message_reference          VARCHAR(128),
    envelope                   TEXT,
    status                     VARCHAR(16) NOT NULL
                               CHECK (status IN ('QUEUED','SENT','DELIVERED','FAILED','EXPIRED')),
    provider                   VARCHAR(8) CHECK (provider IS NULL OR provider IN ('APNS','FCM')),
    provider_message_id        VARCHAR(256),
    retry_count                INTEGER NOT NULL DEFAULT 0,
    next_attempt_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                 TIMESTAMPTZ NOT NULL,
    last_error                 VARCHAR(256),
    last_http_status           INTEGER,
    sent_at                    TIMESTAMPTZ,
    delivered_at               TIMESTAMPTZ,
    timeout_reported_at        TIMESTAMPTZ,
    -- A security notice for a replaced device, delivered although its
    -- credential is revoked (credentialService.ts).
    replacement_notice         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT push_messages_envelope_check CHECK (envelope IS NOT NULL OR status = 'FAILED')
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_push_message_reference
    ON push_messages(client_id, message_reference) WHERE message_reference IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_push_messages_due ON push_messages(next_attempt_at) WHERE status = 'QUEUED';
CREATE INDEX IF NOT EXISTS idx_push_messages_awaiting_receipt
    ON push_messages(sent_at) WHERE status = 'SENT' AND authorization_id IS NOT NULL AND timeout_reported_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_push_messages_identity ON push_messages(nexus_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_push_messages_authorization ON push_messages(authorization_id) WHERE authorization_id IS NOT NULL;

-- Authorization lifecycle (migrations 017, 018, 022):
--   PENDING_USER -> VERIFIED | EXPIRED | CANCELLED | REJECTED | OFFLINE_PROVISIONAL
--   OFFLINE_PROVISIONAL -> VERIFIED | OFFLINE_UNSIGNED
-- VERIFIED, EXPIRED, CANCELLED, REJECTED and OFFLINE_UNSIGNED are final. The
-- transaction it binds never changes; the signature fields change only on the
-- transition to VERIFIED and the offline code fields only when a code is
-- accepted. Bank transaction lifecycle of a VERIFIED authorization:
-- PENDING -> COMMIT_REQUESTED -> COMMITTED | FAILED | CANCELLED.
CREATE OR REPLACE FUNCTION authorization_lifecycle() RETURNS trigger AS $$
DECLARE
  allowed BOOLEAN;
BEGIN
  IF NEW.authorization_id IS DISTINCT FROM OLD.authorization_id
     OR NEW.client_id IS DISTINCT FROM OLD.client_id
     OR NEW.nexus_id IS DISTINCT FROM OLD.nexus_id
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.transaction_reference IS DISTINCT FROM OLD.transaction_reference
     OR NEW.operation_type IS DISTINCT FROM OLD.operation_type
     OR NEW.amount_minor IS DISTINCT FROM OLD.amount_minor
     OR NEW.currency IS DISTINCT FROM OLD.currency
     OR NEW.beneficiary IS DISTINCT FROM OLD.beneficiary
     OR NEW.policy_reference IS DISTINCT FROM OLD.policy_reference
     OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
     OR NEW.canonical_payload_hash IS DISTINCT FROM OLD.canonical_payload_hash
     OR NEW.nonce IS DISTINCT FROM OLD.nonce
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'authorization % : the authorized transaction is immutable', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  IF NEW.state IS DISTINCT FROM OLD.state THEN
    allowed := (OLD.state = 'PENDING_USER' AND NEW.state IN ('VERIFIED','EXPIRED','CANCELLED','REJECTED','OFFLINE_PROVISIONAL'))
            OR (OLD.state = 'OFFLINE_PROVISIONAL' AND NEW.state IN ('VERIFIED','OFFLINE_UNSIGNED'));
    IF NOT allowed THEN
      RAISE EXCEPTION 'authorization % : % -> % is not a permitted transition', OLD.authorization_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;

  IF (NEW.signature IS DISTINCT FROM OLD.signature
      OR NEW.signature_format IS DISTINCT FROM OLD.signature_format
      OR NEW.confirmation_method IS DISTINCT FROM OLD.confirmation_method
      OR NEW.verified_at IS DISTINCT FROM OLD.verified_at)
     AND NOT (NEW.state = 'VERIFIED' AND OLD.state IN ('PENDING_USER','OFFLINE_PROVISIONAL')) THEN
    RAISE EXCEPTION 'authorization % : signature fields are set once, on verification', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'VERIFIED' AND (NEW.signature IS NULL OR NEW.verified_at IS NULL) THEN
    RAISE EXCEPTION 'authorization % : VERIFIED needs a signature and verified_at', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  -- The accepted offline code: written once, when the code is accepted.
  IF (NEW.offline_code_tag IS DISTINCT FROM OLD.offline_code_tag
      OR NEW.offline_code_accepted_at IS DISTINCT FROM OLD.offline_code_accepted_at
      OR NEW.offline_signature_deadline IS DISTINCT FROM OLD.offline_signature_deadline)
     AND NOT (OLD.state = 'PENDING_USER' AND NEW.state IN ('VERIFIED','OFFLINE_PROVISIONAL')
              AND OLD.offline_code_tag IS NULL AND OLD.offline_code_accepted_at IS NULL AND OLD.offline_signature_deadline IS NULL) THEN
    RAISE EXCEPTION 'authorization % : the offline code fields are set once, when the code is accepted', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'OFFLINE_PROVISIONAL'
     AND (NEW.offline_code_tag IS NULL OR NEW.offline_code_accepted_at IS NULL OR NEW.offline_signature_deadline IS NULL) THEN
    RAISE EXCEPTION 'authorization % : OFFLINE_PROVISIONAL needs the accepted code and its signature deadline', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.confirmation_method = 'OFFLINE_SIGNED' AND NEW.offline_code_tag IS NULL THEN
    RAISE EXCEPTION 'authorization % : OFFLINE_SIGNED needs the accepted code', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.offline_unsigned_reason IS DISTINCT FROM OLD.offline_unsigned_reason
     AND NOT (OLD.state = 'OFFLINE_PROVISIONAL' AND NEW.state = 'OFFLINE_UNSIGNED') THEN
    RAISE EXCEPTION 'authorization % : the unsigned reason is set once, on OFFLINE_UNSIGNED', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'OFFLINE_UNSIGNED' AND NEW.offline_unsigned_reason IS NULL THEN
    RAISE EXCEPTION 'authorization % : OFFLINE_UNSIGNED needs a reason', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  IF NEW.expires_at IS DISTINCT FROM OLD.expires_at AND OLD.state <> 'PENDING_USER' THEN
    RAISE EXCEPTION 'authorization % : expiry of a final authorization is immutable', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  IF NEW.bank_transaction_state IS DISTINCT FROM OLD.bank_transaction_state THEN
    allowed := CASE OLD.bank_transaction_state
      WHEN 'PENDING'          THEN NEW.bank_transaction_state = 'COMMIT_REQUESTED' AND NEW.state = 'VERIFIED'
      WHEN 'COMMIT_REQUESTED' THEN NEW.bank_transaction_state IN ('COMMITTED','FAILED','CANCELLED')
      ELSE FALSE
    END;
    IF NOT allowed THEN
      RAISE EXCEPTION 'authorization % : bank transaction % -> % is not a permitted transition', OLD.authorization_id, OLD.bank_transaction_state, NEW.bank_transaction_state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSIF NEW.bank_transaction_reference IS DISTINCT FROM OLD.bank_transaction_reference THEN
    RAISE EXCEPTION 'authorization % : the bank transaction reference is set with the commit request', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS authorization_lifecycle ON authorization_requests;
CREATE TRIGGER authorization_lifecycle BEFORE UPDATE ON authorization_requests
  FOR EACH ROW EXECUTE FUNCTION authorization_lifecycle();

-- Re-encryption of a stored secret under a new master key (
-- cli/rotateSecretKeys.js): the ciphertext of the offline key may change, its
-- presence may not. The tool sets nexus.secret_rewrap for its own transaction
-- and checks that the new ciphertext decrypts to the same key.
CREATE OR REPLACE FUNCTION secret_rewrap_allowed() RETURNS boolean AS $$
  SELECT coalesce(current_setting('nexus.secret_rewrap', true), '') = 'on';
$$ LANGUAGE sql STABLE;

-- Credential lifecycle: ACTIVE -> REVOKED (final). The keys of a credential never change, and its sealed enrolment
-- record is attached once.
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
DROP TRIGGER IF EXISTS credential_lifecycle ON credentials;
CREATE TRIGGER credential_lifecycle BEFORE UPDATE ON credentials
  FOR EACH ROW EXECUTE FUNCTION credential_lifecycle();

-- Identity lifecycle: ACTIVE <-> SUSPENDED, any -> REVOKED (final).
CREATE OR REPLACE FUNCTION identity_lifecycle() RETURNS trigger AS $$
DECLARE
  allowed BOOLEAN;
BEGIN
  IF NEW.nexus_id IS DISTINCT FROM OLD.nexus_id OR NEW.client_id IS DISTINCT FROM OLD.client_id
     OR NEW.bank_customer_ref IS DISTINCT FROM OLD.bank_customer_ref THEN
    RAISE EXCEPTION 'identity % : the bank binding is immutable', OLD.nexus_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.recovery_evidence_id IS NOT NULL AND NEW.recovery_evidence_id IS NULL THEN
    RAISE EXCEPTION 'identity % : the recovery configuration record cannot be detached', OLD.nexus_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  allowed := CASE OLD.status
      WHEN 'ACTIVE'    THEN NEW.status IN ('SUSPENDED','REVOKED')
      WHEN 'SUSPENDED' THEN NEW.status IN ('ACTIVE','REVOKED')
      ELSE FALSE
    END;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT allowed THEN
    RAISE EXCEPTION 'identity % : % -> % is not a permitted transition', OLD.nexus_id, OLD.status, NEW.status USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_lifecycle ON nexus_identities;
CREATE TRIGGER identity_lifecycle BEFORE UPDATE ON nexus_identities
  FOR EACH ROW EXECUTE FUNCTION identity_lifecycle();

-- Recovery sessions: attempt counters only grow, a session is used once, and
-- what it was issued for never changes, so the per-session and per-identity
-- recovery limits cannot be reset by rewriting rows.
CREATE OR REPLACE FUNCTION recovery_session_lifecycle() RETURNS trigger AS $$
BEGIN
  IF NEW.recovery_session_id IS DISTINCT FROM OLD.recovery_session_id OR NEW.nexus_id IS DISTINCT FROM OLD.nexus_id
     OR NEW.client_id IS DISTINCT FROM OLD.client_id OR NEW.nonce IS DISTINCT FROM OLD.nonce OR NEW.nonce_hash IS DISTINCT FROM OLD.nonce_hash
     OR NEW.kdf_salt IS DISTINCT FROM OLD.kdf_salt OR NEW.access_token_hash IS DISTINCT FROM OLD.access_token_hash
     OR NEW.protocol IS DISTINCT FROM OLD.protocol OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at > OLD.expires_at OR NEW.access_token_expires_at > OLD.access_token_expires_at THEN
    RAISE EXCEPTION 'recovery session % : issued fields are immutable', OLD.recovery_session_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.attempt_count < OLD.attempt_count OR NEW.failed_attempt_count < OLD.failed_attempt_count THEN
    RAISE EXCEPTION 'recovery session % : attempt counters only grow', OLD.recovery_session_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.used_at IS NOT NULL AND NEW.used_at IS DISTINCT FROM OLD.used_at THEN
    RAISE EXCEPTION 'recovery session % : a session is used once', OLD.recovery_session_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS recovery_session_lifecycle ON recovery_sessions;
CREATE TRIGGER recovery_session_lifecycle BEFORE UPDATE ON recovery_sessions
  FOR EACH ROW EXECUTE FUNCTION recovery_session_lifecycle();

-- Rows that carry security history are never deleted by the application:
-- removing recovery sessions would reset the per-identity recovery lockout,
-- removing approvals would hide who decided what, and identities, credentials
-- and authorizations are referenced by sealed evidence.
CREATE OR REPLACE FUNCTION refuse_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% rows are not deleted (% refused)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS recovery_sessions_no_delete ON recovery_sessions;
CREATE TRIGGER recovery_sessions_no_delete BEFORE DELETE ON recovery_sessions FOR EACH ROW EXECUTE FUNCTION refuse_delete();
DROP TRIGGER IF EXISTS admin_approvals_no_delete ON admin_approvals;
CREATE TRIGGER admin_approvals_no_delete BEFORE DELETE ON admin_approvals FOR EACH ROW EXECUTE FUNCTION refuse_delete();
DROP TRIGGER IF EXISTS credentials_no_delete ON credentials;
CREATE TRIGGER credentials_no_delete BEFORE DELETE ON credentials FOR EACH ROW EXECUTE FUNCTION refuse_delete();
DROP TRIGGER IF EXISTS identities_no_delete ON nexus_identities;
CREATE TRIGGER identities_no_delete BEFORE DELETE ON nexus_identities FOR EACH ROW EXECUTE FUNCTION refuse_delete();
DROP TRIGGER IF EXISTS authorizations_no_delete ON authorization_requests;
CREATE TRIGGER authorizations_no_delete BEFORE DELETE ON authorization_requests FOR EACH ROW EXECUTE FUNCTION refuse_delete();

-- One ACTIVE credential per identity.
-- (The one-ACTIVE index of migration 017 is replaced by credentials_device_limit, migration 027.)

-- Authenticated verification results and verifiable channels (migration 019).
CREATE TABLE IF NOT EXISTS verification_providers (
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    provider_id                VARCHAR(64) NOT NULL CHECK (provider_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    key_id                     VARCHAR(64) NOT NULL CHECK (key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    channels                   VARCHAR(16)[] NOT NULL
                               CHECK (cardinality(channels) > 0 AND channels <@ ARRAY['AUDIO','VIDEO']::VARCHAR(16)[]),
    public_key_pem             TEXT NOT NULL,
    status                     VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','RETIRED')),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at                 TIMESTAMPTZ,
    PRIMARY KEY (client_id, provider_id, key_id)
);

ALTER TABLE bank_clients ADD COLUMN IF NOT EXISTS operator_verification_channels VARCHAR(16)[] NOT NULL DEFAULT '{}';
ALTER TABLE bank_clients DROP CONSTRAINT IF EXISTS bank_clients_operator_verification_channels_check;
ALTER TABLE bank_clients ADD CONSTRAINT bank_clients_operator_verification_channels_check
    CHECK (operator_verification_channels <@ ARRAY['AUDIO','VIDEO']::VARCHAR(16)[]);

ALTER TABLE verification_sessions ADD COLUMN IF NOT EXISTS result_method VARCHAR(16);
ALTER TABLE verification_sessions DROP CONSTRAINT IF EXISTS verification_sessions_result_method_check;
ALTER TABLE verification_sessions ADD CONSTRAINT verification_sessions_result_method_check
    CHECK (result_method IS NULL OR result_method IN ('PROVIDER','OPERATOR'));
-- PROVIDER: "<providerId>/<keyId>"; OPERATOR: the admin username.
ALTER TABLE verification_sessions ADD COLUMN IF NOT EXISTS result_issuer VARCHAR(160);
-- The provider result's jti: one result per provider token.
ALTER TABLE verification_sessions ADD COLUMN IF NOT EXISTS result_jti VARCHAR(128);
CREATE UNIQUE INDEX IF NOT EXISTS uq_verification_result_jti
    ON verification_sessions(client_id, result_issuer, result_jti) WHERE result_jti IS NOT NULL;

CREATE TABLE IF NOT EXISTS device_request_nonces (
    credential_id              UUID NOT NULL,
    nonce                      VARCHAR(64) NOT NULL,
    expires_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (credential_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_device_request_nonces_expires_at ON device_request_nonces(expires_at);

-- Offline confirmation v2, deferred device signature (migration 022, ).
ALTER TABLE authorization_requests ALTER COLUMN state TYPE VARCHAR(24);
ALTER TABLE authorization_requests DROP CONSTRAINT IF EXISTS authorization_requests_state_check;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_state_check
  CHECK (state IN ('PENDING_USER','VERIFIED','EXPIRED','CANCELLED','REJECTED','OFFLINE_PROVISIONAL','OFFLINE_UNSIGNED'));
ALTER TABLE authorization_requests DROP CONSTRAINT IF EXISTS authorization_requests_confirmation_method_check;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_confirmation_method_check
  CHECK (confirmation_method IS NULL OR confirmation_method IN ('DEVICE_SIGNATURE','OFFLINE_CODE','OFFLINE_SIGNED'));
-- base64 HMAC tag of the accepted code, when it was accepted, and (v2) until
-- when the device signature may arrive.
ALTER TABLE authorization_requests ADD COLUMN IF NOT EXISTS offline_code_tag TEXT;
ALTER TABLE authorization_requests ADD COLUMN IF NOT EXISTS offline_code_accepted_at TIMESTAMPTZ;
ALTER TABLE authorization_requests ADD COLUMN IF NOT EXISTS offline_signature_deadline TIMESTAMPTZ;
-- OFFLINE_UNSIGNED: deadline | credential_not_active | identity_not_active.
ALTER TABLE authorization_requests ADD COLUMN IF NOT EXISTS offline_unsigned_reason VARCHAR(32);
CREATE INDEX IF NOT EXISTS idx_auth_offline_provisional
    ON authorization_requests(offline_signature_deadline) WHERE state = 'OFFLINE_PROVISIONAL';
CREATE INDEX IF NOT EXISTS idx_auth_offline_accepted
    ON authorization_requests(credential_id, offline_code_accepted_at) WHERE offline_code_accepted_at IS NOT NULL;

-- The device's ECDSA signature over the canonical bytes, uploaded after an
-- offline confirmation; at most one per authorization, never changed.
CREATE TABLE IF NOT EXISTS offline_deferred_signatures (
    authorization_id           UUID PRIMARY KEY REFERENCES authorization_requests(authorization_id),
    credential_id              UUID NOT NULL REFERENCES credentials(credential_id),
    signature                  TEXT NOT NULL,
    signature_format           VARCHAR(8) NOT NULL CHECK (signature_format IN ('der','raw')),
    received_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION offline_deferred_signatures_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'offline_deferred_signatures is append-only (% rejected)', TG_OP USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_offline_deferred_signatures_append_only ON offline_deferred_signatures;
CREATE TRIGGER trg_offline_deferred_signatures_append_only BEFORE UPDATE OR DELETE ON offline_deferred_signatures
  FOR EACH ROW EXECUTE FUNCTION offline_deferred_signatures_append_only();

-- Device replacement requests with a hold (audit finding A2-01): the bank asks,
-- the enrolled device approves or cancels, enrolment uses the request once.
CREATE TABLE IF NOT EXISTS device_replacements (
    replacement_id             UUID PRIMARY KEY,
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    method                     TEXT NOT NULL CHECK (method IN ('BRANCH_VISIT', 'VIDEO_IDENTIFICATION', 'IN_APP_STRONG_AUTHENTICATION', 'OTHER')),
    reference                  TEXT NOT NULL CHECK (length(reference) BETWEEN 1 AND 128),
    state                      TEXT NOT NULL CHECK (state IN ('PENDING', 'APPROVED', 'CANCELLED', 'USED', 'EXPIRED')),
    requested_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    not_before                 TIMESTAMPTZ NOT NULL,
    expires_at                 TIMESTAMPTZ NOT NULL CHECK (expires_at > not_before),
    decided_by_credential_id   UUID REFERENCES credentials(credential_id),
    decided_at                 TIMESTAMPTZ,
    used_by_credential_id      UUID
);
-- One open request per identity.
CREATE UNIQUE INDEX IF NOT EXISTS uq_device_replacements_open
    ON device_replacements(nexus_id) WHERE state IN ('PENDING', 'APPROVED');

-- Final states are final; a request is decided once.
CREATE OR REPLACE FUNCTION device_replacements_lifecycle() RETURNS trigger AS $$
BEGIN
  IF NEW.replacement_id <> OLD.replacement_id OR NEW.nexus_id <> OLD.nexus_id OR NEW.client_id <> OLD.client_id
     OR NEW.method <> OLD.method OR NEW.reference <> OLD.reference OR NEW.requested_at <> OLD.requested_at
     OR NEW.not_before <> OLD.not_before OR NEW.expires_at <> OLD.expires_at THEN
    RAISE EXCEPTION 'device replacement % : only its state changes', OLD.replacement_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT (OLD.state = NEW.state
          OR (OLD.state = 'PENDING' AND NEW.state IN ('APPROVED', 'CANCELLED', 'USED', 'EXPIRED'))
          OR (OLD.state = 'APPROVED' AND NEW.state IN ('USED', 'EXPIRED'))) THEN
    RAISE EXCEPTION 'device replacement % : % -> % is not permitted', OLD.replacement_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp;
DROP TRIGGER IF EXISTS device_replacements_lifecycle ON device_replacements;
CREATE TRIGGER device_replacements_lifecycle BEFORE UPDATE ON device_replacements FOR EACH ROW EXECUTE FUNCTION device_replacements_lifecycle();
DROP TRIGGER IF EXISTS device_replacements_no_delete ON device_replacements;
CREATE OR REPLACE FUNCTION device_replacements_no_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'device_replacements rows are kept' USING ERRCODE = 'integrity_constraint_violation';
END $$ LANGUAGE plpgsql;
CREATE TRIGGER device_replacements_no_delete BEFORE DELETE ON device_replacements FOR EACH ROW EXECUTE FUNCTION device_replacements_no_delete();

-- Authorizations are created PENDING_USER / PENDING (migration 024, audit finding C-05).
DO $$
DECLARE bad TEXT;
BEGIN
  SELECT string_agg(authorization_id::text || ' (' || bank_transaction_state || ')', ', ') INTO bad
    FROM authorization_requests
   WHERE bank_transaction_state NOT IN ('PENDING','COMMIT_REQUESTED','COMMITTED','FAILED','CANCELLED');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'authorizations with an unknown bank_transaction_state: %', bad;
  END IF;
END $$;

ALTER TABLE authorization_requests DROP CONSTRAINT IF EXISTS authorization_requests_bank_state_check;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_bank_state_check
  CHECK (bank_transaction_state IN ('PENDING','COMMIT_REQUESTED','COMMITTED','FAILED','CANCELLED'));

CREATE OR REPLACE FUNCTION authorization_insert_state() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.state <> 'PENDING_USER' OR NEW.bank_transaction_state <> 'PENDING'
     OR NEW.signature IS NOT NULL OR NEW.signature_format IS NOT NULL OR NEW.confirmation_method IS NOT NULL
     OR NEW.verified_at IS NOT NULL OR NEW.consumed_at IS NOT NULL
     OR NEW.bank_transaction_reference IS NOT NULL OR NEW.bank_commit_at IS NOT NULL
     OR NEW.offline_code_tag IS NOT NULL OR NEW.offline_code_accepted_at IS NOT NULL
     OR NEW.offline_signature_deadline IS NOT NULL OR NEW.offline_unsigned_reason IS NOT NULL THEN
    RAISE EXCEPTION 'authorization %: an authorization is created PENDING_USER with bank transaction PENDING and nothing confirmed', NEW.authorization_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authorization_insert_state ON authorization_requests;
CREATE TRIGGER authorization_insert_state BEFORE INSERT ON authorization_requests
  FOR EACH ROW EXECUTE FUNCTION authorization_insert_state();

-- Evidence for every outcome (migration 025, audit finding B-04).

ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS evidence_records_record_type_check;
ALTER TABLE evidence_records ADD CONSTRAINT evidence_records_record_type_check
  CHECK (record_type IN ('AUTHORIZATION','CREDENTIAL_ENROLLED','RECOVERY_CONFIGURED','AUTHORIZATION_OUTCOME','CREDENTIAL_REVOKED'));
ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS evidence_records_outcome_fields_check;
ALTER TABLE evidence_records ADD CONSTRAINT evidence_records_outcome_fields_check
  CHECK (record_type <> 'AUTHORIZATION_OUTCOME' OR (authorization_id IS NOT NULL AND transaction_reference IS NOT NULL
         AND canonical_payload_hash IS NOT NULL AND result IS NOT NULL));

CREATE TABLE IF NOT EXISTS evidence_outcomes (
    outcome_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject                    VARCHAR(16) NOT NULL CHECK (subject IN ('AUTHORIZATION','CREDENTIAL')),
    authorization_id           UUID REFERENCES authorization_requests(authorization_id),
    credential_id              UUID NOT NULL REFERENCES credentials(credential_id),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    outcome                    VARCHAR(24) NOT NULL
                               CHECK (outcome IN ('REJECTED','EXPIRED','CANCELLED','OFFLINE_UNSIGNED','REVOKED')),
    reason                     VARCHAR(64) NOT NULL,
    occurred_at                TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    evidence_id                UUID UNIQUE REFERENCES evidence_records(evidence_id),
    sealed_at                  TIMESTAMPTZ,
    CHECK ((subject = 'AUTHORIZATION') = (authorization_id IS NOT NULL)),
    CHECK ((evidence_id IS NULL) = (sealed_at IS NULL))
);
-- One outcome per authorization (its final state) and per credential revocation.
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_outcomes_authorization ON evidence_outcomes(authorization_id) WHERE subject = 'AUTHORIZATION';
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_outcomes_credential ON evidence_outcomes(credential_id) WHERE subject = 'CREDENTIAL';
CREATE INDEX IF NOT EXISTS idx_evidence_outcomes_unsealed ON evidence_outcomes(occurred_at) WHERE evidence_id IS NULL;

-- Rows are never deleted; only evidence_id and sealed_at change, once.
CREATE OR REPLACE FUNCTION evidence_outcomes_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'evidence_outcomes rows are kept (DELETE refused)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.evidence_id IS NOT NULL
     OR (NEW.outcome_id, NEW.subject, NEW.authorization_id, NEW.credential_id, NEW.nexus_id, NEW.outcome, NEW.reason, NEW.occurred_at)
        IS DISTINCT FROM (OLD.outcome_id, OLD.subject, OLD.authorization_id, OLD.credential_id, OLD.nexus_id, OLD.outcome, OLD.reason, OLD.occurred_at) THEN
    RAISE EXCEPTION 'evidence outcome %: only the sealing record is set, once', OLD.outcome_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_outcomes_guard ON evidence_outcomes;
CREATE TRIGGER evidence_outcomes_guard BEFORE UPDATE OR DELETE ON evidence_outcomes
  FOR EACH ROW EXECUTE FUNCTION evidence_outcomes_guard();
DROP TRIGGER IF EXISTS evidence_outcomes_no_truncate ON evidence_outcomes;
CREATE TRIGGER evidence_outcomes_no_truncate BEFORE TRUNCATE ON evidence_outcomes
  FOR EACH STATEMENT EXECUTE FUNCTION nexus_evidence_append_only();

-- The reason comes from the transaction that changed the state
-- (set_config('nexus.outcome_reason', ..., true)), or a default per state.
CREATE OR REPLACE FUNCTION record_authorization_outcome() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE given TEXT := nullif(current_setting('nexus.outcome_reason', true), '');
BEGIN
  IF NEW.state IN ('REJECTED','EXPIRED','CANCELLED','OFFLINE_UNSIGNED') AND NEW.state IS DISTINCT FROM OLD.state THEN
    INSERT INTO evidence_outcomes (subject, authorization_id, credential_id, nexus_id, outcome, reason)
    VALUES ('AUTHORIZATION', NEW.authorization_id, NEW.credential_id, NEW.nexus_id, NEW.state,
            left(coalesce(given, CASE NEW.state WHEN 'OFFLINE_UNSIGNED' THEN coalesce(NEW.offline_unsigned_reason, 'offline_unsigned')
                                                WHEN 'EXPIRED' THEN 'expired'
                                                WHEN 'CANCELLED' THEN 'cancelled'
                                                ELSE 'rejected' END), 64));
  END IF;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS authorization_outcome_evidence ON authorization_requests;
CREATE TRIGGER authorization_outcome_evidence AFTER UPDATE ON authorization_requests
  FOR EACH ROW EXECUTE FUNCTION record_authorization_outcome();

CREATE OR REPLACE FUNCTION record_credential_revocation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.state = 'REVOKED' AND OLD.state IS DISTINCT FROM 'REVOKED' THEN
    INSERT INTO evidence_outcomes (subject, credential_id, nexus_id, outcome, reason)
    VALUES ('CREDENTIAL', NEW.credential_id, NEW.nexus_id, 'REVOKED',
            left(coalesce(nullif(current_setting('nexus.outcome_reason', true), ''), 'revoked'), 64));
  END IF;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS credential_revocation_evidence ON credentials;
CREATE TRIGGER credential_revocation_evidence AFTER UPDATE ON credentials
  FOR EACH ROW EXECUTE FUNCTION record_credential_revocation();

-- Customer security settings (migration 026).
CREATE TABLE IF NOT EXISTS customer_settings_versions (
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    version                    INTEGER NOT NULL CHECK (version > 0),
    currency                   CHAR(3) CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
    per_payment_limit_minor    NUMERIC(30,0) CHECK (per_payment_limit_minor IS NULL OR per_payment_limit_minor >= 0),
    daily_limit_minor          NUMERIC(30,0) CHECK (daily_limit_minor IS NULL OR daily_limit_minor >= 0),
    video_check_above_minor    NUMERIC(30,0) CHECK (video_check_above_minor IS NULL OR video_check_above_minor >= 0),
    channels                   JSONB NOT NULL DEFAULT '{"push": true, "audio": true, "video": true}'::jsonb,
    changed_by_credential_id   UUID NOT NULL REFERENCES credentials(credential_id),
    relaxes                    BOOLEAN NOT NULL,
    effective_at               TIMESTAMPTZ NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (nexus_id, version),
    CHECK (currency IS NOT NULL OR (per_payment_limit_minor IS NULL AND daily_limit_minor IS NULL AND video_check_above_minor IS NULL)),
    CHECK (effective_at >= created_at - interval '1 second')
);
CREATE OR REPLACE FUNCTION customer_settings_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  RAISE EXCEPTION 'customer_settings_versions is append-only (% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;
DROP TRIGGER IF EXISTS customer_settings_append_only ON customer_settings_versions;
CREATE TRIGGER customer_settings_append_only BEFORE UPDATE OR DELETE ON customer_settings_versions
  FOR EACH ROW EXECUTE FUNCTION customer_settings_append_only();

-- Several active devices per NEXUS ID (migration 027).
-- Several active devices per NEXUS ID (a phone and a tablet), up to a limit
-- the bank sets per bank client. Default 1: an existing bank keeps one device
-- per customer until it raises the limit.
ALTER TABLE bank_clients ADD COLUMN IF NOT EXISTS max_devices_per_identity INTEGER NOT NULL DEFAULT 1;
ALTER TABLE bank_clients DROP CONSTRAINT IF EXISTS bank_clients_max_devices_check;
ALTER TABLE bank_clients ADD CONSTRAINT bank_clients_max_devices_check CHECK (max_devices_per_identity BETWEEN 1 AND 10);

-- A device request is a replacement (the new device takes over, every active
-- one is revoked) or an addition (the new device joins, none is revoked).
-- Both wait for the approval of an enrolled device or the end of the hold.
ALTER TABLE device_replacements ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'REPLACEMENT';
ALTER TABLE device_replacements DROP CONSTRAINT IF EXISTS device_replacements_kind_check;
ALTER TABLE device_replacements ADD CONSTRAINT device_replacements_kind_check CHECK (kind IN ('REPLACEMENT', 'ADDITION'));

CREATE OR REPLACE FUNCTION device_replacements_lifecycle() RETURNS trigger AS $$
BEGIN
  IF NEW.replacement_id <> OLD.replacement_id OR NEW.nexus_id <> OLD.nexus_id OR NEW.client_id <> OLD.client_id
     OR NEW.method <> OLD.method OR NEW.reference <> OLD.reference OR NEW.requested_at <> OLD.requested_at
     OR NEW.not_before <> OLD.not_before OR NEW.expires_at <> OLD.expires_at OR NEW.kind <> OLD.kind THEN
    RAISE EXCEPTION 'device replacement % : only its state changes', OLD.replacement_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT (OLD.state = NEW.state
          OR (OLD.state = 'PENDING' AND NEW.state IN ('APPROVED', 'CANCELLED', 'USED', 'EXPIRED'))
          OR (OLD.state = 'APPROVED' AND NEW.state IN ('USED', 'EXPIRED'))) THEN
    RAISE EXCEPTION 'device replacement % : % -> % is not permitted', OLD.replacement_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp;

-- The one-ACTIVE index (migration 017) becomes a limit the database enforces
-- with the identity row locked, so concurrent enrolments are counted.
DROP INDEX IF EXISTS idx_credentials_one_active;
CREATE INDEX IF NOT EXISTS idx_credentials_active ON credentials(nexus_id) WHERE state = 'ACTIVE';
CREATE OR REPLACE FUNCTION credentials_device_limit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  allowed INTEGER;
  active INTEGER;
BEGIN
  IF NEW.state <> 'ACTIVE' OR (TG_OP = 'UPDATE' AND OLD.state = 'ACTIVE') THEN
    RETURN NEW;
  END IF;
  SELECT b.max_devices_per_identity INTO allowed
    FROM nexus_identities n JOIN bank_clients b ON b.client_id = n.client_id
   WHERE n.nexus_id = NEW.nexus_id FOR UPDATE OF n;
  SELECT count(*) INTO active FROM credentials
   WHERE nexus_id = NEW.nexus_id AND state = 'ACTIVE' AND credential_id <> NEW.credential_id;
  IF active >= coalesce(allowed, 1) THEN
    RAISE EXCEPTION 'NEXUS ID % already has % active device(s), the limit of its bank', NEW.nexus_id, active
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS credentials_device_limit ON credentials;
CREATE TRIGGER credentials_device_limit BEFORE INSERT OR UPDATE ON credentials
  FOR EACH ROW EXECUTE FUNCTION credentials_device_limit();

-- Recurring payment mandates (migration 028).
-- Recurring payment mandates (presentation pages 17 to 19). The customer
-- signs the mandate's terms on an enrolled device; Auth Core and the database
-- check every debit against them. The bank cannot change signed terms: they
-- are immutable, and changed terms are a new mandate the customer signs.
CREATE TABLE IF NOT EXISTS mandates (
    mandate_id                 UUID PRIMARY KEY,
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    credential_id              UUID NOT NULL REFERENCES credentials(credential_id),
    mandate_reference          VARCHAR(128) NOT NULL,
    payee                      JSONB NOT NULL,
    currency                   CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    per_payment_limit_minor    NUMERIC(30,0) NOT NULL CHECK (per_payment_limit_minor > 0),
    total_limit_minor          NUMERIC(30,0) CHECK (total_limit_minor IS NULL OR total_limit_minor > 0),
    frequency                  VARCHAR(16) NOT NULL CHECK (frequency IN ('WEEKLY','MONTHLY','QUARTERLY','YEARLY')),
    valid_from                 TIMESTAMPTZ NOT NULL,
    valid_until                TIMESTAMPTZ NOT NULL,
    terms_version              VARCHAR(64) NOT NULL,
    -- The exact bytes the device shows and signs, and their SHA-256.
    canonical_terms            BYTEA NOT NULL,
    terms_hash                 CHAR(64) NOT NULL CHECK (terms_hash ~ '^[0-9a-f]{64}$'),
    offer_expires_at           TIMESTAMPTZ NOT NULL,
    state                      VARCHAR(24) NOT NULL DEFAULT 'PENDING_SIGNATURE'
                               CHECK (state IN ('PENDING_SIGNATURE','ACTIVE','SUSPENDED','REVOKED','EXPIRED','DECLINED','WITHDRAWN')),
    signature                  TEXT,
    signature_format           VARCHAR(8) CHECK (signature_format IS NULL OR signature_format IN ('der','raw')),
    signed_at                  TIMESTAMPTZ,
    state_reason               VARCHAR(128),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_until > valid_from),
    CHECK (total_limit_minor IS NULL OR total_limit_minor >= per_payment_limit_minor),
    CHECK ((state IN ('PENDING_SIGNATURE','DECLINED') OR (state IN ('EXPIRED','WITHDRAWN') AND signature IS NULL)) = (signature IS NULL)),
    UNIQUE (client_id, mandate_reference)
);
CREATE INDEX IF NOT EXISTS idx_mandates_nexus ON mandates(nexus_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mandates_expiry ON mandates(valid_until) WHERE state IN ('ACTIVE','SUSPENDED');
CREATE INDEX IF NOT EXISTS idx_mandates_offer ON mandates(offer_expires_at) WHERE state = 'PENDING_SIGNATURE';

CREATE OR REPLACE FUNCTION mandates_insert_state() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF NEW.state <> 'PENDING_SIGNATURE' OR NEW.signature IS NOT NULL OR NEW.signed_at IS NOT NULL THEN
    RAISE EXCEPTION 'mandate %: a mandate is created PENDING_SIGNATURE without a signature', NEW.mandate_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS mandates_insert_state ON mandates;
CREATE TRIGGER mandates_insert_state BEFORE INSERT ON mandates FOR EACH ROW EXECUTE FUNCTION mandates_insert_state();

CREATE OR REPLACE FUNCTION mandates_lifecycle() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE allowed BOOLEAN;
BEGIN
  IF (NEW.mandate_id, NEW.client_id, NEW.nexus_id, NEW.credential_id, NEW.mandate_reference, NEW.payee, NEW.currency,
      NEW.per_payment_limit_minor, NEW.total_limit_minor, NEW.frequency, NEW.valid_from, NEW.valid_until, NEW.terms_version,
      NEW.canonical_terms, NEW.terms_hash, NEW.offer_expires_at, NEW.created_at)
     IS DISTINCT FROM
     (OLD.mandate_id, OLD.client_id, OLD.nexus_id, OLD.credential_id, OLD.mandate_reference, OLD.payee, OLD.currency,
      OLD.per_payment_limit_minor, OLD.total_limit_minor, OLD.frequency, OLD.valid_from, OLD.valid_until, OLD.terms_version,
      OLD.canonical_terms, OLD.terms_hash, OLD.offer_expires_at, OLD.created_at) THEN
    RAISE EXCEPTION 'mandate %: the terms are immutable; changed terms are a new mandate', OLD.mandate_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.signature IS NOT NULL AND (NEW.signature, NEW.signature_format, NEW.signed_at) IS DISTINCT FROM (OLD.signature, OLD.signature_format, OLD.signed_at) THEN
    RAISE EXCEPTION 'mandate %: the signature is set once', OLD.mandate_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state THEN
    allowed := CASE OLD.state
      WHEN 'PENDING_SIGNATURE' THEN NEW.state IN ('ACTIVE','DECLINED','WITHDRAWN','EXPIRED')
      WHEN 'ACTIVE' THEN NEW.state IN ('SUSPENDED','REVOKED','EXPIRED','WITHDRAWN')
      WHEN 'SUSPENDED' THEN NEW.state IN ('ACTIVE','REVOKED','EXPIRED','WITHDRAWN')
      ELSE FALSE END;
    IF NOT allowed THEN
      RAISE EXCEPTION 'mandate %: % -> % is not a permitted transition', OLD.mandate_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.state = 'PENDING_SIGNATURE' AND NEW.state = 'ACTIVE' AND (NEW.signature IS NULL OR NEW.signed_at IS NULL OR NEW.signature_format IS NULL) THEN
      RAISE EXCEPTION 'mandate %: ACTIVE needs the customer''s signature', OLD.mandate_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS mandates_lifecycle ON mandates;
CREATE TRIGGER mandates_lifecycle BEFORE UPDATE ON mandates FOR EACH ROW EXECUTE FUNCTION mandates_lifecycle();

-- Every debit the bank asked about, allowed or refused; append-only.
CREATE TABLE IF NOT EXISTS mandate_debits (
    debit_id                   UUID PRIMARY KEY,
    mandate_id                 UUID NOT NULL REFERENCES mandates(mandate_id),
    debit_reference            VARCHAR(128) NOT NULL,
    amount_minor               NUMERIC(30,0) NOT NULL CHECK (amount_minor > 0),
    currency                   CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    period_start               DATE NOT NULL,
    decision                   VARCHAR(8) NOT NULL CHECK (decision IN ('ALLOWED','REFUSED')),
    reason                     VARCHAR(64),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (mandate_id, debit_reference),
    CHECK ((decision = 'REFUSED') = (reason IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_mandate_debits_period ON mandate_debits(mandate_id, period_start) WHERE decision = 'ALLOWED';

-- The period a debit falls in (UTC calendar week, month, quarter or year).
CREATE OR REPLACE FUNCTION mandate_period_start(frequency TEXT, at TIMESTAMPTZ) RETURNS DATE
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
  SELECT date_trunc(CASE frequency WHEN 'WEEKLY' THEN 'week' WHEN 'MONTHLY' THEN 'month' WHEN 'QUARTERLY' THEN 'quarter' ELSE 'year' END,
                    at AT TIME ZONE 'UTC')::date
$$;

-- The database decides an ALLOWED debit itself, with the mandate row locked,
-- so a defect or a direct write cannot let a debit outside the signed terms
-- through: active, in validity, same currency, within the per-payment and the
-- total limit, at most one allowed debit per period.
CREATE OR REPLACE FUNCTION mandate_debits_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE m RECORD; used NUMERIC; in_period INTEGER;
BEGIN
  IF NEW.decision <> 'ALLOWED' THEN RETURN NEW; END IF;
  SELECT * INTO m FROM mandates WHERE mandate_id = NEW.mandate_id FOR UPDATE;
  IF m.state <> 'ACTIVE' OR m.signature IS NULL OR now() < m.valid_from OR now() >= m.valid_until
     OR NEW.currency <> m.currency OR NEW.amount_minor > m.per_payment_limit_minor
     OR NEW.period_start <> mandate_period_start(m.frequency, now()) THEN
    RAISE EXCEPTION 'mandate %: debit outside the signed terms', NEW.mandate_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  SELECT count(*), coalesce(sum(amount_minor), 0) INTO in_period, used FROM mandate_debits
   WHERE mandate_id = NEW.mandate_id AND decision = 'ALLOWED' AND period_start = NEW.period_start;
  IF in_period > 0 THEN
    RAISE EXCEPTION 'mandate %: a debit was already allowed in this period', NEW.mandate_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF m.total_limit_minor IS NOT NULL THEN
    SELECT coalesce(sum(amount_minor), 0) INTO used FROM mandate_debits WHERE mandate_id = NEW.mandate_id AND decision = 'ALLOWED';
    IF used + NEW.amount_minor > m.total_limit_minor THEN
      RAISE EXCEPTION 'mandate %: debit above the total limit', NEW.mandate_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS mandate_debits_check ON mandate_debits;
CREATE TRIGGER mandate_debits_check BEFORE INSERT ON mandate_debits FOR EACH ROW EXECUTE FUNCTION mandate_debits_check();

CREATE OR REPLACE FUNCTION mandate_rows_kept() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION '% rows are kept (% refused)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'integrity_constraint_violation';
END $$;
DROP TRIGGER IF EXISTS mandates_no_delete ON mandates;
CREATE TRIGGER mandates_no_delete BEFORE DELETE ON mandates FOR EACH ROW EXECUTE FUNCTION mandate_rows_kept();
DROP TRIGGER IF EXISTS mandate_debits_append_only ON mandate_debits;
CREATE TRIGGER mandate_debits_append_only BEFORE UPDATE OR DELETE ON mandate_debits FOR EACH ROW EXECUTE FUNCTION mandate_rows_kept();

-- Sealed mandate events in the identity's evidence chain.
ALTER TABLE evidence_records ADD COLUMN IF NOT EXISTS mandate_id UUID REFERENCES mandates(mandate_id);
ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS evidence_records_record_type_check;
ALTER TABLE evidence_records ADD CONSTRAINT evidence_records_record_type_check
  CHECK (record_type IN ('AUTHORIZATION','CREDENTIAL_ENROLLED','RECOVERY_CONFIGURED','AUTHORIZATION_OUTCOME','CREDENTIAL_REVOKED','MANDATE'));
ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS evidence_records_mandate_fields_check;
ALTER TABLE evidence_records ADD CONSTRAINT evidence_records_mandate_fields_check
  CHECK ((record_type = 'MANDATE') = (mandate_id IS NOT NULL));

-- Conversations with the bank (migration 029).
-- Conversations between a customer and the bank inside the bank's app
-- (presentation pages 11 and 12): customer messages, the bank's bot (run by
-- the bank, posting through the bank API) and the bank's operators after a
-- handover. Each conversation belongs to one NEXUS ID of one bank client.
-- Messages are append-only and hash-chained per conversation; only their
-- delivery and read marks are set, once each.
CREATE TABLE IF NOT EXISTS conversations (
    conversation_id            UUID PRIMARY KEY,
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    topic                      VARCHAR(200) NOT NULL,
    -- A payment the conversation is about (the "transaction card").
    authorization_id           UUID REFERENCES authorization_requests(authorization_id),
    state                      VARCHAR(24) NOT NULL DEFAULT 'WITH_BOT'
                               CHECK (state IN ('WITH_BOT','WAITING_FOR_AGENT','WITH_AGENT','CLOSED')),
    assigned_operator          TEXT,
    handover_reason            VARCHAR(200),
    last_sequence              INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_message_hash          CHAR(64),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at                  TIMESTAMPTZ,
    CHECK ((state = 'WITH_AGENT') = (assigned_operator IS NOT NULL)),
    CHECK ((state = 'CLOSED') = (closed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_conversations_nexus ON conversations(nexus_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_conversations_queue ON conversations(client_id, updated_at) WHERE state = 'WAITING_FOR_AGENT';

CREATE OR REPLACE FUNCTION conversations_lifecycle() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE allowed BOOLEAN;
BEGIN
  IF (NEW.conversation_id, NEW.client_id, NEW.nexus_id, NEW.topic, NEW.authorization_id, NEW.created_at)
     IS DISTINCT FROM (OLD.conversation_id, OLD.client_id, OLD.nexus_id, OLD.topic, OLD.authorization_id, OLD.created_at) THEN
    RAISE EXCEPTION 'conversation %: owner, topic and subject are immutable', OLD.conversation_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.last_sequence < OLD.last_sequence THEN
    RAISE EXCEPTION 'conversation %: messages are never removed', OLD.conversation_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state THEN
    allowed := CASE OLD.state
      WHEN 'WITH_BOT' THEN NEW.state IN ('WAITING_FOR_AGENT','CLOSED')
      WHEN 'WAITING_FOR_AGENT' THEN NEW.state IN ('WITH_AGENT','CLOSED')
      WHEN 'WITH_AGENT' THEN NEW.state IN ('WAITING_FOR_AGENT','CLOSED')
      ELSE FALSE END;
    IF NOT allowed THEN
      RAISE EXCEPTION 'conversation %: % -> % is not permitted', OLD.conversation_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS conversations_lifecycle ON conversations;
CREATE TRIGGER conversations_lifecycle BEFORE UPDATE ON conversations FOR EACH ROW EXECUTE FUNCTION conversations_lifecycle();

CREATE TABLE IF NOT EXISTS conversation_messages (
    message_id                 UUID PRIMARY KEY,
    conversation_id            UUID NOT NULL REFERENCES conversations(conversation_id),
    sequence                   INTEGER NOT NULL CHECK (sequence > 0),
    sender_type                VARCHAR(8) NOT NULL CHECK (sender_type IN ('CUSTOMER','BOT','AGENT','SYSTEM')),
    -- credential:<id>, bank:<client>, admin:<username> or system.
    sender_ref                 VARCHAR(200) NOT NULL,
    body                       TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 4000),
    -- An attachment the bank stores: its reference, SHA-256 and media type.
    attachment                 JSONB,
    client_message_id          VARCHAR(64),
    previous_hash              CHAR(64),
    message_hash               CHAR(64) NOT NULL CHECK (message_hash ~ '^[0-9a-f]{64}$'),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    delivered_at               TIMESTAMPTZ,
    read_at                    TIMESTAMPTZ,
    UNIQUE (conversation_id, sequence),
    UNIQUE (conversation_id, sender_ref, client_message_id)
);

CREATE OR REPLACE FUNCTION conversation_messages_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'conversation messages are kept' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF (NEW.message_id, NEW.conversation_id, NEW.sequence, NEW.sender_type, NEW.sender_ref, NEW.body, NEW.attachment,
      NEW.client_message_id, NEW.previous_hash, NEW.message_hash, NEW.created_at)
     IS DISTINCT FROM
     (OLD.message_id, OLD.conversation_id, OLD.sequence, OLD.sender_type, OLD.sender_ref, OLD.body, OLD.attachment,
      OLD.client_message_id, OLD.previous_hash, OLD.message_hash, OLD.created_at)
     OR (OLD.delivered_at IS NOT NULL AND NEW.delivered_at IS DISTINCT FROM OLD.delivered_at)
     OR (OLD.read_at IS NOT NULL AND NEW.read_at IS DISTINCT FROM OLD.read_at) THEN
    RAISE EXCEPTION 'conversation message %: only its delivery and read marks are set, once', OLD.message_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS conversation_messages_append_only ON conversation_messages;
CREATE TRIGGER conversation_messages_append_only BEFORE UPDATE OR DELETE ON conversation_messages
  FOR EACH ROW EXECUTE FUNCTION conversation_messages_append_only();

-- Calls the customer starts (migration 030).
-- Calls the customer starts from the bank's app (presentation page 12:
-- "talk to the bank"), outside a payment check. The bank enables the
-- channels it staffs; a call waits in the bank's operator queue, one
-- operator answers it, and either side ends it. Auth Core relays the WebRTC
-- signalling only; it never receives media and records nothing of it. The
-- row is the call's record: who asked, which device, who answered, when,
-- and how it ended.
ALTER TABLE bank_clients ADD COLUMN IF NOT EXISTS customer_call_channels VARCHAR(16)[] NOT NULL DEFAULT '{}';
ALTER TABLE bank_clients DROP CONSTRAINT IF EXISTS bank_clients_customer_call_channels_check;
ALTER TABLE bank_clients ADD CONSTRAINT bank_clients_customer_call_channels_check
    CHECK (customer_call_channels <@ ARRAY['AUDIO','VIDEO']::VARCHAR(16)[]);

CREATE TABLE IF NOT EXISTS customer_calls (
    call_id                    UUID PRIMARY KEY,
    client_id                  TEXT NOT NULL REFERENCES bank_clients(client_id),
    nexus_id                   VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    credential_id              UUID NOT NULL REFERENCES credentials(credential_id),
    channel                    VARCHAR(8) NOT NULL CHECK (channel IN ('AUDIO','VIDEO')),
    topic                      VARCHAR(200) NOT NULL,
    conversation_id            UUID REFERENCES conversations(conversation_id),
    state                      VARCHAR(16) NOT NULL DEFAULT 'WAITING'
                               CHECK (state IN ('WAITING','CONNECTED','ENDED','CANCELLED','MISSED')),
    operator                   TEXT,
    -- WAITING: until when an operator may answer. CONNECTED: the longest the call may last.
    expires_at                 TIMESTAMPTZ NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    answered_at                TIMESTAMPTZ,
    ended_at                   TIMESTAMPTZ,
    ended_by                   TEXT,
    end_reason                 VARCHAR(64),
    CHECK ((state IN ('CONNECTED','ENDED')) = (answered_at IS NOT NULL)),
    CHECK ((operator IS NULL) = (answered_at IS NULL)),
    CHECK ((state IN ('WAITING','CONNECTED')) = (ended_at IS NULL))
);
-- One open call per NEXUS ID.
CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_calls_open ON customer_calls(nexus_id) WHERE state IN ('WAITING','CONNECTED');
CREATE INDEX IF NOT EXISTS idx_customer_calls_queue ON customer_calls(client_id, created_at) WHERE state = 'WAITING';
CREATE INDEX IF NOT EXISTS idx_customer_calls_nexus ON customer_calls(nexus_id, created_at DESC);

-- WAITING -> CONNECTED | CANCELLED | MISSED; CONNECTED -> ENDED. Who asked,
-- with which device and on which channel never changes; an answered call
-- keeps its operator.
CREATE OR REPLACE FUNCTION customer_calls_lifecycle() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF (NEW.call_id, NEW.client_id, NEW.nexus_id, NEW.credential_id, NEW.channel, NEW.topic, NEW.conversation_id, NEW.created_at)
     IS DISTINCT FROM (OLD.call_id, OLD.client_id, OLD.nexus_id, OLD.credential_id, OLD.channel, OLD.topic, OLD.conversation_id, OLD.created_at) THEN
    RAISE EXCEPTION 'customer call %: who called and how is immutable', OLD.call_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.operator IS NOT NULL AND NEW.operator IS DISTINCT FROM OLD.operator THEN
    RAISE EXCEPTION 'customer call %: the operator who answered is kept', OLD.call_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'WAITING' AND NEW.state IN ('CONNECTED','CANCELLED','MISSED'))
    OR (OLD.state = 'CONNECTED' AND NEW.state = 'ENDED')) THEN
    RAISE EXCEPTION 'customer call %: % -> % is not a permitted transition', OLD.call_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.state IN ('ENDED','CANCELLED','MISSED') AND ROW(NEW.*) IS DISTINCT FROM ROW(OLD.*) THEN
    RAISE EXCEPTION 'customer call %: a finished call is kept as it ended', OLD.call_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS customer_calls_lifecycle ON customer_calls;
CREATE TRIGGER customer_calls_lifecycle BEFORE UPDATE ON customer_calls FOR EACH ROW EXECUTE FUNCTION customer_calls_lifecycle();

CREATE OR REPLACE FUNCTION customer_calls_kept() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'customer calls are kept as records' USING ERRCODE = 'integrity_constraint_violation';
END $$;
DROP TRIGGER IF EXISTS customer_calls_no_delete ON customer_calls;
CREATE TRIGGER customer_calls_no_delete BEFORE DELETE ON customer_calls FOR EACH ROW EXECUTE FUNCTION customer_calls_kept();
