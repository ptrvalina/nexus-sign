-- 002: NEXUS identities, credentials and authorization protocol v1.
-- Incremental migration from the existing identity/challenge schema.
-- Run after the existing auth-core schema and bank_clients are present.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS nexus_identities (
    nexus_id              VARCHAR(9) PRIMARY KEY
                          CHECK (nexus_id ~ '^[0-9]{9}$'),
    client_id             TEXT NOT NULL REFERENCES bank_clients(client_id),
    bank_customer_ref     VARCHAR(128) NOT NULL,
    status                VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
                          CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at          TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_nexus_identity_customer
    ON nexus_identities(client_id, bank_customer_ref)
    WHERE status <> 'REVOKED';

CREATE TABLE IF NOT EXISTS credentials (
    credential_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nexus_id              VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    key_algorithm         VARCHAR(32) NOT NULL CHECK (key_algorithm IN ('ES256')),
    public_key_pem        TEXT NOT NULL,
    platform              VARCHAR(16) NOT NULL CHECK (platform IN ('IOS','ANDROID','OTHER')),
    security_level        VARCHAR(32) NOT NULL,
    attestation_status    VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN'
                          CHECK (attestation_status IN ('UNKNOWN','VERIFIED','FAILED','EXPIRED')),
    state                 VARCHAR(16) NOT NULL DEFAULT 'PENDING'
                          CHECK (state IN ('PENDING','ACTIVE','SUSPENDED','REVOKED')),
    key_version           INTEGER NOT NULL DEFAULT 1,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at          TIMESTAMPTZ,
    suspended_at          TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    last_used_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_credentials_nexus_id ON credentials(nexus_id);
CREATE INDEX IF NOT EXISTS idx_credentials_state ON credentials(state);

CREATE TABLE IF NOT EXISTS authorization_requests (
    authorization_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                 TEXT NOT NULL REFERENCES bank_clients(client_id),
    nexus_id                  VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    credential_id             UUID REFERENCES credentials(credential_id),
    transaction_reference     VARCHAR(128) NOT NULL,
    operation_type            VARCHAR(32) NOT NULL,
    amount_minor              NUMERIC(30,0) NOT NULL CHECK (amount_minor >= 0),
    currency                  CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    beneficiary               JSONB NOT NULL,
    protocol_version          VARCHAR(16) NOT NULL DEFAULT '1',
    domain                    VARCHAR(128) NOT NULL DEFAULT 'NEXUS-SIGN/TRANSACTION-AUTH',
    policy_reference          VARCHAR(128) NOT NULL,
    policy_version            VARCHAR(64) NOT NULL,
    canonical_payload_hash    CHAR(64) NOT NULL,
    nonce                     VARCHAR(128) NOT NULL,
    issued_at                 TIMESTAMPTZ NOT NULL,
    expires_at                TIMESTAMPTZ NOT NULL,
    state                     VARCHAR(16) NOT NULL DEFAULT 'CREATED'
                              CHECK (state IN ('CREATED','DELIVERING','PENDING_USER','SIGNED','VERIFIED','CONSUMED','EXPIRED','CANCELLED','REJECTED')),
    signature                 TEXT,
    signature_algorithm       VARCHAR(32) NOT NULL DEFAULT 'ES256',
    signature_format          VARCHAR(8),
    verified_at               TIMESTAMPTZ,
    consumed_at               TIMESTAMPTZ,
    correlation_id            VARCHAR(128),
    idempotency_key           VARCHAR(128),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_idempotency
    ON authorization_requests(client_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_transaction_reference
    ON authorization_requests(client_id, transaction_reference);

CREATE INDEX IF NOT EXISTS idx_auth_nexus_state ON authorization_requests(nexus_id, state);
CREATE INDEX IF NOT EXISTS idx_auth_expiry ON authorization_requests(expires_at);

CREATE TABLE IF NOT EXISTS authorization_attempts (
    attempt_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    authorization_id       UUID NOT NULL REFERENCES authorization_requests(authorization_id),
    credential_id          UUID REFERENCES credentials(credential_id),
    attempt_number         INTEGER NOT NULL,
    result                 VARCHAR(24) NOT NULL
                           CHECK (result IN ('INVALID_SIGNATURE','VERIFIED','EXPIRED','REJECTED','CREDENTIAL_INVALID')),
    reason_code            VARCHAR(128),
    occurred_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_ip              INET,
    user_agent             TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_attempts_authorization ON authorization_attempts(authorization_id, occurred_at);

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    authorization_id        UUID NOT NULL UNIQUE REFERENCES authorization_requests(authorization_id),
    policy_reference        VARCHAR(128) NOT NULL,
    policy_version          VARCHAR(64) NOT NULL,
    risk_context_reference  VARCHAR(128),
    decision                 VARCHAR(24) NOT NULL
                            CHECK (decision IN ('ALLOW','STEP_UP','DENY','REVIEW')),
    reason_code             VARCHAR(128),
    risk_score              NUMERIC(12,6),
    decided_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attestation_records (
    attestation_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id             UUID NOT NULL REFERENCES credentials(credential_id),
    platform                  VARCHAR(16) NOT NULL,
    verdict                   VARCHAR(32) NOT NULL,
    environment               VARCHAR(32),
    token_hash                CHAR(64),
    policy_version            VARCHAR(64),
    issued_at                 TIMESTAMPTZ,
    verified_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    details                   JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    authorization_id         UUID NOT NULL UNIQUE REFERENCES authorization_requests(authorization_id),
    nexus_id                 VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
    credential_id             UUID NOT NULL REFERENCES credentials(credential_id),
    transaction_reference    VARCHAR(128) NOT NULL,
    canonical_payload_hash   CHAR(64) NOT NULL,
    signature                TEXT NOT NULL,
    signature_algorithm      VARCHAR(32) NOT NULL,
    key_version              INTEGER NOT NULL,
    policy_version           VARCHAR(64) NOT NULL,
    attestation_verdict      VARCHAR(32),
    verified_at              TIMESTAMPTZ NOT NULL,
    consumed_at              TIMESTAMPTZ,
    result                   VARCHAR(24) NOT NULL,
    correlation_id           VARCHAR(128),
    previous_evidence_hash   CHAR(64),
    evidence_hash            CHAR(64) NOT NULL,
    hsm_signature            TEXT,
    schema_version           VARCHAR(16) NOT NULL DEFAULT '1',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evidence_nexus ON evidence_records(nexus_id);
CREATE INDEX IF NOT EXISTS idx_evidence_transaction ON evidence_records(transaction_reference);

-- Backfill the new model from the existing model where tenant ownership is known.
-- A deployment with legacy identities missing client_id must repair those rows
-- before applying this migration; silently guessing the bank would be unsafe.
DO $$
BEGIN
  -- Fresh installations have no legacy identities table; the backfill
  -- below only applies when upgrading a pre-v1 deployment.
  IF to_regclass('public.identities') IS NULL THEN
    RETURN;
  END IF;

  IF EXISTS (SELECT 1 FROM identities WHERE client_id IS NULL) THEN
    RAISE EXCEPTION 'identity migration requires identities.client_id for every legacy identity';
  END IF;

  INSERT INTO nexus_identities (nexus_id, client_id, bank_customer_ref, status, created_at, updated_at, last_used_at)
  SELECT i.nexus_id, i.client_id, i.bank_customer_id, i.status, i.created_at, i.updated_at, i.last_used_at
  FROM identities i
  ON CONFLICT (nexus_id) DO NOTHING;

  INSERT INTO credentials (
      credential_id, nexus_id, key_algorithm, public_key_pem, platform,
      security_level, attestation_status, state, key_version,
      created_at, activated_at, suspended_at, revoked_at, last_used_at
  )
  SELECT
      i.id,
      i.nexus_id,
      i.key_algorithm,
      i.public_key_pem,
      CASE
        WHEN lower(COALESCE(i.device_attestation->>'platform','')) = 'ios' THEN 'IOS'
        WHEN lower(COALESCE(i.device_attestation->>'platform','')) = 'android' THEN 'ANDROID'
        ELSE 'OTHER'
      END,
      CASE
        WHEN COALESCE((i.device_attestation->>'strongBox')::boolean, false) THEN 'STRONGBOX'
        WHEN COALESCE((i.device_attestation->>'secureEnclave')::boolean, false) THEN 'SECURE_ENCLAVE'
        ELSE 'HARDWARE_BACKED_OR_UNKNOWN'
      END,
      CASE
        WHEN COALESCE((i.device_attestation->>'serverAttestationVerdict')::jsonb->>'verified','false') = 'true' THEN 'VERIFIED'
        ELSE 'UNKNOWN'
      END,
      i.status,
      1,
      i.created_at,
      CASE WHEN i.status = 'ACTIVE' THEN i.created_at ELSE NULL END,
      CASE WHEN i.status = 'SUSPENDED' THEN i.updated_at ELSE NULL END,
      CASE WHEN i.status = 'REVOKED' THEN i.updated_at ELSE NULL END,
      i.last_used_at
  FROM identities i
  ON CONFLICT (credential_id) DO NOTHING;
END $$;
