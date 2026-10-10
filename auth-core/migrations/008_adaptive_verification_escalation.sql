-- 008: adaptive verification plans and verification sessions.
CREATE TABLE IF NOT EXISTS authorization_verification_plans (
  authorization_id UUID PRIMARY KEY REFERENCES authorization_requests(authorization_id) ON DELETE CASCADE,
  nexus_id VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
  client_id TEXT NOT NULL REFERENCES bank_clients(client_id),
  policy_version VARCHAR(64) NOT NULL,
  required_step VARCHAR(16) NOT NULL CHECK (required_step IN ('PUSH','AUDIO','VIDEO')),
  current_step VARCHAR(16) NOT NULL CHECK (current_step IN ('PUSH','AUDIO','VIDEO')),
  allowed_steps VARCHAR(16)[] NOT NULL,
  audio_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  video_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  push_timeout_seconds INTEGER NOT NULL CHECK (push_timeout_seconds BETWEEN 10 AND 300),
  high_amount_threshold_minor NUMERIC(30,0),
  client_escalation_allowed BOOLEAN NOT NULL DEFAULT TRUE,
  status VARCHAR(16) NOT NULL CHECK (status IN ('PENDING','IN_PROGRESS','VERIFIED','FAILED','EXPIRED','CANCELLED')),
  last_escalation_reason VARCHAR(32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS verification_sessions (
  session_id UUID PRIMARY KEY,
  authorization_id UUID NOT NULL REFERENCES authorization_requests(authorization_id) ON DELETE CASCADE,
  nexus_id VARCHAR(9) NOT NULL REFERENCES nexus_identities(nexus_id),
  client_id TEXT NOT NULL REFERENCES bank_clients(client_id),
  channel VARCHAR(16) NOT NULL CHECK (channel IN ('PUSH','AUDIO','VIDEO')),
  nonce_hash CHAR(64) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  status VARCHAR(16) NOT NULL CHECK (status IN ('IN_PROGRESS','VERIFIED','FAILED','EXPIRED','CANCELLED')),
  provider_reference VARCHAR(128),
  assertion_hash CHAR(64),
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_verification_sessions_authorization ON verification_sessions(authorization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_verification_sessions_expiry ON verification_sessions(expires_at) WHERE status='IN_PROGRESS';

ALTER TABLE evidence_records ADD COLUMN IF NOT EXISTS verification_factors JSONB NOT NULL DEFAULT '[]'::jsonb;
