-- 019: authenticated audio/video verification results and the
-- channels each bank can actually verify.
--
-- A result advances a verification plan only if it is either a JWS signed by
-- a verification provider key registered for the bank (PROVIDER), or the
-- decision of an authenticated bank operator in the admin console after an
-- in-app call (OPERATOR). Re-runnable.

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
