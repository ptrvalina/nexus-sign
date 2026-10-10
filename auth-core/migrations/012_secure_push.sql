-- 012: secure push delivery.
--
-- * bank_clients.push_mode: BANK (the bank's push system delivers
--   authorization requests) or NEXUS (Auth Core delivers them through secure push).
-- * push_registrations: the APNs or FCM token of a device credential and the
--   push key agreed with it, encrypted with DEVICE_SECRET_ENCRYPTION_KEY, with
--   the key's public ID.
-- * push_messages: outbox of messages sealed for one device.

ALTER TABLE bank_clients ADD COLUMN IF NOT EXISTS push_mode VARCHAR(16) NOT NULL DEFAULT 'BANK';
ALTER TABLE bank_clients DROP CONSTRAINT IF EXISTS bank_clients_push_mode_check;
ALTER TABLE bank_clients ADD CONSTRAINT bank_clients_push_mode_check CHECK (push_mode IN ('BANK','NEXUS'));

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
