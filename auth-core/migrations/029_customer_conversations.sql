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
