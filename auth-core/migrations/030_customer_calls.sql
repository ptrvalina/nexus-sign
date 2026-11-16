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
