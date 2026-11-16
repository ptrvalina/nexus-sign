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
