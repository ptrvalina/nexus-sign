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
