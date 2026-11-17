-- The customer's own security settings: limits, the amount above which a
-- video check is required, and channel preferences. Versioned and
-- append-only; a change that makes the settings less strict takes effect only
-- after a hold (CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS), so someone holding an
-- unlocked phone cannot raise a limit and use it at once.
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
