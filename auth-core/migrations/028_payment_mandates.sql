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
