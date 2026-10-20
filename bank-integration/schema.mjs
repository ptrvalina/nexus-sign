// The bank's trust registry and execution journal (PostgreSQL), in its own
// schema `bank`, with the payment state machine enforced in the database.
//
// Authorization model (phase 15, docs/security/bank-database-authorization.md):
//   - The schema owner installs it and is never used by a service.
//   - No application role has INSERT, UPDATE, DELETE or TRUNCATE on any table,
//     or any right on a sequence. Every change is made by a SECURITY DEFINER
//     function of the owner with `search_path = pg_catalog, pg_temp` and
//     schema-qualified names; each role may execute only its own functions.
//   - Every state change names the function that makes it (`bank.via`), and
//     the transition trigger accepts only (from, to, function) triples listed
//     in bank.allowed_transitions. The same trigger writes the log row with the
//     login role (session_user) and the function: no role writes the log.
//
// Roles:
//   boundary  the execution boundary: records payments, claims, approves,
//             refuses, holds; reads the journal and the registry
//   gateway   the payment gateway's process: submits what is approved for an
//             attempt, records the provider's answers; reads nothing
//   registry  the bank's credential registry service: stores signed approvals
//             and revocations (it verifies the bank's signatures before)
//   operator  people settling REVIEW payments; reads the journal
//
// Execution states (bank.executions.state), see docs/architecture/payment-state-machine.md:
//   CHECKING          an attempt holds the payment and runs the checks
//   HELD              stopped before approval (error, unavailable service); retried
//   APPROVED          the bank's decision and final check passed: the revocation cut-off
//   SUBMITTED         the gateway recorded the command before sending it to the provider
//   PENDING_PROVIDER  the provider accepted it and has not settled it
//   OUTCOME_UNKNOWN   no answer (timeout, lost response, crash)
//   RECONCILING       an attempt asks the provider what happened
//   EXECUTED          the provider confirmed it (final)
//   PROVIDER_FAILED   the provider confirmed it failed: no money moved (final)
//   REFUSED           the bank refused it (final)
//   REVIEW            a person settles it with the provider
import { APPROVAL, REVOCATION } from '../auth-core/scripts/lib/bankTrust.mjs';

export const EXECUTION_STATES = ['CHECKING', 'HELD', 'APPROVED', 'SUBMITTED', 'PENDING_PROVIDER', 'OUTCOME_UNKNOWN', 'RECONCILING', 'EXECUTED', 'PROVIDER_FAILED', 'REFUSED', 'REVIEW'];
export const FINAL_STATES = ['EXECUTED', 'PROVIDER_FAILED', 'REFUSED'];
export const LEASE_LIMITS_MS = Object.freeze({ min: 100, max: 3_600_000 });

/** [from, to, function]: the only transitions the database accepts ('' is "no execution yet"). */
export const TRANSITIONS = Object.freeze([
  ['', 'CHECKING', 'claim'],
  ['CHECKING', 'CHECKING', 'claim'], ['HELD', 'CHECKING', 'claim'], ['APPROVED', 'HELD', 'claim'],
  ['SUBMITTED', 'RECONCILING', 'claim'], ['RECONCILING', 'RECONCILING', 'claim'],
  ['PENDING_PROVIDER', 'RECONCILING', 'claim'], ['OUTCOME_UNKNOWN', 'RECONCILING', 'claim'],
  ['CHECKING', 'APPROVED', 'approve'],
  ['CHECKING', 'REFUSED', 'refuse'],
  ['CHECKING', 'HELD', 'hold'], ['APPROVED', 'HELD', 'hold'],
  ['SUBMITTED', 'OUTCOME_UNKNOWN', 'mark_unknown'], ['RECONCILING', 'OUTCOME_UNKNOWN', 'mark_unknown'],
  ['RECONCILING', 'REVIEW', 'mark_review'],
  ['APPROVED', 'SUBMITTED', 'submit'],
  ['RECONCILING', 'SUBMITTED', 'resubmit'],
  ['APPROVED', 'REVIEW', 'gateway_refuse'], ['RECONCILING', 'REVIEW', 'gateway_refuse'],
  ...['SUBMITTED', 'RECONCILING'].flatMap((from) => ['EXECUTED', 'PROVIDER_FAILED', 'PENDING_PROVIDER', 'OUTCOME_UNKNOWN'].map((to) => [from, to, 'report'])),
  ['REVIEW', 'EXECUTED', 'resolve_review'], ['REVIEW', 'PROVIDER_FAILED', 'resolve_review'],
]);

const TABLES = ['payments', 'executions', 'execution_transitions', 'trust_statements', 'credential_trust', 'chain_heads', 'reconciliation_findings', 'allowed_transitions'];

/** Function signatures as PostgreSQL prints them (regprocedure). */
export const FUNCTIONS = Object.freeze({
  boundary: [
    'bank.create_payment(uuid,text,jsonb,uuid)', 'bank.attach_authorization(uuid,uuid)', 'bank.claim(uuid,integer)',
    'bank.approve(uuid,uuid,jsonb,integer)', 'bank.refuse(uuid,uuid,jsonb)', 'bank.hold(uuid,uuid,text,text[])',
    'bank.mark_unknown(uuid,uuid,text)', 'bank.mark_review(uuid,uuid,text)', 'bank.keep_head(character varying,integer,text)',
    'bank.add_finding(uuid,text,text,jsonb)',
  ],
  gateway: [
    'bank.submit_basis(uuid,uuid)', 'bank.submit(uuid,uuid)', 'bank.resubmit(uuid,uuid)', 'bank.gateway_refuse(uuid,uuid,text)',
    'bank.report(uuid,uuid,text,text,text)', 'bank.operation_for_lookup(uuid)',
  ],
  registry: ['bank.approve_credential(jsonb,integer,text)', 'bank.revoke_credential(jsonb)'],
  operator: ['bank.resolve_review(uuid,text,text,text)'],
});

/** Tables each role may read; no role may write any table. */
export const READS = Object.freeze({
  boundary: ['payments', 'executions', 'execution_transitions', 'trust_statements', 'chain_heads', 'reconciliation_findings'],
  gateway: [],
  registry: [],
  operator: ['payments', 'executions', 'execution_transitions', 'reconciliation_findings'],
});
export const ROLE_KINDS = Object.freeze(['boundary', 'gateway', 'registry', 'operator']);

const ident = (name) => {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(name)) throw new Error(`not a plain role name: ${name}`);
  return name;
};
const lit = (s) => `'${String(s).replace(/'/g, "''")}'`;
const transitionRows = TRANSITIONS.map(([f, t, v]) => `(${lit(f)}, ${lit(t)}, ${lit(v)})`).join(', ');
const LEASE = `IF p_lease_ms IS NULL OR p_lease_ms < ${LEASE_LIMITS_MS.min} OR p_lease_ms > ${LEASE_LIMITS_MS.max} THEN
    RAISE EXCEPTION 'a lease of % ms is outside ${LEASE_LIMITS_MS.min}..${LEASE_LIMITS_MS.max} ms', p_lease_ms USING ERRCODE = 'invalid_parameter_value';
  END IF;`;
// Every function: owner's rights, nothing found through the caller's search_path.
const DEFINER = `SECURITY DEFINER SET search_path = pg_catalog, pg_temp`;

export const SCHEMA = `
CREATE TABLE IF NOT EXISTS bank.trust_statements (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  credential_id UUID NOT NULL,
  nexus_id VARCHAR(9) NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('${APPROVAL}', '${REVOCATION}')),
  entry JSONB NOT NULL,
  recorded_by TEXT NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS trust_statements_nexus ON bank.trust_statements (nexus_id);
CREATE TABLE IF NOT EXISTS bank.credential_trust (
  credential_id UUID PRIMARY KEY,
  nexus_id VARCHAR(9) NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('APPROVED', 'REVOKED')),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank.chain_heads (
  nexus_id VARCHAR(9) PRIMARY KEY,
  chain_sequence INTEGER NOT NULL CHECK (chain_sequence > 0),
  evidence_hash CHAR(64) NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank.payments (
  payment_id UUID PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('CREATED', 'AWAITING_AUTHORIZATION')),
  authorization_id UUID UNIQUE,
  bank_transaction_reference TEXT NOT NULL UNIQUE,
  terms JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((status = 'CREATED') = (authorization_id IS NULL))
);
CREATE TABLE IF NOT EXISTS bank.executions (
  payment_id UUID PRIMARY KEY REFERENCES bank.payments (payment_id),
  state TEXT NOT NULL CHECK (state IN (${EXECUTION_STATES.map(lit).join(', ')})),
  attempt_id UUID NOT NULL,
  lease_until TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 1,
  credential_id UUID,
  order_hash CHAR(64),
  approval_evidence JSONB,
  approval_registry_id BIGINT,
  submissions INTEGER NOT NULL DEFAULT 0,
  provider_reference TEXT,
  problems JSONB,
  resolved_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank.execution_transitions (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  payment_id UUID NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  attempt_id UUID NOT NULL,
  actor TEXT NOT NULL,
  via TEXT NOT NULL,
  at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS execution_transitions_payment ON bank.execution_transitions (payment_id, id);
CREATE TABLE IF NOT EXISTS bank.reconciliation_findings (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  payment_id UUID NOT NULL REFERENCES bank.payments (payment_id),
  local_state TEXT NOT NULL,
  provider_status TEXT NOT NULL,
  detail JSONB,
  recorded_by TEXT NOT NULL,
  found_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank.allowed_transitions (
  from_state TEXT NOT NULL, to_state TEXT NOT NULL, via TEXT NOT NULL, PRIMARY KEY (from_state, to_state, via)
);
DELETE FROM bank.allowed_transitions;
INSERT INTO bank.allowed_transitions VALUES ${transitionRows};

-- Internal helpers: not executable by any role.
CREATE OR REPLACE FUNCTION bank.via(p_name TEXT) RETURNS VOID LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN PERFORM set_config('bank.via', p_name, true); END $$;

-- The order the bank pays: from its own record of the payment, nothing else.
CREATE OR REPLACE FUNCTION bank.order_document(p_payment UUID) RETURNS JSONB LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object(
    'operationId', p.bank_transaction_reference, 'paymentId', p.payment_id::text, 'reference', p.terms->>'transactionReference',
    'operationType', p.terms->'operationType', 'amountMinor', p.terms->>'amountMinor', 'currency', p.terms->>'currency',
    'beneficiary', p.terms->'beneficiary')
  FROM bank.payments p WHERE p.payment_id = p_payment
$$;
CREATE OR REPLACE FUNCTION bank.order_hash(p_document JSONB) RETURNS TEXT LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT encode(sha256(convert_to(p_document::text, 'UTF8')), 'hex')
$$;

-- What the confirmation evidence must say about this payment. The signatures
-- are verified by the boundary and again by the gateway (PostgreSQL has no
-- ECDSA); this binds the evidence to the payment, the customer and the terms.
CREATE OR REPLACE FUNCTION bank.evidence_problem(p_payment UUID, p_evidence JSONB) RETURNS TEXT
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  pay bank.payments%ROWTYPE; sealed JSONB; signed_bytes BYTEA; signed JSONB;
BEGIN
  SELECT * INTO pay FROM bank.payments p WHERE p.payment_id = p_payment;
  sealed := p_evidence->'sealedPayload';
  IF jsonb_typeof(sealed) IS DISTINCT FROM 'object' OR sealed->>'schemaVersion' IS DISTINCT FROM '3' OR sealed->>'recordType' IS DISTINCT FROM 'AUTHORIZATION' THEN
    RETURN 'the evidence is not a schema 3 AUTHORIZATION record';
  END IF;
  IF coalesce(p_evidence->>'evidenceHash', '') !~ '^[0-9a-f]{64}$' THEN RETURN 'the evidence has no evidence hash'; END IF;
  IF coalesce(sealed->>'credentialId', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN RETURN 'the evidence names no credential'; END IF;
  IF sealed->>'authorizationId' IS DISTINCT FROM pay.authorization_id::text THEN RETURN 'the evidence is for another authorization'; END IF;
  IF sealed->>'nexusId' IS DISTINCT FROM pay.terms->>'nexusId' THEN RETURN 'the evidence is for another customer'; END IF;
  IF sealed->>'transactionReference' IS DISTINCT FROM pay.terms->>'transactionReference' THEN RETURN 'the evidence is for another transaction reference'; END IF;
  BEGIN
    signed_bytes := decode(sealed->>'signedPayloadBase64', 'base64');
    signed := convert_from(signed_bytes, 'UTF8')::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RETURN 'the signed bytes are not readable';
  END;
  IF signed_bytes IS NULL OR encode(sha256(signed_bytes), 'hex') IS DISTINCT FROM sealed->>'canonicalPayloadHash' THEN
    RETURN 'the signed bytes do not match canonicalPayloadHash';
  END IF;
  IF signed->>'authorization_id' IS DISTINCT FROM pay.authorization_id::text OR signed->>'nexus_id' IS DISTINCT FROM pay.terms->>'nexusId'
     OR signed->>'credential_id' IS DISTINCT FROM sealed->>'credentialId' OR signed->>'transaction_reference' IS DISTINCT FROM pay.terms->>'transactionReference'
     OR signed->>'amount_minor' IS DISTINCT FROM pay.terms->>'amountMinor' OR signed->>'currency' IS DISTINCT FROM pay.terms->>'currency'
     OR signed->'beneficiary' IS DISTINCT FROM pay.terms->'beneficiary'
     OR (pay.terms ? 'operationType' AND signed->>'operation_type' IS DISTINCT FROM pay.terms->>'operationType') THEN
    RETURN 'the signed terms are not the terms of this payment';
  END IF;
  RETURN NULL;
END $$;

-- The state machine. A transition is accepted only when the function that
-- makes it announced itself (bank.via) and (from, to, function) is listed;
-- the announcement is used up by one row. The log row is written here, with
-- the login role: no role can write, change or remove log rows.
CREATE OR REPLACE FUNCTION bank.executions_lifecycle() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v TEXT := coalesce(current_setting('bank.via', true), '');
  v_from TEXT := CASE WHEN TG_OP = 'INSERT' THEN '' ELSE OLD.state END;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM bank.allowed_transitions a WHERE a.from_state = v_from AND a.to_state = NEW.state AND a.via = v) THEN
    RAISE EXCEPTION 'payment % : % -> % is not a permitted transition (via %)', NEW.payment_id, nullif(v_from, ''), NEW.state, nullif(v, '')
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF (SELECT p.status FROM bank.payments p WHERE p.payment_id = NEW.payment_id) IS DISTINCT FROM 'AWAITING_AUTHORIZATION' THEN
      RAISE EXCEPTION 'payment % has no authorization yet', NEW.payment_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.credential_id IS NOT NULL OR NEW.order_hash IS NOT NULL OR NEW.approval_evidence IS NOT NULL OR NEW.approval_registry_id IS NOT NULL OR NEW.submissions <> 0 THEN
      RAISE EXCEPTION 'payment % : an execution starts without an approval', NEW.payment_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSE
    IF NEW.payment_id IS DISTINCT FROM OLD.payment_id THEN
      RAISE EXCEPTION 'payment id is immutable' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.attempt_id IS DISTINCT FROM OLD.attempt_id AND v <> 'claim' THEN
      RAISE EXCEPTION 'payment % : only a claim starts a new attempt', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.submissions < OLD.submissions OR (NEW.submissions <> OLD.submissions AND v NOT IN ('submit', 'resubmit')) THEN
      RAISE EXCEPTION 'payment % : submissions are counted by the gateway only', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- The approval binds the credential, the order and the evidence; nothing changes them later.
    IF (OLD.state <> 'CHECKING' OR v <> 'approve')
       AND (NEW.order_hash IS DISTINCT FROM OLD.order_hash OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
            OR NEW.approval_evidence IS DISTINCT FROM OLD.approval_evidence OR NEW.approval_registry_id IS DISTINCT FROM OLD.approval_registry_id) THEN
      RAISE EXCEPTION 'payment % : the approved order is immutable', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  PERFORM set_config('bank.via', '', true);
  INSERT INTO bank.execution_transitions (payment_id, from_state, to_state, attempt_id, actor, via)
    VALUES (NEW.payment_id, nullif(v_from, ''), NEW.state, NEW.attempt_id, session_user, v);
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS executions_lifecycle ON bank.executions;
CREATE TRIGGER executions_lifecycle BEFORE INSERT OR UPDATE ON bank.executions FOR EACH ROW EXECUTE FUNCTION bank.executions_lifecycle();

CREATE OR REPLACE FUNCTION bank.payments_lifecycle() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.terms IS DISTINCT FROM OLD.terms OR NEW.bank_transaction_reference IS DISTINCT FROM OLD.bank_transaction_reference OR NEW.payment_id IS DISTINCT FROM OLD.payment_id THEN
    RAISE EXCEPTION 'payment % : terms and reference are immutable', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.authorization_id IS NOT NULL AND NEW.authorization_id IS DISTINCT FROM OLD.authorization_id THEN
    RAISE EXCEPTION 'payment % : the authorization is attached once', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT (OLD.status = NEW.status OR (OLD.status = 'CREATED' AND NEW.status = 'AWAITING_AUTHORIZATION')) THEN
    RAISE EXCEPTION 'payment % : % -> % is not permitted', OLD.payment_id, OLD.status, NEW.status USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS payments_lifecycle ON bank.payments;
CREATE TRIGGER payments_lifecycle BEFORE UPDATE ON bank.payments FOR EACH ROW EXECUTE FUNCTION bank.payments_lifecycle();

CREATE OR REPLACE FUNCTION bank.chain_head_forward_only() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.nexus_id IS DISTINCT FROM OLD.nexus_id OR NEW.chain_sequence < OLD.chain_sequence
     OR (NEW.chain_sequence = OLD.chain_sequence AND NEW.evidence_hash <> OLD.evidence_hash) THEN
    RAISE EXCEPTION 'chain head of % only moves forward (% -> %)', OLD.nexus_id, OLD.chain_sequence, NEW.chain_sequence USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS chain_head_forward_only ON bank.chain_heads;
CREATE TRIGGER chain_head_forward_only BEFORE UPDATE ON bank.chain_heads FOR EACH ROW EXECUTE FUNCTION bank.chain_head_forward_only();

CREATE OR REPLACE FUNCTION bank.credential_trust_lifecycle() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.nexus_id IS DISTINCT FROM OLD.nexus_id OR NEW.credential_id IS DISTINCT FROM OLD.credential_id THEN
    RAISE EXCEPTION 'credential % is bound to one customer', OLD.credential_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.state = 'REVOKED' AND NEW.state <> 'REVOKED' THEN
    RAISE EXCEPTION 'credential % : a revocation is final', OLD.credential_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS credential_trust_lifecycle ON bank.credential_trust;
CREATE TRIGGER credential_trust_lifecycle BEFORE UPDATE ON bank.credential_trust FOR EACH ROW EXECUTE FUNCTION bank.credential_trust_lifecycle();

CREATE OR REPLACE FUNCTION bank.append_only() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'bank.% is append-only', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END $$;
DROP TRIGGER IF EXISTS chain_heads_no_delete ON bank.chain_heads;
CREATE TRIGGER chain_heads_no_delete BEFORE DELETE ON bank.chain_heads FOR EACH ROW EXECUTE FUNCTION bank.append_only();
DROP TRIGGER IF EXISTS credential_trust_no_delete ON bank.credential_trust;
CREATE TRIGGER credential_trust_no_delete BEFORE DELETE ON bank.credential_trust FOR EACH ROW EXECUTE FUNCTION bank.append_only();
DROP TRIGGER IF EXISTS trust_statements_append_only ON bank.trust_statements;
CREATE TRIGGER trust_statements_append_only BEFORE UPDATE OR DELETE ON bank.trust_statements FOR EACH ROW EXECUTE FUNCTION bank.append_only();
DROP TRIGGER IF EXISTS execution_transitions_append_only ON bank.execution_transitions;
CREATE TRIGGER execution_transitions_append_only BEFORE UPDATE OR DELETE ON bank.execution_transitions FOR EACH ROW EXECUTE FUNCTION bank.append_only();
DROP TRIGGER IF EXISTS reconciliation_findings_append_only ON bank.reconciliation_findings;
CREATE TRIGGER reconciliation_findings_append_only BEFORE UPDATE OR DELETE ON bank.reconciliation_findings FOR EACH ROW EXECUTE FUNCTION bank.append_only();
DROP TRIGGER IF EXISTS payments_no_delete ON bank.payments;
CREATE TRIGGER payments_no_delete BEFORE DELETE ON bank.payments FOR EACH ROW EXECUTE FUNCTION bank.append_only();
DROP TRIGGER IF EXISTS executions_no_delete ON bank.executions;
CREATE TRIGGER executions_no_delete BEFORE DELETE ON bank.executions FOR EACH ROW EXECUTE FUNCTION bank.append_only();
${['payments', 'executions', 'execution_transitions', 'trust_statements', 'credential_trust', 'chain_heads', 'reconciliation_findings'].map((t) => `DROP TRIGGER IF EXISTS ${t}_no_truncate ON bank.${t};
CREATE TRIGGER ${t}_no_truncate BEFORE TRUNCATE ON bank.${t} FOR EACH STATEMENT EXECUTE FUNCTION bank.append_only();`).join('\n')}

-- Kept chain heads: forward only (internal; reached through keep_head and approve_credential).
CREATE OR REPLACE FUNCTION bank.advance_head(p_nexus VARCHAR, p_sequence INTEGER, p_hash TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE n INTEGER;
BEGIN
  IF p_sequence IS NULL THEN RETURN false; END IF;
  IF p_nexus !~ '^[0-9]{9}$' OR p_sequence < 1 OR coalesce(p_hash, '') !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'not a chain head' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  INSERT INTO bank.chain_heads AS h (nexus_id, chain_sequence, evidence_hash) VALUES (p_nexus, p_sequence, p_hash)
    ON CONFLICT (nexus_id) DO UPDATE SET chain_sequence = EXCLUDED.chain_sequence, evidence_hash = EXCLUDED.evidence_hash, updated_at = now()
    WHERE h.chain_sequence < EXCLUDED.chain_sequence;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n = 1;
END $$;

-- ===== boundary =====

CREATE OR REPLACE FUNCTION bank.create_payment(p_payment UUID, p_reference TEXT, p_terms JSONB, p_authorization UUID DEFAULT NULL) RETURNS VOID
LANGUAGE plpgsql ${DEFINER} AS $$
BEGIN
  IF p_payment IS NULL OR coalesce(p_reference, '') = '' OR jsonb_typeof(p_terms) IS DISTINCT FROM 'object'
     OR coalesce(p_terms->>'nexusId', '') !~ '^[0-9]{9}$' OR coalesce(p_terms->>'amountMinor', '') !~ '^[0-9]{1,18}$'
     OR coalesce(p_terms->>'currency', '') !~ '^[A-Z]{3}$' OR coalesce(p_terms->>'transactionReference', '') = ''
     OR jsonb_typeof(p_terms->'beneficiary') IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'not a payment: identifier, reference and terms (nexusId, transactionReference, amountMinor, currency, beneficiary) are required'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  INSERT INTO bank.payments (payment_id, status, authorization_id, bank_transaction_reference, terms)
    VALUES (p_payment, CASE WHEN p_authorization IS NULL THEN 'CREATED' ELSE 'AWAITING_AUTHORIZATION' END, p_authorization, p_reference, p_terms);
END $$;

CREATE OR REPLACE FUNCTION bank.attach_authorization(p_payment UUID, p_authorization UUID) RETURNS BOOLEAN
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE n INTEGER;
BEGIN
  UPDATE bank.payments p SET status = 'AWAITING_AUTHORIZATION', authorization_id = p_authorization
   WHERE p.payment_id = p_payment AND p.status = 'CREATED' AND p_authorization IS NOT NULL;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n = 1;
END $$;

-- Takes the payment for one attempt (see trustStore.claim for the outcomes).
CREATE OR REPLACE FUNCTION bank.claim(p_payment UUID, p_lease_ms INTEGER) RETURNS TABLE (outcome TEXT, attempt UUID)
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE
  pay bank.payments%ROWTYPE; ex bank.executions%ROWTYPE; fresh UUID := gen_random_uuid(); live BOOLEAN;
BEGIN
  ${LEASE}
  SELECT * INTO pay FROM bank.payments p WHERE p.payment_id = p_payment FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'no payment % in the bank''s records', p_payment USING ERRCODE = 'no_data_found'; END IF;
  IF pay.status <> 'AWAITING_AUTHORIZATION' THEN RETURN QUERY SELECT 'NOT_AUTHORIZED'::text, NULL::uuid; RETURN; END IF;
  SELECT * INTO ex FROM bank.executions e WHERE e.payment_id = p_payment FOR UPDATE;
  IF NOT FOUND THEN
    PERFORM bank.via('claim');
    INSERT INTO bank.executions (payment_id, state, attempt_id, lease_until) VALUES (p_payment, 'CHECKING', fresh, now() + p_lease_ms * interval '1 millisecond');
    RETURN QUERY SELECT 'CHECKING'::text, fresh; RETURN;
  END IF;
  live := ex.lease_until IS NOT NULL AND ex.lease_until >= now();
  IF ex.state IN ('EXECUTED', 'PROVIDER_FAILED', 'REFUSED') THEN RETURN QUERY SELECT 'FINAL'::text, NULL::uuid; RETURN; END IF;
  IF ex.state = 'REVIEW' THEN RETURN QUERY SELECT 'REVIEW'::text, NULL::uuid; RETURN; END IF;
  IF live AND ex.state IN ('CHECKING', 'APPROVED', 'SUBMITTED', 'RECONCILING') THEN RETURN QUERY SELECT 'IN_PROGRESS'::text, NULL::uuid; RETURN; END IF;
  IF ex.state = 'APPROVED' THEN
    -- The approving attempt is gone before the gateway took the approval: withdraw it.
    PERFORM bank.via('claim');
    UPDATE bank.executions e SET state = 'HELD', lease_until = NULL, problems = '["the approving attempt stopped before submission"]'::jsonb, updated_at = now()
     WHERE e.payment_id = p_payment;
    ex.state := 'HELD';
  END IF;
  PERFORM bank.via('claim');
  UPDATE bank.executions e SET state = CASE WHEN ex.state IN ('HELD', 'CHECKING') THEN 'CHECKING' ELSE 'RECONCILING' END,
         attempt_id = fresh, lease_until = now() + p_lease_ms * interval '1 millisecond', attempts = e.attempts + 1, updated_at = now()
   WHERE e.payment_id = p_payment;
  RETURN QUERY SELECT CASE WHEN ex.state IN ('HELD', 'CHECKING') THEN 'CHECKING' ELSE 'RECONCILE' END, fresh;
END $$;

-- CHECKING -> APPROVED: the revocation cut-off. The caller gives the attempt
-- and the confirmation evidence it verified; everything else comes from the
-- database: the customer and terms from the payment, the credential from the
-- evidence (checked against the payment), its standing from the registry row
-- (read FOR SHARE: a revocation waits for this, or came first), the order and
-- its hash from the payment. Used once per attempt.
CREATE OR REPLACE FUNCTION bank.approve(p_payment UUID, p_attempt UUID, p_evidence JSONB, p_lease_ms INTEGER)
RETURNS TABLE (ok BOOLEAN, lost BOOLEAN, reason TEXT)
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE
  ex bank.executions%ROWTYPE; pay bank.payments%ROWTYPE; tr bank.credential_trust%ROWTYPE; problem TEXT; cred UUID;
BEGIN
  ${LEASE}
  SELECT * INTO ex FROM bank.executions e WHERE e.payment_id = p_payment FOR UPDATE;
  IF NOT FOUND OR ex.state <> 'CHECKING' OR ex.attempt_id IS DISTINCT FROM p_attempt OR ex.lease_until IS NULL OR ex.lease_until < now() THEN
    RETURN QUERY SELECT false, true, 'the claim was lost (lease expired or taken over)'::text; RETURN;
  END IF;
  SELECT * INTO pay FROM bank.payments p WHERE p.payment_id = p_payment;
  problem := bank.evidence_problem(p_payment, p_evidence);
  IF problem IS NOT NULL THEN RETURN QUERY SELECT false, false, problem; RETURN; END IF;
  cred := (p_evidence->'sealedPayload'->>'credentialId')::uuid;
  SELECT * INTO tr FROM bank.credential_trust t WHERE t.credential_id = cred FOR SHARE;
  IF NOT FOUND THEN RETURN QUERY SELECT false, false, format('credential %s is not in the bank''s registry', cred); RETURN; END IF;
  IF tr.nexus_id IS DISTINCT FROM pay.terms->>'nexusId' THEN RETURN QUERY SELECT false, false, format('credential %s is approved for another customer', cred); RETURN; END IF;
  IF tr.state <> 'APPROVED' THEN RETURN QUERY SELECT false, false, format('credential %s was revoked by the bank', cred); RETURN; END IF;
  IF NOT EXISTS (SELECT 1 FROM bank.trust_statements s WHERE s.credential_id = cred AND s.nexus_id = tr.nexus_id AND s.type = '${APPROVAL}') THEN
    RETURN QUERY SELECT false, false, format('credential %s has no stored approval statement', cred); RETURN;
  END IF;
  PERFORM bank.via('approve');
  UPDATE bank.executions e SET state = 'APPROVED', credential_id = cred, approval_evidence = p_evidence,
         approval_registry_id = (SELECT max(s.id) FROM bank.trust_statements s WHERE s.nexus_id = tr.nexus_id),
         order_hash = bank.order_hash(bank.order_document(p_payment)), lease_until = now() + p_lease_ms * interval '1 millisecond', updated_at = now()
   WHERE e.payment_id = p_payment;
  RETURN QUERY SELECT true, false, NULL::text;
END $$;

CREATE OR REPLACE FUNCTION bank.refuse(p_payment UUID, p_attempt UUID, p_problems JSONB) RETURNS BOOLEAN
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE n INTEGER;
BEGIN
  PERFORM bank.via('refuse');
  UPDATE bank.executions e SET state = 'REFUSED', lease_until = NULL, problems = coalesce(p_problems, '[]'::jsonb), updated_at = now()
   WHERE e.payment_id = p_payment AND e.attempt_id = p_attempt AND e.state = 'CHECKING';
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM bank.via('');
  RETURN n = 1;
END $$;

CREATE OR REPLACE FUNCTION bank.hold(p_payment UUID, p_attempt UUID, p_reason TEXT, p_from TEXT[] DEFAULT ARRAY['CHECKING', 'APPROVED']) RETURNS BOOLEAN
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE n INTEGER;
BEGIN
  PERFORM bank.via('hold');
  UPDATE bank.executions e SET state = 'HELD', lease_until = NULL, problems = jsonb_build_array(p_reason), updated_at = now()
   WHERE e.payment_id = p_payment AND e.attempt_id = p_attempt AND e.state = ANY (p_from) AND e.state IN ('CHECKING', 'APPROVED');
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM bank.via('');
  RETURN n = 1;
END $$;

CREATE OR REPLACE FUNCTION bank.mark_unknown(p_payment UUID, p_attempt UUID, p_reason TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE n INTEGER;
BEGIN
  PERFORM bank.via('mark_unknown');
  UPDATE bank.executions e SET state = 'OUTCOME_UNKNOWN', lease_until = NULL, problems = coalesce(e.problems, '[]'::jsonb) || jsonb_build_array(p_reason), updated_at = now()
   WHERE e.payment_id = p_payment AND e.attempt_id = p_attempt AND e.state IN ('SUBMITTED', 'RECONCILING');
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM bank.via('');
  RETURN n = 1;
END $$;

CREATE OR REPLACE FUNCTION bank.mark_review(p_payment UUID, p_attempt UUID, p_reason TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE n INTEGER;
BEGIN
  PERFORM bank.via('mark_review');
  UPDATE bank.executions e SET state = 'REVIEW', lease_until = NULL, problems = coalesce(e.problems, '[]'::jsonb) || jsonb_build_array(p_reason), updated_at = now()
   WHERE e.payment_id = p_payment AND e.attempt_id = p_attempt AND e.state = 'RECONCILING';
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM bank.via('');
  RETURN n = 1;
END $$;

CREATE OR REPLACE FUNCTION bank.keep_head(p_nexus VARCHAR, p_sequence INTEGER, p_hash TEXT) RETURNS BOOLEAN
LANGUAGE sql ${DEFINER} AS $$ SELECT bank.advance_head(p_nexus, p_sequence, p_hash) $$;

CREATE OR REPLACE FUNCTION bank.add_finding(p_payment UUID, p_local_state TEXT, p_provider_status TEXT, p_detail JSONB) RETURNS VOID
LANGUAGE plpgsql ${DEFINER} AS $$
BEGIN
  INSERT INTO bank.reconciliation_findings (payment_id, local_state, provider_status, detail, recorded_by)
    VALUES (p_payment, p_local_state, p_provider_status, p_detail, session_user);
END $$;

-- ===== gateway =====

-- What the gateway needs to check an approval before it submits: the order
-- (from the payment), whether it still has the hash bound at approval, the
-- evidence stored with the approval, the customer's statements as they stood
-- at the approval (the revocation cut-off stays at APPROVED; statements are
-- append-only) and the expected terms. Locks the execution row for the
-- gateway's transaction.
CREATE OR REPLACE FUNCTION bank.submit_basis(p_payment UUID, p_attempt UUID)
RETURNS TABLE (state TEXT, operation_id TEXT, payment_order JSONB, order_matches BOOLEAN, evidence JSONB, registry JSONB, expected JSONB)
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE ex bank.executions%ROWTYPE; pay bank.payments%ROWTYPE; doc JSONB;
BEGIN
  SELECT * INTO ex FROM bank.executions e WHERE e.payment_id = p_payment FOR UPDATE;
  IF NOT FOUND OR ex.state NOT IN ('APPROVED', 'RECONCILING') OR ex.attempt_id IS DISTINCT FROM p_attempt OR ex.lease_until IS NULL OR ex.lease_until < now()
     OR ex.order_hash IS NULL OR ex.approval_registry_id IS NULL THEN
    RAISE EXCEPTION 'payment % : nothing is approved for this attempt', p_payment USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT * INTO pay FROM bank.payments p WHERE p.payment_id = p_payment;
  doc := bank.order_document(p_payment);
  RETURN QUERY SELECT ex.state, pay.bank_transaction_reference, doc, bank.order_hash(doc) = ex.order_hash, ex.approval_evidence,
    coalesce((SELECT jsonb_agg(s.entry ORDER BY s.id) FROM bank.trust_statements s WHERE s.nexus_id = pay.terms->>'nexusId' AND s.id <= ex.approval_registry_id), '[]'::jsonb),
    pay.terms || jsonb_build_object('authorizationId', pay.authorization_id::text);
END $$;

-- APPROVED -> SUBMITTED, before the provider is called; only for the attempt
-- that holds the approval, with a live lease, once, and only if the order
-- still hashes to the approved hash. Returns the order to send.
CREATE OR REPLACE FUNCTION bank.submit(p_payment UUID, p_attempt UUID) RETURNS TABLE (operation_id TEXT, payment_order JSONB)
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE ex bank.executions%ROWTYPE; doc JSONB;
BEGIN
  SELECT * INTO ex FROM bank.executions e WHERE e.payment_id = p_payment FOR UPDATE;
  IF NOT FOUND OR ex.state <> 'APPROVED' OR ex.attempt_id IS DISTINCT FROM p_attempt OR ex.lease_until IS NULL OR ex.lease_until < now() THEN
    RAISE EXCEPTION 'payment % : nothing is approved for this attempt', p_payment USING ERRCODE = 'insufficient_privilege';
  END IF;
  doc := bank.order_document(p_payment);
  IF bank.order_hash(doc) IS DISTINCT FROM ex.order_hash THEN
    RAISE EXCEPTION 'payment % : the order is not the approved order', p_payment USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM bank.via('submit');
  UPDATE bank.executions e SET state = 'SUBMITTED', submissions = e.submissions + 1, updated_at = now() WHERE e.payment_id = p_payment;
  RETURN QUERY SELECT doc->>'operationId', doc;
END $$;

-- RECONCILING -> SUBMITTED: the same operation id again (the boundary asks
-- only with a provider that declares idempotent submission).
CREATE OR REPLACE FUNCTION bank.resubmit(p_payment UUID, p_attempt UUID) RETURNS TABLE (operation_id TEXT, payment_order JSONB)
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE ex bank.executions%ROWTYPE; doc JSONB;
BEGIN
  SELECT * INTO ex FROM bank.executions e WHERE e.payment_id = p_payment FOR UPDATE;
  IF NOT FOUND OR ex.state <> 'RECONCILING' OR ex.attempt_id IS DISTINCT FROM p_attempt OR ex.lease_until IS NULL OR ex.lease_until < now()
     OR ex.submissions < 1 THEN
    RAISE EXCEPTION 'payment % : no reconciliation by this attempt', p_payment USING ERRCODE = 'insufficient_privilege';
  END IF;
  doc := bank.order_document(p_payment);
  IF bank.order_hash(doc) IS DISTINCT FROM ex.order_hash THEN
    RAISE EXCEPTION 'payment % : the order is not the approved order', p_payment USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM bank.via('resubmit');
  UPDATE bank.executions e SET state = 'SUBMITTED', submissions = e.submissions + 1, updated_at = now() WHERE e.payment_id = p_payment;
  RETURN QUERY SELECT doc->>'operationId', doc;
END $$;

-- The gateway does not send: the approval's basis did not hold up. REVIEW.
CREATE OR REPLACE FUNCTION bank.gateway_refuse(p_payment UUID, p_attempt UUID, p_reason TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE n INTEGER;
BEGIN
  PERFORM bank.via('gateway_refuse');
  UPDATE bank.executions e SET state = 'REVIEW', lease_until = NULL, problems = coalesce(e.problems, '[]'::jsonb) || jsonb_build_array(p_reason), updated_at = now()
   WHERE e.payment_id = p_payment AND e.attempt_id = p_attempt AND e.state IN ('APPROVED', 'RECONCILING');
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM bank.via('');
  RETURN n = 1;
END $$;

-- The provider's answer to a submission or a lookup, for this attempt.
CREATE OR REPLACE FUNCTION bank.report(p_payment UUID, p_attempt UUID, p_outcome TEXT, p_provider_reference TEXT, p_reason TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE target TEXT; n INTEGER;
BEGIN
  target := CASE p_outcome WHEN 'succeeded' THEN 'EXECUTED' WHEN 'failed' THEN 'PROVIDER_FAILED' WHEN 'pending' THEN 'PENDING_PROVIDER' WHEN 'unknown' THEN 'OUTCOME_UNKNOWN' END;
  IF target IS NULL THEN RAISE EXCEPTION 'unknown provider outcome %', p_outcome USING ERRCODE = 'invalid_parameter_value'; END IF;
  PERFORM bank.via('report');
  UPDATE bank.executions e SET state = target, lease_until = NULL, provider_reference = coalesce(p_provider_reference, e.provider_reference),
         problems = CASE WHEN p_reason IS NULL THEN e.problems ELSE coalesce(e.problems, '[]'::jsonb) || jsonb_build_array(p_reason) END, updated_at = now()
   WHERE e.payment_id = p_payment AND e.attempt_id = p_attempt AND e.state IN ('SUBMITTED', 'RECONCILING');
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM bank.via('');
  RETURN n = 1;
END $$;

-- The operation id of a payment submitted at least once, for lookups.
CREATE OR REPLACE FUNCTION bank.operation_for_lookup(p_payment UUID) RETURNS TEXT
LANGUAGE sql STABLE ${DEFINER} AS $$
  SELECT p.bank_transaction_reference FROM bank.payments p JOIN bank.executions e ON e.payment_id = p.payment_id
   WHERE p.payment_id = p_payment AND e.submissions > 0
$$;

-- ===== registry =====

-- Stores a bank-signed approval (the registry service verified the signature).
-- A credential is approved for one customer, and never again after a revocation.
CREATE OR REPLACE FUNCTION bank.approve_credential(p_entry JSONB, p_head_sequence INTEGER DEFAULT NULL, p_head_hash TEXT DEFAULT NULL) RETURNS VOID
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE s JSONB := p_entry->'statement'; cred UUID; tr bank.credential_trust%ROWTYPE;
BEGIN
  IF s->>'type' IS DISTINCT FROM '${APPROVAL}' OR coalesce(s->>'credentialId', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR coalesce(s->>'nexusId', '') !~ '^[0-9]{9}$' OR coalesce(s->>'signingKeySha256', '') !~ '^[0-9a-f]{64}$' OR jsonb_typeof(p_entry->'signature') IS DISTINCT FROM 'string' THEN
    RAISE EXCEPTION 'not a ${APPROVAL} statement' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  cred := (s->>'credentialId')::uuid;
  SELECT * INTO tr FROM bank.credential_trust t WHERE t.credential_id = cred FOR UPDATE;
  IF FOUND AND tr.nexus_id <> s->>'nexusId' THEN RAISE EXCEPTION 'credential % is approved for another customer', cred USING ERRCODE = 'integrity_constraint_violation'; END IF;
  IF FOUND AND tr.state = 'REVOKED' THEN RAISE EXCEPTION 'credential % was revoked; a new device gets a new credential', cred USING ERRCODE = 'integrity_constraint_violation'; END IF;
  IF NOT FOUND THEN INSERT INTO bank.credential_trust (credential_id, nexus_id, state) VALUES (cred, s->>'nexusId', 'APPROVED'); END IF;
  INSERT INTO bank.trust_statements (credential_id, nexus_id, type, entry, recorded_by) VALUES (cred, s->>'nexusId', '${APPROVAL}', p_entry, session_user);
  PERFORM bank.advance_head(s->>'nexusId', p_head_sequence, p_head_hash);
END $$;

-- Stores a bank-signed revocation (final). Serialized with bank.approve on the
-- credential's row; returns the payments already past the cut-off (in flight).
CREATE OR REPLACE FUNCTION bank.revoke_credential(p_entry JSONB) RETURNS TABLE (payment_id UUID, state TEXT)
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE s JSONB := p_entry->'statement'; cred UUID; tr bank.credential_trust%ROWTYPE;
BEGIN
  IF s->>'type' IS DISTINCT FROM '${REVOCATION}' OR coalesce(s->>'credentialId', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR coalesce(s->>'nexusId', '') !~ '^[0-9]{9}$' OR jsonb_typeof(p_entry->'signature') IS DISTINCT FROM 'string' THEN
    RAISE EXCEPTION 'not a ${REVOCATION} statement' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  cred := (s->>'credentialId')::uuid;
  SELECT * INTO tr FROM bank.credential_trust t WHERE t.credential_id = cred FOR UPDATE;
  IF FOUND AND tr.nexus_id <> s->>'nexusId' THEN RAISE EXCEPTION 'credential % belongs to another customer', cred USING ERRCODE = 'integrity_constraint_violation'; END IF;
  IF FOUND THEN UPDATE bank.credential_trust t SET state = 'REVOKED', updated_at = now() WHERE t.credential_id = cred;
  ELSE INSERT INTO bank.credential_trust (credential_id, nexus_id, state) VALUES (cred, s->>'nexusId', 'REVOKED'); END IF;
  INSERT INTO bank.trust_statements (credential_id, nexus_id, type, entry, recorded_by) VALUES (cred, s->>'nexusId', '${REVOCATION}', p_entry, session_user);
  RETURN QUERY SELECT e.payment_id, e.state FROM bank.executions e
    WHERE e.credential_id = cred AND e.state IN ('APPROVED', 'SUBMITTED', 'PENDING_PROVIDER', 'OUTCOME_UNKNOWN', 'RECONCILING', 'REVIEW') ORDER BY e.payment_id;
END $$;

-- ===== operator =====

-- A person settled a REVIEW with the provider. Who: the database login, not an argument.
CREATE OR REPLACE FUNCTION bank.resolve_review(p_payment UUID, p_outcome TEXT, p_note TEXT, p_provider_reference TEXT DEFAULT NULL) RETURNS BOOLEAN
LANGUAGE plpgsql ${DEFINER} AS $$
DECLARE target TEXT; n INTEGER;
BEGIN
  IF coalesce(btrim(p_note), '') = '' THEN RAISE EXCEPTION 'a resolution needs a note' USING ERRCODE = 'invalid_parameter_value'; END IF;
  target := CASE p_outcome WHEN 'succeeded' THEN 'EXECUTED' WHEN 'failed' THEN 'PROVIDER_FAILED' END;
  IF target IS NULL THEN RAISE EXCEPTION 'a review is resolved as succeeded or failed' USING ERRCODE = 'invalid_parameter_value'; END IF;
  PERFORM bank.via('resolve_review');
  UPDATE bank.executions e SET state = target, resolved_by = session_user, provider_reference = coalesce(p_provider_reference, e.provider_reference),
         problems = coalesce(e.problems, '[]'::jsonb) || jsonb_build_array(p_note), updated_at = now()
   WHERE e.payment_id = p_payment AND e.state = 'REVIEW';
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM bank.via('');
  RETURN n = 1;
END $$;
`;

/**
 * Run once by the database administrator (not by the schema owner): no
 * temporary objects and no objects in `public` for anyone by default.
 */
export const DATABASE_HARDENING = (database) => `
REVOKE TEMPORARY ON DATABASE ${ident(database)} FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
`;

const LEGACY_FUNCTIONS = ['bank_submit(uuid,uuid)', 'bank_resubmit(uuid,uuid)', 'bank_operation_for_lookup(uuid)'];

/**
 * Installs or reinstalls the schema as its owner, then gives each role
 * exactly its part (FUNCTIONS, READS) after removing whatever it had before,
 * including the grants of the phase 14 tables in `public` if they still exist.
 * Refuses roles that are superusers, bypass row security, or are members of the owner.
 *
 * @param roles { boundary, gateway, registry, operator } role names (any may be absent)
 */
export async function installSchema(ownerPool, roles = {}) {
  const given = Object.fromEntries(ROLE_KINDS.filter((k) => roles[k]).map((k) => [k, ident(roles[k])]));
  const client = await ownerPool.connect();
  try {
    for (const role of Object.values(given)) {
      const r = (await client.query(`SELECT r.rolsuper, r.rolbypassrls, pg_has_role($1, current_user, 'MEMBER') AS owner_member
        FROM pg_catalog.pg_roles r WHERE r.rolname = $1`, [role])).rows[0];
      if (!r) throw new Error(`role ${role} does not exist`);
      if (r.rolsuper || r.rolbypassrls) throw new Error(`role ${role} is a superuser or bypasses row security`);
      if (r.owner_member) throw new Error(`role ${role} is a member of the schema owner`);
    }
    await client.query('BEGIN');
    await client.query(`CREATE SCHEMA IF NOT EXISTS bank`);
    await client.query(`REVOKE ALL ON SCHEMA bank FROM PUBLIC`);
    // Objects the owner creates later are granted to nobody (functions are executable by PUBLIC by default).
    await client.query(`ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA bank REVOKE ALL ON TABLES FROM PUBLIC`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA bank REVOKE ALL ON SEQUENCES FROM PUBLIC`);
    await client.query(SCHEMA);
    await client.query(`REVOKE ALL ON ALL TABLES IN SCHEMA bank FROM PUBLIC`);
    await client.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA bank FROM PUBLIC`);
    await client.query(`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bank FROM PUBLIC`);
    const legacyTables = (await client.query(`SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname LIKE 'bank\\_%' AND c.relkind IN ('r', 'S', 'v', 'p') AND pg_has_role(c.relowner, 'USAGE')`)).rows.map((r) => `public.${ident(r.relname)}`);
    const legacyFunctions = (await client.query(`SELECT p.oid::regprocedure::text AS sig FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.oid::regprocedure::text = ANY ($1) AND pg_has_role(p.proowner, 'USAGE')`, [LEGACY_FUNCTIONS])).rows.map((r) => `public.${r.sig}`);
    for (const f of legacyFunctions) await client.query(`REVOKE ALL ON FUNCTION ${f} FROM PUBLIC`);
    for (const [kind, role] of Object.entries(given)) {
      await client.query(`REVOKE ALL ON ALL TABLES IN SCHEMA bank FROM ${role}`);
      await client.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA bank FROM ${role}`);
      await client.query(`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bank FROM ${role}`);
      await client.query(`REVOKE ALL ON SCHEMA bank FROM ${role}`);
      for (const t of legacyTables) await client.query(`REVOKE ALL ON ${t} FROM ${role}`);
      for (const f of legacyFunctions) await client.query(`REVOKE ALL ON FUNCTION ${f} FROM ${role}`);
      await client.query(`GRANT USAGE ON SCHEMA bank TO ${role}`);
      if (READS[kind].length) await client.query(`GRANT SELECT ON ${READS[kind].map((t) => `bank.${t}`).join(', ')} TO ${role}`);
      for (const f of FUNCTIONS[kind]) await client.query(`GRANT EXECUTE ON FUNCTION ${f} TO ${role}`);
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

const TABLE_PRIVILEGES = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'];

/**
 * What each role can actually do, direct and inherited, read from the
 * catalog: tables, sequences and functions of `bank`, the schemas, the
 * database, role memberships and attributes. Compare with intendedPrivileges.
 */
export async function privilegeMatrix(pool, roles) {
  const out = {};
  for (const kind of ROLE_KINDS.filter((k) => roles[k])) {
    const role = roles[kind];
    const tables = (await pool.query(`SELECT c.relname, array_remove(ARRAY[${TABLE_PRIVILEGES.map((p) => `CASE WHEN has_table_privilege($1, c.oid, '${p}') THEN '${p}' END`).join(', ')}], NULL) AS privs
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'bank' AND c.relkind IN ('r', 'p', 'v') ORDER BY c.relname`, [role])).rows;
    const sequences = (await pool.query(`SELECT c.relname, array_remove(ARRAY[${['USAGE', 'SELECT', 'UPDATE'].map((p) => `CASE WHEN has_sequence_privilege($1, c.oid, '${p}') THEN '${p}' END`).join(', ')}], NULL) AS privs
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'bank' AND c.relkind = 'S' ORDER BY c.relname`, [role])).rows;
    const functions = (await pool.query(`SELECT p.oid::regprocedure::text AS sig FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'bank' AND has_function_privilege($1, p.oid, 'EXECUTE')`, [role])).rows.map((r) => r.sig).sort();
    const schema = async (name) => (await pool.query(`SELECT array_remove(ARRAY[CASE WHEN has_schema_privilege($1, $2, 'USAGE') THEN 'USAGE' END,
      CASE WHEN has_schema_privilege($1, $2, 'CREATE') THEN 'CREATE' END], NULL) AS privs`, [role, name])).rows[0].privs;
    const database = (await pool.query(`SELECT array_remove(ARRAY[${['CONNECT', 'CREATE', 'TEMPORARY'].map((p) => `CASE WHEN has_database_privilege($1, current_database(), '${p}') THEN '${p}' END`).join(', ')}], NULL) AS privs`, [role])).rows[0].privs;
    const memberOf = (await pool.query(`SELECT g.rolname FROM pg_catalog.pg_roles g WHERE g.rolname <> $1 AND pg_has_role($1, g.oid, 'MEMBER') ORDER BY 1`, [role])).rows.map((r) => r.rolname);
    const attrs = (await pool.query(`SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = $1`, [role])).rows[0];
    out[kind] = {
      tables: Object.fromEntries(tables.filter((t) => t.privs.length).map((t) => [t.relname, t.privs])),
      sequences: Object.fromEntries(sequences.filter((s) => s.privs.length).map((s) => [s.relname, s.privs])),
      functions,
      schemas: { bank: await schema('bank'), public: await schema('public') },
      database,
      memberOf: memberOf.filter((m) => !m.startsWith('pg_')),
      attributes: Object.entries(attrs).filter(([, v]) => v).map(([k]) => k),
    };
  }
  return out;
}

/** The intended matrix (installSchema plus the deployment in DATABASE_HARDENING and CONNECT). */
export function intendedPrivileges(roles) {
  return Object.fromEntries(ROLE_KINDS.filter((k) => roles[k]).map((kind) => [kind, {
    tables: Object.fromEntries(READS[kind].map((t) => [t, ['SELECT']]).sort(([a], [b]) => (a < b ? -1 : 1))),
    sequences: {},
    functions: [...FUNCTIONS[kind]].sort(),
    schemas: { bank: ['USAGE'], public: ['USAGE'] },
    database: ['CONNECT'],
    memberOf: [],
    attributes: [],
  }]));
}
export { TABLES };
