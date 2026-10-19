// The bank's trust registry and execution journal (PostgreSQL), with the
// payment state machine enforced in the database. Installed by the owner of
// the bank's schema; the execution boundary and the payment gateway connect
// with their own roles (installSchema grants them only what they need).
//
// Execution states (bank_executions.state), see docs/architecture/payment-state-machine.md:
//   CHECKING          an attempt holds the payment and runs the checks
//   HELD              stopped before approval (error, unavailable service); retried
//   APPROVED          the bank's decision and final check passed: the revocation
//                     cut-off; only the payment gateway may move on from here
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

/** Allowed transitions; anything else is refused by the database. */
export const TRANSITIONS = {
  CHECKING: ['CHECKING', 'APPROVED', 'REFUSED', 'HELD'],
  HELD: ['CHECKING'],
  APPROVED: ['SUBMITTED', 'HELD'],
  SUBMITTED: ['EXECUTED', 'PROVIDER_FAILED', 'PENDING_PROVIDER', 'OUTCOME_UNKNOWN', 'RECONCILING', 'REVIEW'],
  PENDING_PROVIDER: ['RECONCILING'],
  OUTCOME_UNKNOWN: ['RECONCILING'],
  RECONCILING: ['RECONCILING', 'SUBMITTED', 'EXECUTED', 'PROVIDER_FAILED', 'PENDING_PROVIDER', 'OUTCOME_UNKNOWN', 'REVIEW'],
  REVIEW: ['EXECUTED', 'PROVIDER_FAILED'],
  EXECUTED: [],
  PROVIDER_FAILED: [],
  REFUSED: [],
};

const pairs = Object.entries(TRANSITIONS).flatMap(([from, tos]) => tos.map((to) => `('${from}','${to}')`)).join(', ');
const ident = (name) => {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(name)) throw new Error(`not a plain role name: ${name}`);
  return name;
};

export const SCHEMA = `
CREATE TABLE IF NOT EXISTS bank_trust_statements (
  id BIGSERIAL PRIMARY KEY,
  credential_id UUID NOT NULL,
  nexus_id VARCHAR(9) NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('${APPROVAL}', '${REVOCATION}')),
  entry JSONB NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bank_trust_statements_nexus ON bank_trust_statements (nexus_id);
CREATE TABLE IF NOT EXISTS bank_credential_trust (
  credential_id UUID PRIMARY KEY,
  nexus_id VARCHAR(9) NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('APPROVED', 'REVOKED')),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank_chain_heads (
  nexus_id VARCHAR(9) PRIMARY KEY,
  chain_sequence INTEGER NOT NULL CHECK (chain_sequence > 0),
  evidence_hash CHAR(64) NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank_payments (
  payment_id UUID PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('CREATED', 'AWAITING_AUTHORIZATION')),
  authorization_id UUID UNIQUE,
  bank_transaction_reference TEXT NOT NULL UNIQUE,
  terms JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((status = 'CREATED') = (authorization_id IS NULL))
);
CREATE TABLE IF NOT EXISTS bank_executions (
  payment_id UUID PRIMARY KEY REFERENCES bank_payments (payment_id),
  state TEXT NOT NULL CHECK (state IN (${EXECUTION_STATES.map((s) => `'${s}'`).join(', ')})),
  attempt_id UUID NOT NULL,
  lease_until TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 1,
  credential_id UUID,
  order_hash CHAR(64),
  submissions INTEGER NOT NULL DEFAULT 0,
  provider_reference TEXT,
  problems JSONB,
  resolved_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank_execution_transitions (
  id BIGSERIAL PRIMARY KEY,
  payment_id UUID NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  attempt_id UUID NOT NULL,
  actor TEXT NOT NULL,
  at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS bank_reconciliation_findings (
  id BIGSERIAL PRIMARY KEY,
  payment_id UUID NOT NULL REFERENCES bank_payments (payment_id),
  local_state TEXT NOT NULL,
  provider_status TEXT NOT NULL,
  detail JSONB,
  found_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank_allowed_transitions (from_state TEXT NOT NULL, to_state TEXT NOT NULL, PRIMARY KEY (from_state, to_state));
INSERT INTO bank_allowed_transitions VALUES ${pairs} ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION bank_execution_lifecycle() RETURNS trigger AS $$
DECLARE
  owner_name TEXT;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'CHECKING' THEN
      RAISE EXCEPTION 'payment % : an execution starts in CHECKING', NEW.payment_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (SELECT status FROM bank_payments WHERE payment_id = NEW.payment_id) <> 'AWAITING_AUTHORIZATION' THEN
      RAISE EXCEPTION 'payment % has no authorization yet', NEW.payment_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSE
    IF NOT EXISTS (SELECT 1 FROM bank_allowed_transitions WHERE from_state = OLD.state AND to_state = NEW.state) THEN
      RAISE EXCEPTION 'payment % : % -> % is not a permitted transition', OLD.payment_id, OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.payment_id IS DISTINCT FROM OLD.payment_id THEN
      RAISE EXCEPTION 'payment id is immutable' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- Only the payment gateway's functions (running as the schema owner) submit.
    IF NEW.state = 'SUBMITTED' AND OLD.state <> 'SUBMITTED' THEN
      SELECT tableowner INTO owner_name FROM pg_tables WHERE schemaname = current_schema() AND tablename = 'bank_executions';
      IF current_user <> owner_name THEN
        RAISE EXCEPTION 'payment % : only the payment gateway submits', OLD.payment_id USING ERRCODE = 'insufficient_privilege';
      END IF;
    END IF;
    -- The approval binds the attempt and the order; nothing changes them later.
    IF OLD.state IN ('APPROVED', 'SUBMITTED', 'PENDING_PROVIDER', 'OUTCOME_UNKNOWN', 'RECONCILING', 'REVIEW')
       AND (NEW.order_hash IS DISTINCT FROM OLD.order_hash OR NEW.credential_id IS DISTINCT FROM OLD.credential_id) THEN
      RAISE EXCEPTION 'payment % : the approved order is immutable', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  INSERT INTO bank_execution_transitions (payment_id, from_state, to_state, attempt_id, actor)
    VALUES (NEW.payment_id, CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.state END, NEW.state, NEW.attempt_id, session_user);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS bank_execution_lifecycle ON bank_executions;
CREATE TRIGGER bank_execution_lifecycle BEFORE INSERT OR UPDATE ON bank_executions FOR EACH ROW EXECUTE FUNCTION bank_execution_lifecycle();

CREATE OR REPLACE FUNCTION bank_payment_lifecycle() RETURNS trigger AS $$
BEGIN
  IF NEW.terms IS DISTINCT FROM OLD.terms OR NEW.bank_transaction_reference IS DISTINCT FROM OLD.bank_transaction_reference THEN
    RAISE EXCEPTION 'payment % : terms and reference are immutable', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.authorization_id IS NOT NULL AND NEW.authorization_id IS DISTINCT FROM OLD.authorization_id THEN
    RAISE EXCEPTION 'payment % : the authorization is attached once', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT (OLD.status = NEW.status OR (OLD.status = 'CREATED' AND NEW.status = 'AWAITING_AUTHORIZATION')) THEN
    RAISE EXCEPTION 'payment % : % -> % is not permitted', OLD.payment_id, OLD.status, NEW.status USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS bank_payment_lifecycle ON bank_payments;
CREATE TRIGGER bank_payment_lifecycle BEFORE UPDATE ON bank_payments FOR EACH ROW EXECUTE FUNCTION bank_payment_lifecycle();

CREATE OR REPLACE FUNCTION bank_chain_head_forward_only() RETURNS trigger AS $$
BEGIN
  IF NEW.chain_sequence < OLD.chain_sequence OR (NEW.chain_sequence = OLD.chain_sequence AND NEW.evidence_hash <> OLD.evidence_hash) THEN
    RAISE EXCEPTION 'chain head of % only moves forward (% -> %)', OLD.nexus_id, OLD.chain_sequence, NEW.chain_sequence USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS bank_chain_head_forward_only ON bank_chain_heads;
CREATE TRIGGER bank_chain_head_forward_only BEFORE UPDATE ON bank_chain_heads FOR EACH ROW EXECUTE FUNCTION bank_chain_head_forward_only();

CREATE OR REPLACE FUNCTION bank_credential_trust_lifecycle() RETURNS trigger AS $$
BEGIN
  IF NEW.nexus_id IS DISTINCT FROM OLD.nexus_id THEN
    RAISE EXCEPTION 'credential % is bound to one customer', OLD.credential_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.state = 'REVOKED' AND NEW.state <> 'REVOKED' THEN
    RAISE EXCEPTION 'credential % : a revocation is final', OLD.credential_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS bank_credential_trust_lifecycle ON bank_credential_trust;
CREATE TRIGGER bank_credential_trust_lifecycle BEFORE UPDATE ON bank_credential_trust FOR EACH ROW EXECUTE FUNCTION bank_credential_trust_lifecycle();

CREATE OR REPLACE FUNCTION bank_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS bank_chain_heads_no_delete ON bank_chain_heads;
CREATE TRIGGER bank_chain_heads_no_delete BEFORE DELETE ON bank_chain_heads FOR EACH ROW EXECUTE FUNCTION bank_append_only();
DROP TRIGGER IF EXISTS bank_trust_statements_append_only ON bank_trust_statements;
CREATE TRIGGER bank_trust_statements_append_only BEFORE UPDATE OR DELETE ON bank_trust_statements FOR EACH ROW EXECUTE FUNCTION bank_append_only();
DROP TRIGGER IF EXISTS bank_execution_transitions_append_only ON bank_execution_transitions;
CREATE TRIGGER bank_execution_transitions_append_only BEFORE UPDATE OR DELETE ON bank_execution_transitions FOR EACH ROW EXECUTE FUNCTION bank_append_only();
DROP TRIGGER IF EXISTS bank_payments_no_delete ON bank_payments;
CREATE TRIGGER bank_payments_no_delete BEFORE DELETE ON bank_payments FOR EACH ROW EXECUTE FUNCTION bank_append_only();
DROP TRIGGER IF EXISTS bank_executions_no_delete ON bank_executions;
CREATE TRIGGER bank_executions_no_delete BEFORE DELETE ON bank_executions FOR EACH ROW EXECUTE FUNCTION bank_append_only();

-- The payment gateway's only access to the journal. It submits the order
-- stored with the payment (never one the caller sends), only for the attempt
-- that holds the approval, once: APPROVED -> SUBMITTED. Returns the order and
-- the hash bound at approval, for the gateway to compare.
CREATE OR REPLACE FUNCTION bank_submit(p_payment UUID, p_attempt UUID)
RETURNS TABLE (operation_id TEXT, payment_order JSONB, order_hash CHAR(64)) AS $$
DECLARE
  row_state TEXT; row_attempt UUID; row_lease TIMESTAMPTZ; row_hash CHAR(64);
BEGIN
  SELECT e.state, e.attempt_id, e.lease_until, e.order_hash INTO row_state, row_attempt, row_lease, row_hash
    FROM bank_executions e WHERE e.payment_id = p_payment FOR UPDATE;
  IF row_state IS NULL THEN RAISE EXCEPTION 'no execution for payment %', p_payment USING ERRCODE = 'insufficient_privilege'; END IF;
  IF row_state <> 'APPROVED' THEN RAISE EXCEPTION 'payment % is % , not APPROVED', p_payment, row_state USING ERRCODE = 'insufficient_privilege'; END IF;
  IF row_attempt <> p_attempt THEN RAISE EXCEPTION 'payment % : the approval belongs to another attempt', p_payment USING ERRCODE = 'insufficient_privilege'; END IF;
  IF row_lease IS NULL OR row_lease <= now() THEN RAISE EXCEPTION 'payment % : the approval expired', p_payment USING ERRCODE = 'insufficient_privilege'; END IF;
  UPDATE bank_executions SET state = 'SUBMITTED', submissions = submissions + 1, updated_at = now() WHERE payment_id = p_payment;
  RETURN QUERY SELECT p.bank_transaction_reference, p.terms, row_hash FROM bank_payments p WHERE p.payment_id = p_payment;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

-- A resubmission of the same operation id, allowed only while reconciling a
-- payment with a provider that declares idempotent submission (the caller,
-- the boundary, decides; the gateway checks the state and the attempt).
CREATE OR REPLACE FUNCTION bank_resubmit(p_payment UUID, p_attempt UUID)
RETURNS TABLE (operation_id TEXT, payment_order JSONB, order_hash CHAR(64)) AS $$
DECLARE
  row_state TEXT; row_attempt UUID; row_hash CHAR(64);
BEGIN
  SELECT e.state, e.attempt_id, e.order_hash INTO row_state, row_attempt, row_hash FROM bank_executions e WHERE e.payment_id = p_payment FOR UPDATE;
  IF row_state IS DISTINCT FROM 'RECONCILING' OR row_attempt IS DISTINCT FROM p_attempt THEN
    RAISE EXCEPTION 'payment % : no reconciliation by this attempt', p_payment USING ERRCODE = 'insufficient_privilege';
  END IF;
  UPDATE bank_executions SET state = 'SUBMITTED', submissions = submissions + 1, updated_at = now() WHERE payment_id = p_payment;
  RETURN QUERY SELECT p.bank_transaction_reference, p.terms, row_hash FROM bank_payments p WHERE p.payment_id = p_payment;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

-- The operation id of a payment that was submitted at least once, for lookups.
CREATE OR REPLACE FUNCTION bank_operation_for_lookup(p_payment UUID) RETURNS TEXT AS $$
  SELECT p.bank_transaction_reference FROM bank_payments p JOIN bank_executions e USING (payment_id)
   WHERE p.payment_id = p_payment AND e.submissions > 0;
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp;
`;

/**
 * Installs the schema (as its owner) and gives each role exactly its part:
 *   boundaryRole  reads everything; writes statements, trust, heads, payments,
 *                 executions (the trigger stops it from submitting) and findings
 *   gatewayRole   no table access; may only call bank_submit, bank_resubmit
 *                 and bank_operation_for_lookup
 */
export async function installSchema(ownerPool, { boundaryRole, gatewayRole } = {}) {
  await ownerPool.query(SCHEMA);
  const tables = ['bank_trust_statements', 'bank_credential_trust', 'bank_chain_heads', 'bank_payments', 'bank_executions', 'bank_execution_transitions', 'bank_reconciliation_findings', 'bank_allowed_transitions'];
  const functions = ['bank_submit(uuid, uuid)', 'bank_resubmit(uuid, uuid)', 'bank_operation_for_lookup(uuid)'];
  for (const f of functions) await ownerPool.query(`REVOKE ALL ON FUNCTION ${f} FROM PUBLIC`);
  if (boundaryRole) {
    const r = ident(boundaryRole);
    await ownerPool.query(`GRANT SELECT ON ${tables.join(', ')} TO ${r}`);
    await ownerPool.query(`GRANT INSERT ON bank_trust_statements, bank_credential_trust, bank_chain_heads, bank_payments, bank_executions, bank_execution_transitions, bank_reconciliation_findings TO ${r}`);
    await ownerPool.query(`GRANT UPDATE ON bank_credential_trust, bank_chain_heads, bank_payments, bank_executions TO ${r}`);
    await ownerPool.query(`GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ${r}`);
  }
  if (gatewayRole) {
    const g = ident(gatewayRole);
    await ownerPool.query(`REVOKE ALL ON ${tables.join(', ')} FROM ${g}`);
    for (const f of functions) await ownerPool.query(`GRANT EXECUTE ON FUNCTION ${f} TO ${g}`);
  }
}
