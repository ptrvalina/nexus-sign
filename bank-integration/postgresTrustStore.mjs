// The bank's own trust registry and execution journal, in the bank's
// PostgreSQL (never Auth Core's). Reference implementation of the store the
// execution boundary needs; a bank may implement the same contract on its
// own database. The `pg` pool is passed in: this module has no dependencies.
//
// Tables:
//   bank_trust_statements   signed approvals and revocations, as signed
//   bank_credential_trust   per credential: the customer it is bound to and
//                           APPROVED or REVOKED (final); the row the final
//                           check and a revocation serialize on
//   bank_chain_heads        the latest chain head the bank has seen, per customer (forward only)
//   bank_payments           the bank's own record of each payment and the terms it asked for
//   bank_executions         the execution journal: one row per payment, final states fixed
import { randomUUID } from 'node:crypto';
import { APPROVAL, REVOCATION, readRegistry } from '../auth-core/scripts/lib/bankTrust.mjs';

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
  authorization_id UUID NOT NULL UNIQUE,
  bank_transaction_reference TEXT NOT NULL UNIQUE,
  terms JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank_executions (
  payment_id UUID PRIMARY KEY REFERENCES bank_payments (payment_id),
  state TEXT NOT NULL CHECK (state IN ('CLAIMED', 'HELD', 'EXECUTING', 'OUTCOME_UNKNOWN', 'EXECUTED', 'REFUSED', 'REVIEW')),
  claim_id UUID,
  lease_until TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0,
  credential_id UUID,
  provider_reference TEXT,
  problems JSONB,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION bank_execution_lifecycle() RETURNS trigger AS $$
BEGIN
  IF OLD.state IN ('EXECUTED', 'REFUSED') THEN
    RAISE EXCEPTION 'execution of payment % is final (%)', OLD.payment_id, OLD.state USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'EXECUTED' AND OLD.state NOT IN ('EXECUTING', 'OUTCOME_UNKNOWN') THEN
    RAISE EXCEPTION 'payment % : EXECUTED only after EXECUTING', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = 'EXECUTING' AND OLD.state <> 'CLAIMED' THEN
    RAISE EXCEPTION 'payment % : EXECUTING only from CLAIMED', OLD.payment_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS bank_execution_lifecycle ON bank_executions;
CREATE TRIGGER bank_execution_lifecycle BEFORE UPDATE ON bank_executions FOR EACH ROW EXECUTE FUNCTION bank_execution_lifecycle();
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
DROP TRIGGER IF EXISTS bank_trust_statements_append_only ON bank_trust_statements;
CREATE TRIGGER bank_trust_statements_append_only BEFORE UPDATE OR DELETE ON bank_trust_statements FOR EACH ROW EXECUTE FUNCTION bank_append_only();
`;

const CLAIMABLE = ['HELD'];

/**
 * @param pool a pg Pool on the bank's database
 * @param options.bankTrustKeys when given, statements are verified before they are stored
 */
export function createPostgresTrustStore(pool, { bankTrustKeys } = {}) {
  const tx = async (work) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  };
  const checked = (entry, type) => {
    const s = entry?.statement;
    if (!s || s.type !== type) throw new Error(`not a ${type} statement`);
    if (bankTrustKeys) {
      const { problems } = readRegistry([entry], bankTrustKeys);
      if (problems.length) throw new Error(`statement refused: ${problems.join('; ')}`);
    }
    return s;
  };
  const advanceHead = (client, nexusId, head) => (head ? client.query(
    `INSERT INTO bank_chain_heads (nexus_id, chain_sequence, evidence_hash) VALUES ($1, $2, $3)
     ON CONFLICT (nexus_id) DO UPDATE SET chain_sequence = EXCLUDED.chain_sequence, evidence_hash = EXCLUDED.evidence_hash, updated_at = now()
     WHERE bank_chain_heads.chain_sequence < EXCLUDED.chain_sequence`, [nexusId, head.chainSequence, head.evidenceHash]) : null);
  const executionView = (row) => (row ? {
    paymentId: row.payment_id, state: row.state, claimId: row.claim_id, credentialId: row.credential_id,
    providerReference: row.provider_reference, problems: row.problems, attempts: row.attempts,
  } : null);
  const paymentView = (row) => (row ? {
    paymentId: row.payment_id, authorizationId: row.authorization_id, bankTransactionReference: row.bank_transaction_reference, terms: row.terms,
  } : null);

  return {
    async migrate() { await pool.query(SCHEMA); },

    /** The bank records a payment and the terms it asks the customer to confirm. */
    async createPayment({ paymentId, authorizationId, bankTransactionReference, terms }) {
      await pool.query(`INSERT INTO bank_payments (payment_id, authorization_id, bank_transaction_reference, terms) VALUES ($1, $2, $3, $4)`,
        [paymentId, authorizationId, bankTransactionReference, JSON.stringify(terms)]).catch((error) => {
        if (error.code === '23505') throw new Error(`payment already recorded for this authorization or reference (${error.constraint})`);
        throw error;
      });
    },
    async payment(paymentId) {
      return paymentView((await pool.query(`SELECT * FROM bank_payments WHERE payment_id = $1`, [paymentId])).rows[0]);
    },
    async execution(paymentId) {
      return executionView((await pool.query(`SELECT * FROM bank_executions WHERE payment_id = $1`, [paymentId])).rows[0]);
    },

    /** Stores a signed approval; optionally the chain head the bank verified when approving. */
    async approve(entry, { head } = {}) {
      const s = checked(entry, APPROVAL);
      return tx(async (client) => {
        const existing = (await client.query(`SELECT nexus_id, state FROM bank_credential_trust WHERE credential_id = $1 FOR UPDATE`, [s.credentialId])).rows[0];
        if (existing && existing.nexus_id !== s.nexusId) throw new Error(`credential ${s.credentialId} is approved for another customer`);
        if (existing && existing.state === 'REVOKED') throw new Error(`credential ${s.credentialId} was revoked; a new device gets a new credential`);
        if (!existing) await client.query(`INSERT INTO bank_credential_trust (credential_id, nexus_id, state) VALUES ($1, $2, 'APPROVED')`, [s.credentialId, s.nexusId]);
        await client.query(`INSERT INTO bank_trust_statements (credential_id, nexus_id, type, entry) VALUES ($1, $2, $3, $4)`, [s.credentialId, s.nexusId, APPROVAL, JSON.stringify(entry)]);
        await advanceHead(client, s.nexusId, head);
      });
    },

    /**
     * Stores a signed revocation (final). Serializes with the final check of
     * the execution boundary on the credential's row: a payment checked after
     * this is refused; a payment already past its final check is returned, so
     * the bank can stop or reverse it.
     */
    async revoke(entry) {
      const s = checked(entry, REVOCATION);
      return tx(async (client) => {
        const existing = (await client.query(`SELECT nexus_id FROM bank_credential_trust WHERE credential_id = $1 FOR UPDATE`, [s.credentialId])).rows[0];
        if (existing && existing.nexus_id !== s.nexusId) throw new Error(`credential ${s.credentialId} belongs to another customer`);
        if (existing) await client.query(`UPDATE bank_credential_trust SET state = 'REVOKED', updated_at = now() WHERE credential_id = $1`, [s.credentialId]);
        else await client.query(`INSERT INTO bank_credential_trust (credential_id, nexus_id, state) VALUES ($1, $2, 'REVOKED')`, [s.credentialId, s.nexusId]);
        await client.query(`INSERT INTO bank_trust_statements (credential_id, nexus_id, type, entry) VALUES ($1, $2, $3, $4)`, [s.credentialId, s.nexusId, REVOCATION, JSON.stringify(entry)]);
        const inFlight = await client.query(`SELECT payment_id, state FROM bank_executions WHERE credential_id = $1 AND state IN ('EXECUTING', 'OUTCOME_UNKNOWN')`, [s.credentialId]);
        return inFlight.rows.map((r) => ({ paymentId: r.payment_id, state: r.state }));
      });
    },

    async head(nexusId) {
      const row = (await pool.query(`SELECT chain_sequence, evidence_hash FROM bank_chain_heads WHERE nexus_id = $1`, [nexusId])).rows[0];
      return row ? { chainSequence: row.chain_sequence, evidenceHash: row.evidence_hash } : null;
    },
    /** A head the bank received (e.g. from an `evidence.appended` webhook); forward only. */
    async keepHead(nexusId, head) { await advanceHead(pool, nexusId, head); },

    /** The bank's statements for a customer and the head it kept. */
    async loadTrust(nexusId) {
      const entries = (await pool.query(`SELECT entry FROM bank_trust_statements WHERE nexus_id = $1 ORDER BY id`, [nexusId])).rows.map((r) => r.entry);
      return { entries, head: await this.head(nexusId) };
    },

    /**
     * Claims a payment for one attempt. Outcomes: CLAIMED (go on, with
     * claimId), IN_PROGRESS (another attempt holds it), DONE, REFUSED, REVIEW
     * (final or waiting for a person), RECONCILE (the payment system may have
     * executed it: look it up, never execute again).
     */
    async claim(paymentId, leaseMs) {
      return tx(async (client) => {
        const payment = paymentView((await client.query(`SELECT * FROM bank_payments WHERE payment_id = $1`, [paymentId])).rows[0]);
        if (!payment) throw new Error(`no payment ${paymentId} in the bank's records`);
        const claimId = randomUUID();
        const inserted = await client.query(
          `INSERT INTO bank_executions (payment_id, state, claim_id, lease_until, attempts) VALUES ($1, 'CLAIMED', $2, now() + $3 * interval '1 millisecond', 1)
           ON CONFLICT (payment_id) DO NOTHING RETURNING payment_id`, [paymentId, claimId, leaseMs]);
        if (inserted.rowCount === 1) return { outcome: 'CLAIMED', claimId, payment };
        const row = (await client.query(`SELECT *, lease_until < now() AS expired FROM bank_executions WHERE payment_id = $1 FOR UPDATE`, [paymentId])).rows[0];
        const execution = executionView(row);
        if (row.state === 'EXECUTED') return { outcome: 'DONE', payment, execution };
        if (row.state === 'REFUSED') return { outcome: 'REFUSED', payment, execution };
        if (row.state === 'REVIEW') return { outcome: 'REVIEW', payment, execution };
        if (row.state === 'OUTCOME_UNKNOWN' || (row.state === 'EXECUTING' && row.expired)) return { outcome: 'RECONCILE', payment, execution };
        if (row.state === 'EXECUTING' || (row.state === 'CLAIMED' && !row.expired)) return { outcome: 'IN_PROGRESS', payment, execution };
        if (row.state === 'CLAIMED' || CLAIMABLE.includes(row.state)) {
          await client.query(`UPDATE bank_executions SET state = 'CLAIMED', claim_id = $2, lease_until = now() + $3 * interval '1 millisecond', attempts = attempts + 1, updated_at = now() WHERE payment_id = $1`,
            [paymentId, claimId, leaseMs]);
          return { outcome: 'CLAIMED', claimId, payment };
        }
        throw new Error(`unexpected execution state ${row.state}`);
      });
    },

    /**
     * The last check before the payment system, in one transaction with the
     * move to EXECUTING: the credential must still be APPROVED for this
     * customer (its row is read FOR SHARE, so a revocation waits or comes
     * first), and this attempt must still hold the claim.
     */
    async finalCheck(paymentId, claimId, credentialId, nexusId, leaseMs) {
      return tx(async (client) => {
        const trust = (await client.query(`SELECT nexus_id, state FROM bank_credential_trust WHERE credential_id = $1 FOR SHARE`, [credentialId])).rows[0];
        if (!trust) return { ok: false, reason: `credential ${credentialId} is not in the bank's registry` };
        if (trust.nexus_id !== nexusId) return { ok: false, reason: `credential ${credentialId} is approved for another customer` };
        if (trust.state !== 'APPROVED') return { ok: false, reason: `credential ${credentialId} was revoked by the bank` };
        const moved = await client.query(
          `UPDATE bank_executions SET state = 'EXECUTING', credential_id = $3, lease_until = now() + $4 * interval '1 millisecond', updated_at = now()
           WHERE payment_id = $1 AND claim_id = $2 AND state = 'CLAIMED' AND lease_until > now()`, [paymentId, claimId, credentialId, leaseMs]);
        return moved.rowCount === 1 ? { ok: true } : { ok: false, lost: true, reason: 'the claim was lost (lease expired or taken over)' };
      });
    },

    async markRefused(paymentId, claimId, problems) {
      await pool.query(`UPDATE bank_executions SET state = 'REFUSED', problems = $3, lease_until = NULL, updated_at = now() WHERE payment_id = $1 AND claim_id = $2 AND state = 'CLAIMED'`,
        [paymentId, claimId, JSON.stringify(problems)]);
    },
    async markHeld(paymentId, claimId, reason) {
      await pool.query(`UPDATE bank_executions SET state = 'HELD', problems = $3, lease_until = NULL, updated_at = now() WHERE payment_id = $1 AND claim_id = $2 AND state = 'CLAIMED'`,
        [paymentId, claimId, JSON.stringify([reason])]);
    },
    async markOutcomeUnknown(paymentId, reason) {
      await pool.query(`UPDATE bank_executions SET state = 'OUTCOME_UNKNOWN', problems = $2, updated_at = now() WHERE payment_id = $1 AND state = 'EXECUTING'`,
        [paymentId, JSON.stringify([reason])]);
    },
    async markReview(paymentId, reason) {
      await pool.query(`UPDATE bank_executions SET state = 'REVIEW', problems = $2, updated_at = now() WHERE payment_id = $1 AND state IN ('EXECUTING', 'OUTCOME_UNKNOWN')`,
        [paymentId, JSON.stringify([reason])]);
    },
    /** Records the execution and moves the kept head forward, in one transaction. */
    async markExecuted(paymentId, providerReference, nexusId, head) {
      return tx(async (client) => {
        const done = await client.query(`UPDATE bank_executions SET state = 'EXECUTED', provider_reference = $2, lease_until = NULL, updated_at = now()
          WHERE payment_id = $1 AND state IN ('EXECUTING', 'OUTCOME_UNKNOWN')`, [paymentId, providerReference]);
        if (done.rowCount !== 1) throw new Error(`payment ${paymentId} was not executing`);
        await advanceHead(client, nexusId, head);
      });
    },
  };
}
