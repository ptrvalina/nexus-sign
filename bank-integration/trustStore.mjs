// The execution boundary's access to the bank's registry and journal
// (schema.mjs), with the boundary's database role. Every state change is one
// statement or one transaction; the database refuses any transition that is
// not in TRANSITIONS, and refuses SUBMITTED from this role.
import { createHash, randomUUID } from 'node:crypto';
import { canonicalJson } from '../auth-core/scripts/lib/evidence.mjs';
import { APPROVAL, REVOCATION, readRegistry } from '../auth-core/scripts/lib/bankTrust.mjs';

/** The order the bank pays: from its own record of the payment, nothing else. */
export function orderOf(payment) {
  const t = payment.terms;
  return {
    operationId: payment.bankTransactionReference, paymentId: payment.paymentId, reference: t.transactionReference,
    operationType: t.operationType ?? null, amountMinor: String(t.amountMinor), currency: t.currency, beneficiary: t.beneficiary,
  };
}
/** Hash of an order, bound at approval and checked by the gateway. */
export const orderHash = (order) => createHash('sha256').update(canonicalJson(order)).digest('hex');
/** The order the gateway reconstructs from what bank_submit returns. */
export function orderFromSubmission(paymentId, operationId, terms) {
  return orderOf({ paymentId, bankTransactionReference: operationId, terms });
}

/**
 * @param pool a pg Pool connected with the boundary's role
 * @param options.bankTrustKeys when given, statements are verified before they are stored
 */
export function createTrustStore(pool, { bankTrustKeys } = {}) {
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
  const advanceHead = (runner, nexusId, head) => (head ? runner.query(
    `INSERT INTO bank_chain_heads (nexus_id, chain_sequence, evidence_hash) VALUES ($1, $2, $3)
     ON CONFLICT (nexus_id) DO UPDATE SET chain_sequence = EXCLUDED.chain_sequence, evidence_hash = EXCLUDED.evidence_hash, updated_at = now()
     WHERE bank_chain_heads.chain_sequence < EXCLUDED.chain_sequence`, [nexusId, head.chainSequence, head.evidenceHash]) : null);
  const executionView = (row) => (row ? {
    paymentId: row.payment_id, state: row.state, attemptId: row.attempt_id, credentialId: row.credential_id, orderHash: row.order_hash,
    submissions: row.submissions, providerReference: row.provider_reference, problems: row.problems, attempts: row.attempts, resolvedBy: row.resolved_by,
    expired: row.expired,
  } : null);
  const paymentView = (row) => (row ? {
    paymentId: row.payment_id, status: row.status, authorizationId: row.authorization_id, bankTransactionReference: row.bank_transaction_reference, terms: row.terms,
  } : null);
  const ms = (leaseMs) => `now() + ${Number(leaseMs)} * interval '1 millisecond'`;
  /** One guarded transition; true when this attempt made it. */
  const move = async (paymentId, attemptId, from, to, extra = {}, runner = pool) => {
    const sets = ['state = $3', 'updated_at = now()'];
    const args = [paymentId, attemptId, to];
    for (const [column, value] of Object.entries(extra)) {
      if (value === LEASE_CLEAR) { sets.push(`${column} = NULL`); continue; }
      if (value && value.lease) { sets.push(`${column} = ${ms(value.lease)}`); continue; }
      args.push(column === 'problems' ? JSON.stringify(value) : value);
      sets.push(`${column} = $${args.length}`);
    }
    const r = await runner.query(`UPDATE bank_executions SET ${sets.join(', ')} WHERE payment_id = $1 AND attempt_id = $2 AND state = ANY($${args.length + 1}::text[])`,
      [...args, Array.isArray(from) ? from : [from]]);
    return r.rowCount === 1;
  };

  return {
    /** The bank records a payment before it asks Auth Core for an authorization (CREATED). */
    async createPayment({ paymentId, bankTransactionReference, terms, authorizationId }) {
      await pool.query(`INSERT INTO bank_payments (payment_id, status, authorization_id, bank_transaction_reference, terms) VALUES ($1, $2, $3, $4, $5)`,
        [paymentId, authorizationId ? 'AWAITING_AUTHORIZATION' : 'CREATED', authorizationId ?? null, bankTransactionReference, JSON.stringify(terms)]).catch((error) => {
        if (error.code === '23505') throw new Error(`payment already recorded for this authorization or reference (${error.constraint})`);
        throw error;
      });
    },
    /** Auth Core created the authorization: AWAITING_AUTHORIZATION. Once. */
    async attachAuthorization(paymentId, authorizationId) {
      const r = await pool.query(`UPDATE bank_payments SET status = 'AWAITING_AUTHORIZATION', authorization_id = $2 WHERE payment_id = $1 AND status = 'CREATED'`, [paymentId, authorizationId]);
      if (r.rowCount !== 1) throw new Error(`payment ${paymentId} already has an authorization`);
    },
    async payment(paymentId) {
      return paymentView((await pool.query(`SELECT * FROM bank_payments WHERE payment_id = $1`, [paymentId])).rows[0]);
    },
    async paymentForAuthorization(authorizationId) {
      return paymentView((await pool.query(`SELECT * FROM bank_payments WHERE authorization_id = $1`, [authorizationId])).rows[0]);
    },
    async execution(paymentId) {
      return executionView((await pool.query(`SELECT *, lease_until < now() AS expired FROM bank_executions WHERE payment_id = $1`, [paymentId])).rows[0]);
    },
    async transitions(paymentId) {
      return (await pool.query(`SELECT from_state, to_state, attempt_id FROM bank_execution_transitions WHERE payment_id = $1 ORDER BY id`, [paymentId])).rows
        .map((r) => ({ from: r.from_state, to: r.to_state, attemptId: r.attempt_id }));
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
     * Stores a signed revocation (final). It serializes with the approval of an
     * execution on the credential's row: a payment approved after it is
     * refused; payments already APPROVED or later are returned (in flight:
     * the revocation does not stop them).
     */
    async revoke(entry) {
      const s = checked(entry, REVOCATION);
      return tx(async (client) => {
        const existing = (await client.query(`SELECT nexus_id FROM bank_credential_trust WHERE credential_id = $1 FOR UPDATE`, [s.credentialId])).rows[0];
        if (existing && existing.nexus_id !== s.nexusId) throw new Error(`credential ${s.credentialId} belongs to another customer`);
        if (existing) await client.query(`UPDATE bank_credential_trust SET state = 'REVOKED', updated_at = now() WHERE credential_id = $1`, [s.credentialId]);
        else await client.query(`INSERT INTO bank_credential_trust (credential_id, nexus_id, state) VALUES ($1, $2, 'REVOKED')`, [s.credentialId, s.nexusId]);
        await client.query(`INSERT INTO bank_trust_statements (credential_id, nexus_id, type, entry) VALUES ($1, $2, $3, $4)`, [s.credentialId, s.nexusId, REVOCATION, JSON.stringify(entry)]);
        const inFlight = await client.query(`SELECT payment_id, state FROM bank_executions WHERE credential_id = $1 AND state IN ('APPROVED', 'SUBMITTED', 'PENDING_PROVIDER', 'OUTCOME_UNKNOWN', 'RECONCILING', 'REVIEW')`, [s.credentialId]);
        return inFlight.rows.map((r) => ({ paymentId: r.payment_id, state: r.state }));
      });
    },

    async head(nexusId) {
      const row = (await pool.query(`SELECT chain_sequence, evidence_hash FROM bank_chain_heads WHERE nexus_id = $1`, [nexusId])).rows[0];
      return row ? { chainSequence: row.chain_sequence, evidenceHash: row.evidence_hash } : null;
    },
    /** A head the bank received (e.g. from an `evidence.appended` webhook); forward only. */
    async keepHead(nexusId, head) { await advanceHead(pool, nexusId, head); },
    async loadTrust(nexusId) {
      const entries = (await pool.query(`SELECT entry FROM bank_trust_statements WHERE nexus_id = $1 ORDER BY id`, [nexusId])).rows.map((r) => r.entry);
      const row = (await pool.query(`SELECT chain_sequence, evidence_hash FROM bank_chain_heads WHERE nexus_id = $1`, [nexusId])).rows[0];
      return { entries, head: row ? { chainSequence: row.chain_sequence, evidenceHash: row.evidence_hash } : null };
    },

    /**
     * Takes the payment for one attempt. Outcomes:
     *   CHECKING      this attempt checks it (attemptId)
     *   IN_PROGRESS   another attempt holds it (live lease)
     *   FINAL         EXECUTED, PROVIDER_FAILED or REFUSED
     *   REVIEW        a person settles it
     *   RECONCILE     sent, or maybe sent: ask the provider (attemptId of the reconciliation)
     *   NOT_AUTHORIZED the payment has no authorization yet
     */
    async claim(paymentId, leaseMs) {
      return tx(async (client) => {
        const payment = paymentView((await client.query(`SELECT * FROM bank_payments WHERE payment_id = $1 FOR UPDATE`, [paymentId])).rows[0]);
        if (!payment) throw new Error(`no payment ${paymentId} in the bank's records`);
        if (payment.status !== 'AWAITING_AUTHORIZATION') return { outcome: 'NOT_AUTHORIZED', payment };
        const attemptId = randomUUID();
        const inserted = await client.query(`INSERT INTO bank_executions (payment_id, state, attempt_id, lease_until) VALUES ($1, 'CHECKING', $2, ${ms(leaseMs)})
          ON CONFLICT (payment_id) DO NOTHING RETURNING payment_id`, [paymentId, attemptId]);
        if (inserted.rowCount === 1) return { outcome: 'CHECKING', attemptId, payment };
        const row = (await client.query(`SELECT *, lease_until < now() AS expired FROM bank_executions WHERE payment_id = $1 FOR UPDATE`, [paymentId])).rows[0];
        const execution = executionView(row);
        const live = row.lease_until !== null && !row.expired;
        const take = async (to) => {
          await client.query(`UPDATE bank_executions SET state = $2, attempt_id = $3, lease_until = ${ms(leaseMs)}, attempts = attempts + 1, updated_at = now() WHERE payment_id = $1`, [paymentId, to, attemptId]);
        };
        switch (row.state) {
          case 'EXECUTED': case 'PROVIDER_FAILED': case 'REFUSED': return { outcome: 'FINAL', payment, execution };
          case 'REVIEW': return { outcome: 'REVIEW', payment, execution };
          case 'HELD': await take('CHECKING'); return { outcome: 'CHECKING', attemptId, payment };
          case 'CHECKING':
            if (live) return { outcome: 'IN_PROGRESS', payment, execution };
            await take('CHECKING'); return { outcome: 'CHECKING', attemptId, payment };
          case 'APPROVED':
            if (live) return { outcome: 'IN_PROGRESS', payment, execution };
            // The approving attempt is gone. Withdraw the approval unless the
            // gateway took it first (then it is SUBMITTED and gets reconciled).
            await client.query(`UPDATE bank_executions SET state = 'HELD', lease_until = NULL, problems = $2, updated_at = now() WHERE payment_id = $1 AND state = 'APPROVED'`,
              [paymentId, JSON.stringify(['the approving attempt stopped before submission'])]);
            await take('CHECKING'); return { outcome: 'CHECKING', attemptId, payment };
          case 'SUBMITTED': case 'RECONCILING':
            if (live) return { outcome: 'IN_PROGRESS', payment, execution };
            await take('RECONCILING'); return { outcome: 'RECONCILE', attemptId, payment, execution };
          case 'PENDING_PROVIDER': case 'OUTCOME_UNKNOWN':
            await take('RECONCILING'); return { outcome: 'RECONCILE', attemptId, payment, execution };
          default: throw new Error(`unexpected execution state ${row.state}`);
        }
      });
    },

    /**
     * CHECKING -> APPROVED: the revocation cut-off. In one transaction: the
     * credential's trust row read FOR SHARE (a revocation waits, or came
     * first), APPROVED for this customer, this attempt still holding the claim;
     * the approval binds the credential and the order hash.
     */
    async approveExecution(paymentId, attemptId, credentialId, nexusId, hash, leaseMs) {
      return tx(async (client) => {
        const trust = (await client.query(`SELECT nexus_id, state FROM bank_credential_trust WHERE credential_id = $1 FOR SHARE`, [credentialId])).rows[0];
        if (!trust) return { ok: false, reason: `credential ${credentialId} is not in the bank's registry` };
        if (trust.nexus_id !== nexusId) return { ok: false, reason: `credential ${credentialId} is approved for another customer` };
        if (trust.state !== 'APPROVED') return { ok: false, reason: `credential ${credentialId} was revoked by the bank` };
        const moved = await client.query(
          `UPDATE bank_executions SET state = 'APPROVED', credential_id = $3, order_hash = $4, lease_until = ${ms(leaseMs)}, updated_at = now()
           WHERE payment_id = $1 AND attempt_id = $2 AND state = 'CHECKING' AND lease_until > now()`, [paymentId, attemptId, credentialId, hash]);
        return moved.rowCount === 1 ? { ok: true } : { ok: false, lost: true, reason: 'the claim was lost (lease expired or taken over)' };
      });
    },
    async refuse(paymentId, attemptId, problems) { return move(paymentId, attemptId, 'CHECKING', 'REFUSED', { problems, lease_until: LEASE_CLEAR }); },
    async hold(paymentId, attemptId, reason, from = ['CHECKING', 'APPROVED']) { return move(paymentId, attemptId, from, 'HELD', { problems: [reason], lease_until: LEASE_CLEAR }); },
    /** The provider's answer to a submission or a lookup. */
    async record(paymentId, attemptId, outcome, { providerReference = null, reason = null } = {}) {
      const to = { succeeded: 'EXECUTED', failed: 'PROVIDER_FAILED', pending: 'PENDING_PROVIDER', unknown: 'OUTCOME_UNKNOWN', review: 'REVIEW' }[outcome];
      if (!to) throw new Error(`unknown provider outcome ${outcome}`);
      const extra = { lease_until: LEASE_CLEAR, ...(reason ? { problems: [reason] } : {}), ...(providerReference ? { provider_reference: providerReference } : {}) };
      return move(paymentId, attemptId, ['SUBMITTED', 'RECONCILING'], to, extra);
    },
    /** EXECUTED and the kept head forward, in one transaction. */
    async recordExecuted(paymentId, attemptId, providerReference, nexusId, head) {
      return tx(async (client) => {
        const done = await move(paymentId, attemptId, ['SUBMITTED', 'RECONCILING'], 'EXECUTED', { provider_reference: providerReference, lease_until: LEASE_CLEAR }, client);
        if (!done) return false;
        await advanceHead(client, nexusId, head);
        return true;
      });
    },
    /** A person settled a REVIEW with the provider: EXECUTED or PROVIDER_FAILED, with who and why. */
    async resolveReview(paymentId, outcome, { operator, providerReference = null, note }) {
      if (!operator || !note) throw new Error('a resolution needs the operator and a note');
      const to = outcome === 'succeeded' ? 'EXECUTED' : outcome === 'failed' ? 'PROVIDER_FAILED' : null;
      if (!to) throw new Error('a review is resolved as succeeded or failed');
      const r = await pool.query(`UPDATE bank_executions SET state = $2, resolved_by = $3, provider_reference = COALESCE($4, provider_reference), problems = COALESCE(problems, '[]'::jsonb) || $5::jsonb, updated_at = now()
        WHERE payment_id = $1 AND state = 'REVIEW'`, [paymentId, to, operator, providerReference, JSON.stringify([note])]);
      return r.rowCount === 1;
    },
    async addFinding(paymentId, localState, providerStatus, detail) {
      await pool.query(`INSERT INTO bank_reconciliation_findings (payment_id, local_state, provider_status, detail) VALUES ($1, $2, $3, $4)`,
        [paymentId, localState, providerStatus, JSON.stringify(detail ?? null)]);
    },
    async findings(paymentId) {
      return (await pool.query(`SELECT local_state, provider_status, detail FROM bank_reconciliation_findings WHERE payment_id = $1 ORDER BY id`, [paymentId])).rows;
    },
    /** Payments a reconciliation job should look at. */
    async dueForReconciliation() {
      return (await pool.query(`SELECT payment_id FROM bank_executions WHERE state IN ('PENDING_PROVIDER', 'OUTCOME_UNKNOWN')
        OR (state IN ('SUBMITTED', 'RECONCILING', 'APPROVED', 'CHECKING') AND lease_until < now()) ORDER BY updated_at`)).rows.map((r) => r.payment_id);
    },
  };
}

const LEASE_CLEAR = Symbol('clear');
