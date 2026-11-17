// The execution boundary's access to the bank's journal (schema.mjs), with
// the boundary's database role. The role reads the journal and the registry
// and changes nothing directly: every change is a call of one of its
// functions (bank.create_payment, bank.claim, bank.approve, bank.refuse,
// bank.hold, bank.mark_unknown, bank.mark_review, bank.keep_head,
// bank.add_finding). Outcomes from the provider are recorded by the gateway,
// statements by the registry service, resolutions by an operator.

const executionView = (row) => (row ? {
  paymentId: row.payment_id, state: row.state, attemptId: row.attempt_id, credentialId: row.credential_id, orderHash: row.order_hash,
  submissions: row.submissions, providerReference: row.provider_reference, problems: row.problems, attempts: row.attempts, resolvedBy: row.resolved_by,
  expired: row.expired,
} : null);
const paymentView = (row) => (row ? {
  paymentId: row.payment_id, status: row.status, authorizationId: row.authorization_id, bankTransactionReference: row.bank_transaction_reference, terms: row.terms,
} : null);

/** @param pool a pg Pool connected with the boundary's role */
export function createTrustStore(pool) {
  const one = async (sql, args) => (await pool.query(sql, args)).rows[0];
  const execution = async (paymentId) => executionView(await one(`SELECT *, lease_until < now() AS expired FROM bank.executions WHERE payment_id = $1`, [paymentId]));
  const payment = async (paymentId) => paymentView(await one(`SELECT * FROM bank.payments WHERE payment_id = $1`, [paymentId]));
  return {
    /** The bank records a payment before it asks Auth Core for an authorization (CREATED). */
    async createPayment({ paymentId, bankTransactionReference, terms, authorizationId }) {
      await pool.query(`SELECT bank.create_payment($1, $2, $3, $4)`, [paymentId, bankTransactionReference, JSON.stringify(terms), authorizationId ?? null]).catch((error) => {
        if (error.code === '23505') throw new Error(`payment already recorded for this authorization or reference (${error.constraint})`);
        throw error;
      });
    },
    /** Auth Core created the authorization: AWAITING_AUTHORIZATION. Once. */
    async attachAuthorization(paymentId, authorizationId) {
      if (!(await one(`SELECT bank.attach_authorization($1, $2) AS ok`, [paymentId, authorizationId])).ok) throw new Error(`payment ${paymentId} already has an authorization`);
    },
    /** The payment is a debit under the customer's signed mandate. */
    async attachMandate(paymentId, mandateId) {
      if (!(await one(`SELECT bank.attach_mandate($1, $2) AS ok`, [paymentId, mandateId])).ok) throw new Error(`payment ${paymentId} already has an authorization`);
    },
    payment,
    async paymentForAuthorization(authorizationId) {
      return paymentView(await one(`SELECT * FROM bank.payments WHERE authorization_id = $1`, [authorizationId]));
    },
    execution,
    /** The transition log: every change, with the function that made it and the database login that called it. */
    async transitions(paymentId) {
      return (await pool.query(`SELECT from_state, to_state, attempt_id, actor, via FROM bank.execution_transitions WHERE payment_id = $1 ORDER BY id`, [paymentId])).rows
        .map((r) => ({ from: r.from_state, to: r.to_state, attemptId: r.attempt_id, actor: r.actor, via: r.via }));
    },

    async head(nexusId) {
      const row = await one(`SELECT chain_sequence, evidence_hash FROM bank.chain_heads WHERE nexus_id = $1`, [nexusId]);
      return row ? { chainSequence: row.chain_sequence, evidenceHash: row.evidence_hash } : null;
    },
    /** A head the bank verified or received (e.g. from an `evidence.appended` webhook); forward only. */
    async keepHead(nexusId, head) {
      if (!head) return false;
      return (await one(`SELECT bank.keep_head($1, $2, $3) AS moved`, [nexusId, head.chainSequence, head.evidenceHash])).moved;
    },
    async loadTrust(nexusId) {
      const entries = (await pool.query(`SELECT entry FROM bank.trust_statements WHERE nexus_id = $1 ORDER BY id`, [nexusId])).rows.map((r) => r.entry);
      const row = await one(`SELECT chain_sequence, evidence_hash FROM bank.chain_heads WHERE nexus_id = $1`, [nexusId]);
      return { entries, head: row ? { chainSequence: row.chain_sequence, evidenceHash: row.evidence_hash } : null };
    },

    /**
     * Takes the payment for one attempt (bank.claim). Outcomes:
     *   CHECKING       this attempt checks it (attemptId)
     *   IN_PROGRESS    another attempt holds it (live lease)
     *   FINAL          EXECUTED, PROVIDER_FAILED or REFUSED
     *   REVIEW         a person settles it
     *   RECONCILE      sent, or maybe sent: ask the provider (attemptId of the reconciliation)
     *   NOT_AUTHORIZED the payment has no authorization yet
     */
    async claim(paymentId, leaseMs) {
      const r = await one(`SELECT * FROM bank.claim($1, $2)`, [paymentId, Math.round(Number(leaseMs))]);
      const result = { outcome: r.outcome, payment: await payment(paymentId) };
      if (r.attempt) result.attemptId = r.attempt;
      if (['FINAL', 'REVIEW', 'IN_PROGRESS', 'RECONCILE'].includes(r.outcome)) result.execution = await execution(paymentId);
      return result;
    },

    /**
     * CHECKING -> APPROVED (bank.approve) with the evidence the boundary
     * verified. The database takes the credential from the evidence, checks
     * it against the payment and the registry (FOR SHARE, serialized with a
     * revocation), and binds the order hash itself.
     */
    async approveExecution(paymentId, attemptId, evidence, leaseMs) {
      const r = await one(`SELECT * FROM bank.approve($1, $2, $3, $4)`, [paymentId, attemptId, JSON.stringify(evidence ?? null), Math.round(Number(leaseMs))]);
      if (r.ok) return { ok: true };
      return r.lost ? { ok: false, lost: true, reason: r.reason } : { ok: false, reason: r.reason };
    },
    async refuse(paymentId, attemptId, problems) {
      return (await one(`SELECT bank.refuse($1, $2, $3) AS ok`, [paymentId, attemptId, JSON.stringify(problems ?? [])])).ok;
    },
    async hold(paymentId, attemptId, reason, from = ['CHECKING', 'APPROVED']) {
      return (await one(`SELECT bank.hold($1, $2, $3, $4) AS ok`, [paymentId, attemptId, String(reason), from])).ok;
    },
    /** SUBMITTED or RECONCILING -> OUTCOME_UNKNOWN: the boundary lost contact with the gateway. */
    async markUnknown(paymentId, attemptId, reason) {
      return (await one(`SELECT bank.mark_unknown($1, $2, $3) AS ok`, [paymentId, attemptId, String(reason)])).ok;
    },
    /** RECONCILING -> REVIEW: the provider's contract cannot settle it automatically. */
    async markReview(paymentId, attemptId, reason) {
      return (await one(`SELECT bank.mark_review($1, $2, $3) AS ok`, [paymentId, attemptId, String(reason)])).ok;
    },
    async addFinding(paymentId, localState, providerStatus, detail) {
      await pool.query(`SELECT bank.add_finding($1, $2, $3, $4)`, [paymentId, localState, providerStatus, JSON.stringify(detail ?? null)]);
    },
    async findings(paymentId) {
      return (await pool.query(`SELECT local_state, provider_status, detail FROM bank.reconciliation_findings WHERE payment_id = $1 ORDER BY id`, [paymentId])).rows;
    },
    /** Payments a reconciliation job should look at. */
    async dueForReconciliation() {
      return (await pool.query(`SELECT payment_id FROM bank.executions WHERE state IN ('PENDING_PROVIDER', 'OUTCOME_UNKNOWN')
        OR (state IN ('SUBMITTED', 'RECONCILING', 'APPROVED', 'CHECKING') AND lease_until < now()) ORDER BY updated_at`)).rows.map((r) => r.payment_id);
    },
  };
}
