// The bank's credential registry service, with its own database role: it
// stores the bank's signed approvals and revocations with
// bank.approve_credential / bank.revoke_credential. The database verifies the
// bank's signature against the trust keys installed by the schema owner and
// refuses anything else, so a holder of this role cannot store a statement the
// bank did not sign. The service checks the signature first as well, to give
// a clear error before the database call.
import { APPROVAL, REVOCATION, readRegistry } from '../auth-core/scripts/lib/bankTrust.mjs';

/**
 * @param pool           a pg Pool connected with the registry's role
 * @param bankTrustKeys  the bank's statement-signing public keys (PEM list), required
 */
export function createRegistry(pool, { bankTrustKeys } = {}) {
  if (!Array.isArray(bankTrustKeys) || bankTrustKeys.length === 0) throw new Error('registry: bankTrustKeys are required');
  const keys = Object.freeze([...bankTrustKeys]);
  const checked = (entry, type) => {
    const s = entry?.statement;
    if (!s || s.type !== type) throw new Error(`not a ${type} statement`);
    const { problems } = readRegistry([entry], keys);
    if (problems.length) throw new Error(`statement refused: ${problems.join('; ')}`);
    return s;
  };
  const plain = (error) => { throw new Error(error.message); };
  return {
    /** Stores a signed approval; optionally the chain head the bank verified when approving. */
    async approve(entry, { head } = {}) {
      checked(entry, APPROVAL);
      await pool.query(`SELECT bank.approve_credential($1, $2, $3)`, [JSON.stringify(entry), head?.chainSequence ?? null, head?.evidenceHash ?? null]).catch(plain);
    },
    /**
     * Stores a signed revocation (final). Payments already APPROVED or later
     * are returned: the revocation came after the cut-off and does not stop them.
     */
    /**
     * Records that the customer's mandate was stopped (REVOKED, SUSPENDED,
     * WITHDRAWN or EXPIRED), from a sealed MANDATE record whose HSM seal and
     * chain the caller verified. No debit is approved under it afterwards.
     */
    async recordMandateStop({ mandateId, event, evidenceHash }) {
      await pool.query(`SELECT bank.record_mandate_stop($1, $2, $3)`, [mandateId, event, evidenceHash]).catch(plain);
    },
    async revoke(entry) {
      checked(entry, REVOCATION);
      const rows = (await pool.query(`SELECT * FROM bank.revoke_credential($1)`, [JSON.stringify(entry)]).catch(plain)).rows;
      return rows.map((r) => ({ paymentId: r.payment_id, state: r.state }));
    },
  };
}

/**
 * Operator tools: settling a REVIEW, with four eyes (finding C-13). The
 * database records each operator's login. The first operator's call returns
 * 'REQUESTED'; a second operator, with their own login and the same outcome,
 * gets 'RESOLVED'. 'NOT_IN_REVIEW' when the payment is not in REVIEW.
 *
 * With `authCore` (createAuthCoreClient), a resolution is reported to Auth
 * Core as the commit result (COMMITTED or FAILED). If that report fails the
 * resolution still stands in the bank's database, and the error says so
 * (`error.resolved === true`); report it again with `authCore.commitResult`.
 */
export function createOperatorTools(pool, { authCore = null } = {}) {
  return {
    async resolveReview(paymentId, outcome, note, { providerReference = null } = {}) {
      const result = (await pool.query(`SELECT bank.resolve_review($1, $2, $3, $4) AS result`, [paymentId, outcome, note ?? null, providerReference])).rows[0].result;
      if (result !== 'RESOLVED' || !authCore) return result;
      const authorizationId = (await pool.query(`SELECT authorization_id FROM bank.payments WHERE payment_id = $1`, [paymentId])).rows[0]?.authorization_id;
      if (!authorizationId) return result; // a mandate debit: no authorization to report
      try {
        const answer = outcome === 'succeeded'
          ? await authCore.commitResult(authorizationId, 'COMMITTED')
          : await authCore.commitResult(authorizationId, 'FAILED', `settled by two operators: ${note}`.slice(0, 256));
        if (answer.status >= 300) throw new Error(`HTTP ${answer.status} ${answer.json?.code ?? ''}`.trim());
      } catch (error) {
        throw Object.assign(new Error(`resolved in the bank's database; Auth Core was not told: ${error.message}`), { resolved: true });
      }
      return result;
    },
  };
}
