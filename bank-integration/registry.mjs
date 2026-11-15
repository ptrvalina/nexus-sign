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
    async revoke(entry) {
      checked(entry, REVOCATION);
      const rows = (await pool.query(`SELECT * FROM bank.revoke_credential($1)`, [JSON.stringify(entry)]).catch(plain)).rows;
      return rows.map((r) => ({ paymentId: r.payment_id, state: r.state }));
    },
  };
}

/** Operator tools: settling a REVIEW. The database records the operator's login. */
export function createOperatorTools(pool) {
  return {
    async resolveReview(paymentId, outcome, note, { providerReference = null } = {}) {
      return (await pool.query(`SELECT bank.resolve_review($1, $2, $3, $4) AS ok`, [paymentId, outcome, note ?? null, providerReference])).rows[0].ok;
    },
  };
}
