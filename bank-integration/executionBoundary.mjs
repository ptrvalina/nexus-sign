// The bank's execution boundary: the one place where a payment confirmed
// through NEXUS-SIGN may reach the payment system. A bank backend routes
// every path to execution (operator action, API, webhook handler, retry job,
// administrative tool) through `execute(paymentId)`, and gives the payment
// adapter only to the boundary (guardPaymentAdapter).
//
// Order of one attempt (bank-execution-boundary.md):
//  1. claim the payment in the bank's journal (idempotency, one attempt at a time);
//  2. commit request at Auth Core: a precondition, not a reason to execute;
//  3. evidence and chain from Auth Core, the bank's statements and kept head
//     from its own store; bankExecutionDecision on them;
//  4. final check under a lock on the credential's trust row, and EXECUTING;
//  5. the payment system, with a one-time permit and the payment's
//     bank transaction reference as idempotency key;
//  6. EXECUTED and the kept head forward; Auth Core informed.
// Any error before 5 holds the payment (no execution). An error in 5 leaves
// the outcome unknown: the next attempt looks the payment up by its key and
// never executes it again.
import { randomUUID } from 'node:crypto';
import { canonicalJson } from '../auth-core/scripts/lib/evidence.mjs';
import { bankExecutionDecision } from '../auth-core/scripts/lib/bankTrust.mjs';

export class BoundaryBypassError extends Error {}

/**
 * Wraps the bank's payment system adapter ({ execute(order), lookup(key) })
 * so that execute works only with a permit the boundary issued for exactly
 * that order, once. Give `adapter` to whoever needs it; keep `issuePermit`
 * inside the boundary.
 */
export function guardPaymentAdapter(raw) {
  const permits = new Map();
  const fingerprint = (order) => canonicalJson(order).toString('utf8');
  const adapter = Object.freeze({
    async execute(permit, order) {
      const expected = typeof permit === 'string' ? permits.get(permit) : undefined;
      if (typeof permit === 'string') permits.delete(permit);
      if (expected === undefined || expected !== fingerprint(order)) {
        throw new BoundaryBypassError('the payment adapter executes only orders the execution boundary has checked (no valid permit for this order)');
      }
      return raw.execute(order);
    },
    async lookup(idempotencyKey) { return raw.lookup(idempotencyKey); },
  });
  return Object.freeze({
    adapter,
    issuePermit(order) { const permit = randomUUID(); permits.set(permit, fingerprint(order)); return permit; },
  });
}

const tail = (chain) => {
  const last = [...(chain?.records ?? [])].sort((a, b) => b.chainSequence - a.chainSequence)[0];
  return last ? { chainSequence: last.chainSequence, evidenceHash: last.evidenceHash } : null;
};

/**
 * @param store          the bank's trust registry and journal (createPostgresTrustStore)
 * @param authCore       createAuthCoreClient(...)
 * @param payments       guardPaymentAdapter(rawAdapter)
 * @param evidenceKeys   evidence public keys the bank pinned (PEM list)
 * @param bankTrustKeys  the bank's statement-signing public keys (PEM list)
 * @param leaseMs        how long one attempt may hold a payment
 */
export function createExecutionBoundary({ store, authCore, payments, evidenceKeys, bankTrustKeys, leaseMs = 60_000 }) {
  if (!store || !authCore || !payments?.issuePermit || !payments?.adapter) throw new Error('execution boundary: store, authCore and a guarded payment adapter are required');
  const pinned = [...(evidenceKeys ?? [])];
  const trustKeys = [...(bankTrustKeys ?? [])];
  const inform = (authorizationId, state, error) => authCore.commitResult(authorizationId, state, error).catch(() => undefined);

  async function reconcile(claim) {
    const { payment } = claim;
    let found;
    try {
      found = await payments.adapter.lookup(payment.bankTransactionReference);
    } catch (error) {
      return { status: 'OUTCOME_UNKNOWN', reason: `payment system lookup failed: ${error.message}` };
    }
    if (found?.status === 'EXECUTED') {
      await store.markExecuted(payment.paymentId, found.providerReference ?? null, payment.terms.nexusId, null);
      await inform(payment.authorizationId, 'COMMITTED');
      return { status: 'EXECUTED', providerReference: found.providerReference ?? null, reconciled: true };
    }
    // Not found: the request may never have arrived, or may still arrive. It
    // is not retried automatically.
    await store.markReview(payment.paymentId, 'the payment system does not know this payment; outcome to be settled by a person');
    return { status: 'REVIEW', reason: 'outcome unknown and not found at the payment system' };
  }

  async function execute(paymentId) {
    let claim;
    try {
      claim = await store.claim(paymentId, leaseMs);
    } catch (error) {
      return { status: 'HELD', reason: `trust store unavailable: ${error.message}` };
    }
    if (claim.outcome === 'DONE') return { status: 'EXECUTED', repeated: true, providerReference: claim.execution.providerReference };
    if (claim.outcome === 'REFUSED') return { status: 'REFUSED', repeated: true, problems: claim.execution.problems ?? [] };
    if (claim.outcome === 'REVIEW') return { status: 'REVIEW', problems: claim.execution.problems ?? [] };
    if (claim.outcome === 'IN_PROGRESS') return { status: 'IN_PROGRESS' };
    if (claim.outcome === 'RECONCILE') return reconcile(claim);

    const { payment, claimId } = claim;
    const { terms } = payment;
    let commitRequested = false;
    const refuse = async (problems) => {
      await store.markRefused(paymentId, claimId, problems);
      if (commitRequested) await inform(payment.authorizationId, 'CANCELLED', 'refused by the bank\'s execution check');
      return { status: 'REFUSED', problems };
    };
    let evidence; let chain;
    try {
      const commit = await authCore.commitRequest(payment.authorizationId, payment.bankTransactionReference);
      if (commit.status !== 202) {
        if (commit.status >= 400 && commit.status < 500) return refuse([`Auth Core refused the commit request: HTTP ${commit.status} ${commit.json?.code ?? ''}`.trim()]);
        throw new Error(`Auth Core commit request: HTTP ${commit.status}`);
      }
      commitRequested = true;
      evidence = await authCore.evidence(payment.authorizationId);
      chain = await authCore.chain(terms.nexusId);
      const trust = await store.loadTrust(terms.nexusId);
      const decision = bankExecutionDecision({
        evidence, chain, evidenceKeys: pinned, bankTrustKeys: trustKeys, registry: trust.entries,
        expected: terms, expectedHead: trust.head ?? undefined,
      });
      if (!decision.allowed) return refuse(decision.problems);
      const final = await store.finalCheck(paymentId, claimId, evidence.sealedPayload.credentialId, terms.nexusId, leaseMs);
      if (!final.ok) return final.lost ? { status: 'IN_PROGRESS', reason: final.reason } : refuse([final.reason]);
    } catch (error) {
      await store.markHeld(paymentId, claimId, error.message).catch(() => undefined);
      return { status: 'HELD', reason: error.message };
    }

    const order = {
      idempotencyKey: payment.bankTransactionReference, reference: terms.transactionReference, operationType: terms.operationType ?? null,
      amountMinor: terms.amountMinor, currency: terms.currency, beneficiary: terms.beneficiary,
    };
    let result;
    try {
      result = await payments.adapter.execute(payments.issuePermit(order), order);
    } catch (error) {
      await store.markOutcomeUnknown(paymentId, error.message).catch(() => undefined);
      return { status: 'OUTCOME_UNKNOWN', reason: error.message };
    }
    try {
      await store.markExecuted(paymentId, result?.providerReference ?? null, terms.nexusId, tail(chain));
    } catch (error) {
      // Executed, but not recorded: stays EXECUTING; the next attempt reconciles.
      return { status: 'OUTCOME_UNKNOWN', reason: `executed, journal not updated: ${error.message}` };
    }
    await inform(payment.authorizationId, 'COMMITTED');
    return { status: 'EXECUTED', providerReference: result?.providerReference ?? null };
  }

  return Object.freeze({ execute });
}
