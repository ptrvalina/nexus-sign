// The bank's execution boundary: the one place that may decide that a
// payment confirmed through NEXUS-SIGN is sent to the payment provider. Every
// path to execution in the bank's backend (operator action, API, webhook
// handler, retry and reconciliation jobs, administrative tools) calls
// `execute(paymentId)`. The provider is reachable only through the payment
// gateway, which sends nothing the boundary has not APPROVED in the bank's
// database, checks the approval again, and records the provider's answers
// itself (paymentGateway.mjs, schema.mjs). The boundary's database role can
// change nothing directly; it calls its functions in the schema `bank`.
//
// The state machine, every transition and the behaviour on failure and
// restart: docs/architecture/payment-state-machine.md.
import { bankExecutionDecision } from '../auth-core/scripts/lib/bankTrust.mjs';
import { GatewayRefusedError } from './paymentGateway.mjs';

/** Thrown by a test hook to stop an attempt as a crash would: no clean-up runs. */
export class SimulatedCrash extends Error {}

const tail = (chain) => {
  const last = [...(chain?.records ?? [])].sort((a, b) => b.chainSequence - a.chainSequence)[0];
  return last ? { chainSequence: last.chainSequence, evidenceHash: last.evidenceHash } : null;
};

/**
 * @param store                 createTrustStore(pool with the boundary's role)
 * @param authCore              createAuthCoreClient(...)
 * @param gateway               createGatewayClient(...) (or createPaymentGateway(...) in one process)
 * @param evidenceKeys          evidence public keys the bank pinned (PEM list)
 * @param bankTrustKeys         the bank's statement-signing public keys (PEM list)
 * @param providerCapabilities  what the provider's contract guarantees:
 *                              { idempotentSubmit: boolean, lookup: boolean }; both default false
 * @param leaseMs               how long one attempt may hold a payment
 * @param hooks                 test barriers: { [step]: async ({ paymentId, attemptId }) => void }
 */
export function createExecutionBoundary({ store, authCore, gateway, evidenceKeys, bankTrustKeys, providerCapabilities = {}, leaseMs = 60_000, hooks = {} }) {
  if (!store || !authCore || !gateway) throw new Error('execution boundary: store, authCore and gateway are required');
  const pinned = Object.freeze([...(evidenceKeys ?? [])]);
  const trustKeys = Object.freeze([...(bankTrustKeys ?? [])]);
  const caps = Object.freeze({ idempotentSubmit: providerCapabilities.idempotentSubmit === true, lookup: providerCapabilities.lookup === true });
  const hook = async (step, context) => { if (hooks[step]) await hooks[step](context); };
  const crash = (error) => { if (error instanceof SimulatedCrash) throw error; };
  const inform = (authorizationId, state, error) => authCore.commitResult(authorizationId, state, error).catch(() => undefined);

  const STATUS = { succeeded: 'EXECUTED', failed: 'PROVIDER_FAILED', pending: 'PENDING_PROVIDER', unknown: 'OUTCOME_UNKNOWN', review: 'REVIEW' };

  /** The gateway's answer, which the gateway already recorded for this attempt. */
  async function settle(payment, answer, chain) {
    if (answer.recorded === false) return { status: 'IN_PROGRESS', reason: 'the outcome was not recorded for this attempt (taken over, or the bank\'s database was unavailable)' };
    if (answer.outcome === 'succeeded') {
      await store.keepHead(payment.terms.nexusId, tail(chain)).catch(() => undefined);
      await inform(payment.authorizationId, 'COMMITTED');
    } else if (answer.outcome === 'failed') {
      await inform(payment.authorizationId, 'FAILED', 'the payment provider reported a failure');
    }
    const status = STATUS[answer.outcome] ?? 'OUTCOME_UNKNOWN';
    return { status, providerReference: answer.providerReference ?? null, ...(answer.reason ? { reason: answer.reason } : {}) };
  }
  /** The boundary's own decisions after a submission: unknown or review. */
  async function mark(kind, paymentId, attemptId, reason) {
    const done = await (kind === 'review' ? store.markReview : store.markUnknown)(paymentId, attemptId, reason).catch(() => false);
    if (!done) return { status: 'IN_PROGRESS', reason: 'another attempt took the payment over' };
    return { status: kind === 'review' ? 'REVIEW' : 'OUTCOME_UNKNOWN', providerReference: null, reason };
  }

  /** The payment was sent, or may have been: ask the provider, never send it again blindly. */
  async function reconcile(claim) {
    const { payment, attemptId } = claim;
    const { paymentId } = payment;
    await hook('reconciling', { paymentId, attemptId });
    if (!caps.lookup) return mark('review', paymentId, attemptId, 'the provider contract has no lookup: settled by a person');
    let found;
    try {
      found = await gateway.reconcile(paymentId, attemptId);
    } catch (error) {
      crash(error);
      return mark('unknown', paymentId, attemptId, `lookup failed: ${error.message}`);
    }
    if (found?.status === 'not_found') {
      if (!caps.idempotentSubmit) return mark('review', paymentId, attemptId, 'not found at the provider, and its contract does not make a resubmission safe');
      try {
        return settle(payment, await gateway.resubmit(paymentId, attemptId));
      } catch (error) {
        crash(error);
        if (error instanceof GatewayRefusedError) return { status: 'IN_PROGRESS', reason: error.message };
        return mark('unknown', paymentId, attemptId, `resubmission failed: ${error.message}`);
      }
    }
    return settle(payment, { outcome: found?.status ?? 'unknown', providerReference: found?.providerReference, reason: found?.reason, recorded: found?.recorded });
  }

  async function execute(paymentId) {
    let claim;
    try {
      claim = await store.claim(paymentId, leaseMs);
    } catch (error) {
      return { status: 'HELD', reason: `trust store unavailable: ${error.message}` };
    }
    switch (claim.outcome) {
      case 'NOT_AUTHORIZED': return { status: 'NOT_AUTHORIZED' };
      case 'FINAL': return { status: claim.execution.state, repeated: true, providerReference: claim.execution.providerReference, problems: claim.execution.problems ?? [] };
      case 'REVIEW': return { status: 'REVIEW', problems: claim.execution.problems ?? [] };
      case 'IN_PROGRESS': return { status: 'IN_PROGRESS' };
      case 'RECONCILE': return reconcile(claim);
      default: break;
    }

    const { payment, attemptId } = claim;
    const { terms } = payment;
    const context = { paymentId, attemptId };
    let commitRequested = false;
    const refuse = async (problems) => {
      const done = await store.refuse(paymentId, attemptId, problems);
      if (!done) return { status: 'IN_PROGRESS', reason: 'another attempt took the payment over' };
      if (commitRequested) await inform(payment.authorizationId, 'CANCELLED', 'refused by the bank\'s execution check');
      return { status: 'REFUSED', problems };
    };

    // CHECKING: nothing irreversible happens here; any failure holds the payment.
    let evidence; let chain; let decision;
    try {
      await hook('checking', context);
      const commit = await authCore.commitRequest(payment.authorizationId, payment.bankTransactionReference);
      if (commit.status !== 202) {
        if (commit.status >= 400 && commit.status < 500) return refuse([`Auth Core refused the commit request: HTTP ${commit.status} ${commit.json?.code ?? ''}`.trim()]);
        throw new Error(`Auth Core commit request: HTTP ${commit.status}`);
      }
      commitRequested = true;
      evidence = await authCore.evidence(payment.authorizationId);
      chain = await authCore.chain(terms.nexusId);
      const trust = await store.loadTrust(terms.nexusId);
      decision = bankExecutionDecision({
        evidence, chain, evidenceKeys: pinned, bankTrustKeys: trustKeys, registry: trust.entries,
        expected: { ...terms, authorizationId: payment.authorizationId }, expectedHead: trust.head ?? undefined,
      });
    } catch (error) {
      crash(error);
      await store.hold(paymentId, attemptId, error.message, ['CHECKING']).catch(() => undefined);
      return { status: 'HELD', reason: error.message };
    }
    if (!decision.allowed) return refuse(decision.problems);

    // CHECKING -> APPROVED: the revocation cut-off.
    let approval;
    try {
      await hook('beforeApprove', context);
      approval = await store.approveExecution(paymentId, attemptId, evidence, leaseMs);
    } catch (error) {
      crash(error);
      await store.hold(paymentId, attemptId, error.message, ['CHECKING']).catch(() => undefined);
      return { status: 'HELD', reason: error.message };
    }
    if (!approval.ok) return approval.lost ? { status: 'IN_PROGRESS', reason: approval.reason } : refuse([approval.reason]);

    // APPROVED -> SUBMITTED happens in the gateway, in the bank's database, after
    // its own check of the approval and before it calls the provider.
    let answer;
    try {
      await hook('approved', context);
      answer = await gateway.submit(paymentId, attemptId);
    } catch (error) {
      crash(error);
      // Not submitted if the approval can still be withdrawn: whichever of this
      // call and the gateway's bank.submit commits first wins.
      if (await store.hold(paymentId, attemptId, `not submitted: ${error.message}`, ['APPROVED']).catch(() => false)) {
        return { status: 'HELD', reason: error.message };
      }
      if (error instanceof GatewayRefusedError) return { status: 'IN_PROGRESS', reason: error.message };
      return mark('unknown', paymentId, attemptId, `gateway: ${error.message}`);
    }
    await hook('submitted', context);
    return settle(payment, answer, chain);
  }

  /** Checks a settled payment against the provider; a disagreement is recorded, never applied automatically. */
  async function audit(paymentId) {
    const execution = await store.execution(paymentId);
    if (!execution || !['EXECUTED', 'PROVIDER_FAILED'].includes(execution.state) || !caps.lookup) return { checked: false };
    const found = await gateway.lookup(paymentId);
    const expected = execution.state === 'EXECUTED' ? 'succeeded' : 'failed';
    if (found?.status === expected) return { checked: true, agrees: true };
    await store.addFinding(paymentId, execution.state, String(found?.status ?? 'unknown'), { providerReference: execution.providerReference });
    return { checked: true, agrees: false, providerStatus: found?.status ?? 'unknown' };
  }

  /** A reconciliation job: every payment whose outcome is open or whose attempt stopped. */
  async function reconcileDue() {
    const results = [];
    for (const paymentId of await store.dueForReconciliation()) results.push({ paymentId, ...(await execute(paymentId)) });
    return results;
  }

  return Object.freeze({ execute, audit, reconcileDue, capabilities: caps });
}
