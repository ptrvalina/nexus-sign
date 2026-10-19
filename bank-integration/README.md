# Bank integration: the execution boundary

This directory has two parts:

- the **contract** a bank backend implements so that no payment confirmed through NEXUS-SIGN reaches its payment system without the bank's own trust check;
- a **reference implementation** of that contract, tested against Auth Core on SoftHSM and PostgreSQL (`auth-core/test/integration/bank-execution-boundary.test.mjs`).

It is not a bank backend. This repository has no core banking system and no payment adapter. Integrating the boundary into a bank's real backend and payment system is the bank's work; until that is done, nothing here protects a real payment.

Why it is needed: a compromised Auth Core can report `VERIFIED`, `confirmed: true` and a 202 for a device key the bank never approved ([bank credential trust v1](../docs/protocol/bank-credential-trust-v1.md), `bank-trust-compromise.test.mjs`). Those answers are not a reason to execute anything.

## Files

| File | What |
|---|---|
| `executionBoundary.mjs` | `createExecutionBoundary(...)`, which exposes `execute(paymentId)` and nothing else; `guardPaymentAdapter(raw)` |
| `postgresTrustStore.mjs` | `createPostgresTrustStore(pool, { bankTrustKeys })`: the bank's trust registry and execution journal in the bank's PostgreSQL (`SCHEMA`, `migrate()`) |
| `authCoreClient.mjs` | `createAuthCoreClient({ baseUrl, accessToken, timeoutMs })`, `withTimeouts` |
| `index.mjs` | exports |

The boundary uses `auth-core/scripts/lib/bankTrust.mjs` (the decision) and `auth-core/scripts/lib/evidence.mjs` (the verifier). Neither imports Auth Core code. No runtime dependency: the `pg` pool is passed in.

## Rules for the bank backend

1. **One entry point.** Every path that can move money for a NEXUS-SIGN payment calls `boundary.execute(paymentId)`:
   - the operator's "execute" button;
   - the API;
   - a handler for `authorization.verified` or `authorization.bank_transaction.commit_requested` webhooks, which may only enqueue `execute`;
   - retry and recovery jobs;
   - administrative tools.

   No other code calls the payment system for these payments.
2. **The adapter only inside.** Wrap the payment system adapter with `guardPaymentAdapter(raw)` and give `issuePermit` to the boundary only. `adapter.execute` refuses any order without a one-time permit issued for exactly that order. Keep the raw adapter out of reach of other modules; the guard cannot enforce that across process or code boundaries the bank does not control.
3. **The bank's own data decides.**
   - **Payment and terms:** `createPayment` records `{ authorizationId, nexusId, transactionReference, operationType, amountMinor, currency, beneficiary }` when the bank creates the authorization at Auth Core.
   - **Statements:** approvals and revocations signed with the bank's trust key, in its own store (`approve`, `revoke`). They are never imported from an Auth Core export.
   - **Pinned evidence keys and bank trust keys:** configuration, never taken from an Auth Core answer.
   - **Kept heads:** `keepHead` from `evidence.appended`, `approve(..., { head })` at approval, and the boundary itself after each execution. Heads only move forward.
4. **Auth Core's answers are data.** The commit request (202) is a precondition. `VERIFIED` and `confirmed` are not read at all.

## One attempt of `execute(paymentId)`

| Step | On failure |
|---|---|
| 1. Claim in the journal (`bank_executions`, one row per payment, lease) | trust store unavailable: `HELD` |
| 2. `bank-commit-request` at Auth Core | 4xx: `REFUSED` (final); network error, 5xx or timeout: `HELD` |
| 3. Evidence and chain from Auth Core; the bank's statements and kept head; `bankExecutionDecision` | refused: `REFUSED` (final), `CANCELLED` reported to Auth Core; any error or timeout: `HELD` |
| 4. Final check in one transaction: the credential's trust row is read `FOR SHARE`, must be `APPROVED` for this customer, and the journal moves `CLAIMED → EXECUTING` only if this attempt still holds the claim | revoked meanwhile: `REFUSED`; claim lost: `IN_PROGRESS` |
| 5. Payment system: `execute(permit, order)`, with the payment's `bankTransactionReference` as idempotency key | error or timeout: `OUTCOME_UNKNOWN` |
| 6. `EXECUTED` and the kept head moved forward in one transaction; `COMMITTED` reported to Auth Core | journal not updated: stays `EXECUTING`; the next attempt reconciles |

A repeated `execute` returns:

| Journal state | Answer |
|---|---|
| `EXECUTED` | `EXECUTED` (`repeated`), with no call to the payment system |
| `REFUSED` | `REFUSED` |
| `CLAIMED` with a live lease, or `EXECUTING` | `IN_PROGRESS` |
| `HELD` | a new attempt |
| `OUTCOME_UNKNOWN`, or an expired `EXECUTING` | `lookup(idempotencyKey)` at the payment system: `EXECUTED` is recorded; not found becomes `REVIEW` for a person. Never a second `execute`. |

The journal's final states are protected by a trigger, a revocation is final, a credential is bound to one customer, and statements are append-only.

## What is atomic, and what is not

- **Atomic in the bank's database:**
  - the claim;
  - the final check together with the move to `EXECUTING`;
  - a revocation, which serializes with the final check on the credential row;
  - `EXECUTED` together with the head.
- **Not atomic across systems:**
  - The bank's database and the payment system cannot be one transaction. The contract for this:
    - an idempotency key per payment, honoured by the payment system;
    - `OUTCOME_UNKNOWN` when the call fails;
    - reconciliation by `lookup`;
    - `REVIEW` when neither side knows.
  - A revocation that commits after a payment passed its final check does not stop that payment. `revoke()` returns the payments in flight so the bank can stop or reverse them. They are ordered before the revocation.
  - The report to Auth Core (`COMMITTED`, `CANCELLED`) is best effort. Auth Core's record of it is not the bank's.

## Payment system adapter contract

```text
execute(order) -> { providerReference }     order = { idempotencyKey, reference, operationType,
                                                      amountMinor, currency, beneficiary }
lookup(idempotencyKey) -> { status: 'EXECUTED', providerReference } | { status: 'NOT_FOUND' }
```

`execute` must be idempotent by `idempotencyKey`: a second call with the same key never moves money twice. `lookup` must answer for any key `execute` may have received.

## External blocker

The boundary is a contract plus a reference implementation. It is integrated with:

- no real bank backend;
- no core banking or payment system;
- no bank HSM for the trust key.

Integration, the bank's own tests of every execution path it has, and operation of the registry, keys and heads are required before it protects anything.
