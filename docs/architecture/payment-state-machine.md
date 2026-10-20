# Payment state machine on the bank's side

Status: 2.0.0, phase 15. Implemented in `bank-integration/` (`schema.mjs`, `trustStore.mjs`, `executionBoundary.mjs`, `paymentGateway.mjs`, `registry.mjs`). Tests: `auth-core/test/integration/bank-execution-processes.test.mjs` (EP), `bank-execution-boundary.test.mjs` (EB) and `bank-db-authorization.test.mjs` (DA).

Since phase 15 the database is in its own schema `bank`. No application role can write a table. Every transition is made by one `SECURITY DEFINER` function, and the function names itself to the trigger (`bank.via`). The trigger accepts a change only if the triple (from, to, function) is in `bank.allowed_transitions`, for every role including the owner. Roles and rights: [bank database authorization](../security/bank-database-authorization.md).

## Four facts that are kept apart

| Fact | Where it is recorded | Who establishes it |
|---|---|---|
| The customer confirmed the terms | Auth Core: authorization `VERIFIED`, sealed evidence | the device and Auth Core |
| The bank allows the payment | bank journal: `APPROVED`, with the evidence it rests on | the bank's execution boundary (decision and final check in `bank.approve`) |
| The command was sent | bank journal: `SUBMITTED` (written by the gateway before it calls the provider, after its own check of the approval) | the payment gateway |
| Money moved | bank journal: `EXECUTED`, only from the provider's answer or lookup, recorded by the gateway | the payment provider |

Auth Core's `bank_transaction_state = COMMITTED` is what the bank reported after `EXECUTED`; it is not evidence of a transfer. Auth Core's `COMMIT_REQUESTED` (the 202) is only a precondition of `CHECKING`.

## States

Payment (`bank.payments.status`):

| State | Meaning |
|---|---|
| `CREATED` | the bank recorded the payment and its terms (immutable) before asking Auth Core |
| `AWAITING_AUTHORIZATION` | Auth Core created the authorization; its ID is attached once. The customer confirms on the device. Execution is possible only from here. |

Execution (`bank.executions.state`, one row per payment):

| State | Meaning | Final |
|---|---|---|
| `CHECKING` | one attempt (attempt ID, lease) runs the commit request, the evidence and the bank's decision | |
| `HELD` | stopped before approval: an error, a timeout, an unavailable service, an approval withdrawn | |
| `APPROVED` | **revocation cut-off.** `bank.approve` passed. The approval binds the attempt ID, the credential (taken from the evidence), the evidence itself, the registry as it stood (`approval_registry_id`), and the order hash computed by the database. | |
| `SUBMITTED` | the gateway checked the approval, recorded the command for this attempt, and then called the provider | |
| `PENDING_PROVIDER` | the provider accepted it and has not settled it | |
| `OUTCOME_UNKNOWN` | no usable answer (timeout, lost response, crash, nonsense) | |
| `RECONCILING` | one attempt asks the provider (lookup) | |
| `EXECUTED` | the provider confirmed it | yes |
| `PROVIDER_FAILED` | the provider confirmed it failed; no money moved | yes |
| `REFUSED` | the bank refused it (decision, revocation, Auth Core refused the commit request) | yes |
| `REVIEW` | a person settles it with the provider, leaving `EXECUTED` or `PROVIDER_FAILED`; the database records the person's login | |

## Transitions

The column "function" is the only function that may make the transition (`bank.allowed_transitions`); "role" is the only role that may execute it.

| From → to | Function (role) | Preconditions checked in the database | Changes | External calls | Repeat, restart |
|---|---|---|---|---|---|
| — → `CREATED` | `create_payment` (boundary) | identifier, reference (unique), terms with customer, reference, amount, currency, beneficiary | payment row | — | same reference or authorization: refused (unique) |
| `CREATED` → `AWAITING_AUTHORIZATION` | `attach_authorization` (boundary) | `CREATED` | authorization ID, once | create the authorization at Auth Core (before) | second attach: false |
| — / `HELD` / expired `CHECKING` → `CHECKING` | `claim` (boundary) | payment `AWAITING_AUTHORIZATION`, no live lease, lease 100 ms … 1 h | new attempt ID, lease (payment row locked) | — | live lease: `IN_PROGRESS` |
| `CHECKING` → `REFUSED` | `refuse` (boundary) | same attempt, `CHECKING` | problems | `bank-commit-result CANCELLED` (best effort) | final |
| `CHECKING` → `HELD` | `hold` (boundary) | same attempt | reason | — | next call: full check |
| `CHECKING` → `APPROVED` | `approve` (boundary) | same attempt, live lease, lease within limits; the evidence names this payment's authorization, customer, reference, signed terms and a credential; that credential's registry row (`FOR SHARE`) is `APPROVED` for this customer with a stored approval statement | credential, evidence, registry position, order hash, lease | `bank-commit-request` and the evidence calls (before) | second call: lost (`ok: false`); expired `APPROVED`: the next claim withdraws it (`HELD`) unless the gateway took it |
| `APPROVED` → `HELD` | `hold` (boundary), or `claim` withdrawing an expired approval | same attempt, still `APPROVED` (one row lock decides the race with the gateway) | reason | — | next call: full check |
| `APPROVED` → `REVIEW` | `gateway_refuse` (gateway) | the order no longer has the approved hash, or the bank's decision on the stored evidence fails at the gateway | reason | none: nothing was sent | person |
| `APPROVED` → `SUBMITTED` | `submit` (gateway) | `APPROVED`, same attempt, live lease, the order still has the approved hash | submissions + 1; returns the order | provider submit (after the commit) | second call: refused |
| `SUBMITTED` → `EXECUTED` / `PROVIDER_FAILED` / `PENDING_PROVIDER` / `OUTCOME_UNKNOWN` | `report` (gateway) | same attempt, `SUBMITTED` | state, provider reference, reason | `bank-commit-result COMMITTED` or `FAILED` (boundary, best effort); kept head forward (boundary) | other attempt or final state: false |
| `SUBMITTED` → `OUTCOME_UNKNOWN` | `mark_unknown` (boundary) | same attempt; the boundary lost the gateway after it took the approval | reason | — | next call: `RECONCILING` |
| expired `SUBMITTED`, `PENDING_PROVIDER`, `OUTCOME_UNKNOWN`, expired `RECONCILING` → `RECONCILING` | `claim` (boundary) | no live lease | new attempt ID, lease | — | live lease: `IN_PROGRESS` |
| `RECONCILING` → `EXECUTED` / `PROVIDER_FAILED` / `PENDING_PROVIDER` / `OUTCOME_UNKNOWN` | `report` (gateway) | same attempt | state | provider lookup by the gateway | — |
| `RECONCILING` → `OUTCOME_UNKNOWN` | `mark_unknown` (boundary) | same attempt; the gateway unreachable | reason | — | — |
| `RECONCILING` → `SUBMITTED` | `resubmit` (gateway) | same attempt, live lease, submitted before, the order still has the approved hash; the boundary asks only after `not_found` with idempotent submission in the provider contract | submissions + 1 | provider submit, same operation ID | — |
| `RECONCILING` → `REVIEW` | `mark_review` (boundary) or `gateway_refuse` (gateway) | same attempt; `not_found` without idempotent submission, a provider without lookup, or the approval's basis failed at the gateway | reason | — | stays `REVIEW` |
| `REVIEW` → `EXECUTED` / `PROVIDER_FAILED` | `resolve_review` (operator) | a note | state, `resolved_by = session_user`, note | — | — |

Every transition writes one row to `bank.execution_transitions` in the same trigger: from, to, attempt, the function (`via`) and the login role (`session_user`). The log is append-only, also for the owner (`UPDATE`, `DELETE`, `TRUNCATE` raise). No role has `INSERT` on it.

Forbidden, among others (EP «forbidden transitions», DA):

- anything out of a final state;
- `CHECKING` → `SUBMITTED`; `CHECKING` → `APPROVED` by anything but `bank.approve`; `APPROVED` → `EXECUTED`; `HELD` → `APPROVED`; `OUTCOME_UNKNOWN` → `EXECUTED` without reconciliation;
- an outcome recorded by the boundary (`report` is the gateway's);
- deleting or truncating a payment, an execution, a statement or a log row;
- changing terms, the reference, the approved order, credential, evidence or registry position;
- moving the kept head back.

## Never sending twice

A payment is sent at most once per approval, because `bank.submit` moves `APPROVED` to `SUBMITTED` under a row lock. It is sent again only from `RECONCILING`, after a lookup found nothing, and only when the provider's contract declares idempotent submission by operation ID. An unknown outcome is never resolved by sending again blindly. Without lookup in the contract it goes to `REVIEW`; without idempotent submission, a `not_found` goes to `REVIEW`. **Exactly-once execution therefore depends on the provider's contract** (idempotency by operation ID and an authoritative lookup). The bank database alone cannot provide it.

## Revocation cut-off

The decision to revoke is fixed at `CHECKING → APPROVED`. `bank.approve` reads the credential's row `FOR SHARE`, and `bank.revoke_credential` takes it `FOR UPDATE`, so one waits for the other (DA «serialized»).

- A revocation that commits first refuses the payment.
- One that comes after does not stop it. `revoke()` returns the payment as in flight (`APPROVED` or later), and the bank stops or reverses it through the provider if it can.

The gateway checks the approval against the registry **as it stood at the approval** (statements up to `approval_registry_id`; statements are append-only). A later revocation therefore neither stops the payment at the gateway nor turns it into `REVIEW`; the cut-off stays where it is documented. A revocation does not cancel payments in flight instantly, and nothing here claims that it does (EP «revocation at each step»).

## Crashes and who records what

- The gateway records the provider's answer itself (`bank.report`), in its own process. A crash of the boundary after the submission loses nothing (EP «crash at each transition», step `submitted`: the payment is already `EXECUTED`).
- The kept chain head moves forward after `EXECUTED`, in a separate call by the boundary. It is no longer in one transaction with `EXECUTED` (phase 14 did that). If the boundary stops between the two, the head lags by one confirmation, and the next decision checks against the older head. See R-27.
