# Payment state machine on the bank's side

Status: 2.0.0, phase 14. Implemented in `bank-integration/` (`schema.mjs`, `trustStore.mjs`, `executionBoundary.mjs`, `paymentGateway.mjs`). The database enforces the transitions: a trigger checks every update against `bank_allowed_transitions` and refuses everything else, for every role including the owner. Tests: `auth-core/test/integration/bank-execution-processes.test.mjs` (EP) and `bank-execution-boundary.test.mjs` (EB).

## Four facts that are kept apart

| Fact | Where it is recorded | Who establishes it |
|---|---|---|
| The customer confirmed the terms | Auth Core: authorization `VERIFIED`, sealed evidence | the device and Auth Core |
| The bank allows the payment | bank journal: `APPROVED` | the bank's execution boundary (decision and final check) |
| The command was sent | bank journal: `SUBMITTED` (written by the gateway before it calls the provider) | the payment gateway |
| Money moved | bank journal: `EXECUTED`, only from the provider's answer or lookup | the payment provider |

Auth Core's `bank_transaction_state = COMMITTED` is what the bank reported after `EXECUTED`; it is not evidence of a transfer. Auth Core's `COMMIT_REQUESTED` (the 202) is only a precondition of `CHECKING`.

## States

Payment (`bank_payments.status`):

| State | Meaning |
|---|---|
| `CREATED` | the bank recorded the payment and its terms (immutable) before asking Auth Core |
| `AWAITING_AUTHORIZATION` | Auth Core created the authorization; its ID is attached once. The customer confirms on the device. Execution is possible only from here. |

Execution (`bank_executions.state`, one row per payment):

| State | Meaning | Final |
|---|---|---|
| `CHECKING` | one attempt (attempt ID, lease) runs the commit request, the evidence and the bank's decision | |
| `HELD` | stopped before approval: an error, a timeout, an unavailable service, an approval withdrawn | |
| `APPROVED` | **revocation cut-off.** The bank's decision and the final check under the credential row's lock passed. The approval binds the attempt ID, the credential and the hash of the order. | |
| `SUBMITTED` | the gateway recorded the command for this attempt and then called the provider | |
| `PENDING_PROVIDER` | the provider accepted it and has not settled it | |
| `OUTCOME_UNKNOWN` | no usable answer (timeout, lost response, crash, nonsense) | |
| `RECONCILING` | one attempt asks the provider (lookup) | |
| `EXECUTED` | the provider confirmed it | yes |
| `PROVIDER_FAILED` | the provider confirmed it failed; no money moved | yes |
| `REFUSED` | the bank refused it (decision, revocation, Auth Core refused the commit request) | yes |
| `REVIEW` | a person settles it with the provider, leaving `EXECUTED` or `PROVIDER_FAILED` with name and note | |

## Transitions

| From → to | Preconditions | Changes in the bank's DB | External calls | On failure | Repeat / redelivery | After a restart |
|---|---|---|---|---|---|---|
| — → `CREATED` | bank's own payment request | insert payment with terms and reference (unique) | — | nothing recorded | same reference: refused (unique) | — |
| `CREATED` → `AWAITING_AUTHORIZATION` | Auth Core answered 201 | attach the authorization ID (once, unique) | create the authorization at Auth Core (before) | stays `CREATED`; the bank retries with its idempotency key | second attach refused | — |
| — / `HELD` / expired `CHECKING` → `CHECKING` | payment `AWAITING_AUTHORIZATION`; no live lease | new attempt ID, lease (one transaction with the payment row lock) | — | trust store down: nothing written, answer `HELD` | a live lease answers `IN_PROGRESS` | lease expires; the next call takes it over |
| `CHECKING` → `REFUSED` | the decision refuses, or Auth Core refuses the commit request (4xx) | state, problems | `bank-commit-result CANCELLED` (best effort) | stays `CHECKING` until the lease ends | final: the same answer, nothing called | — |
| `CHECKING` → `HELD` | an error or a timeout in the commit request, the evidence, the chain, the registry | state, reason | — | — | next call: `CHECKING` again, full check | — |
| `CHECKING` → `APPROVED` | decision allowed; **in one transaction:** the credential's trust row `FOR SHARE` is `APPROVED` for this customer; this attempt still holds a live lease | state, credential, order hash, lease | `bank-commit-request` and the evidence calls (before) | revoked: `REFUSED`; lease lost: `IN_PROGRESS` | a live lease answers `IN_PROGRESS` | expired `APPROVED`: the next attempt moves it to `HELD` if the gateway has not taken it (one conditional update decides the race), then `CHECKING` |
| `APPROVED` → `SUBMITTED` | **only `bank_submit`** (the gateway's role, `SECURITY DEFINER`): `APPROVED`, same attempt ID, lease live | state, submissions + 1; returns the stored order and the bound hash | — | refused: nothing sent | a second submission of the same approval is refused (no longer `APPROVED`) | — |
| `APPROVED` → `HELD` | the gateway did not take it (unreachable, refused) and the conditional update wins | state, reason | — | — | next call: full check | — |
| `SUBMITTED` → `EXECUTED` / `PROVIDER_FAILED` / `PENDING_PROVIDER` | the provider's answer to the gateway | state, provider reference; with `EXECUTED` the kept head moves forward in the same transaction | provider submit (by the gateway, after `SUBMITTED` committed); then `bank-commit-result COMMITTED` or `FAILED` (best effort) | — | final states answer `repeated` | — |
| `SUBMITTED` → `OUTCOME_UNKNOWN` | no usable answer (timeout, lost, nonsense, gateway gone) | state, reason | — | — | next call: `RECONCILING` | — |
| `SUBMITTED` → `REVIEW` | the stored order does not match the hash bound at approval (database changed) | state | none: nothing was sent | — | person | — |
| expired `SUBMITTED`, `PENDING_PROVIDER`, `OUTCOME_UNKNOWN` → `RECONCILING` | an attempt takes it (new attempt ID, lease) | state, attempt, lease | — | — | a live `RECONCILING` lease answers `IN_PROGRESS` | lease expires; taken over |
| `RECONCILING` → `EXECUTED` / `PROVIDER_FAILED` / `PENDING_PROVIDER` | lookup by the operation ID: succeeded, failed, pending | state | provider lookup (through the gateway) | lookup fails: `OUTCOME_UNKNOWN` | — | — |
| `RECONCILING` → `SUBMITTED` | lookup `not_found` **and** the provider contract declares idempotent submission: `bank_resubmit`, same operation ID | state, submissions + 1 | provider submit, same operation ID | as for `SUBMITTED` | — | — |
| `RECONCILING` → `REVIEW` | `not_found` without idempotent submission, or a provider without lookup | state, reason | — | — | stays `REVIEW` | — |
| `REVIEW` → `EXECUTED` / `PROVIDER_FAILED` | a person, with the provider's statement | state, operator, note | — | — | — | — |

Every transition writes a row to `bank_execution_transitions` (append-only) with the database role that made it: the gateway's role appears only on `SUBMITTED`.

Forbidden, among others (EP «forbidden transitions»):

- anything out of a final state;
- `CHECKING` → `SUBMITTED`; `APPROVED` → `EXECUTED`; `HELD` → `APPROVED`; `OUTCOME_UNKNOWN` → `EXECUTED` without reconciliation;
- deleting a payment, an execution or a log row;
- changing terms, the reference or the approved order;
- moving the kept head back.

## Never sending twice

A payment is sent at most once per approval, because `bank_submit` moves `APPROVED` to `SUBMITTED` under a row lock. It is sent again only from `RECONCILING`, after a lookup found nothing, and only when the provider's contract declares idempotent submission by operation ID. An unknown outcome is never resolved by sending again blindly. Without lookup in the contract it goes to `REVIEW`; without idempotent submission, a `not_found` goes to `REVIEW`. **Exactly-once execution therefore depends on the provider's contract** (idempotency by operation ID and an authoritative lookup). The bank database alone cannot provide it.

## Revocation cut-off

The decision to revoke is fixed at `CHECKING → APPROVED`. A revocation that commits before the approval transaction reads the trust row refuses the payment. One that comes after does not stop it: `revoke()` returns the payment as in flight (`APPROVED` or later), and the bank stops or reverses it through the provider if it can. A revocation does not cancel payments in flight instantly, and nothing here claims that it does (EP «revocation at each step»).
