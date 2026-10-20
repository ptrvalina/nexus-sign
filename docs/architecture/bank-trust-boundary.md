# Bank trust boundary and execution boundary

Status: 2.0.0, phase 13; execution path updated in phase 14 (gateway in its own process with its own database role, [payment state machine](payment-state-machine.md)) and phase 15 (no role writes a table; the gateway checks the approval again: [bank database authorization](../security/bank-database-authorization.md)). Protocol: [bank credential trust v1](../protocol/bank-credential-trust-v1.md). Contract and reference implementation: [`bank-integration/`](../../bank-integration/README.md).

## Trust boundary

```text
            customer                                   bank (trusted for execution)
  ┌──────────────────────────┐             ┌──────────────────────────────────────────────┐
  │ device: signing key       │  credential │ bank app backend                              │
  │ bank app + SDK            │──── ID + ──▶│  approves the key (bank trust key, own HSM)   │
  │ signingKeyFingerprint()   │ fingerprint │                                               │
  └────────────┬─────────────┘             │ trust registry (own DB): statements,          │
               │ signs                     │  credential state, kept heads, payments,      │
               ▼                           │  execution journal                            │
  ┌──────────────────────────┐  evidence,  │ pinned evidence public keys (key ceremony)    │
  │ Auth Core  (NOT trusted   │  chain, 202 │                                               │
  │ for execution: may be     │────────────▶│ EXECUTION BOUNDARY  execute(paymentId)        │
  │ compromised)              │◀────────────│  claim → commit request → decision →          │
  │ HSM evidence key          │ commit req. │  final check → APPROVED → gateway → provider  │
  └──────────────────────────┘  and result │                      │                        │
                                           │                      ▼                        │
                                           │ payment system adapter (idempotent by key)    │
                                           └──────────────────────────────────────────────┘
```

Auth Core is trusted to run the confirmation protocol, not to decide execution. Everything it returns is checked against data it cannot change: the bank's statements, pinned keys, kept heads, and the terms the bank recorded.

## Lifecycle of a device key at the bank

| Event | Auth Core | Bank registry |
|---|---|---|
| Enrolment (`bootstrap`) | credential `ACTIVE`, `CREDENTIAL_ENROLLED` sealed | The app reports `credentialId` and its fingerprint. The bank verifies the enrolment record with its pinned keys, compares fingerprints, signs an approval, and records the head (`approve(entry, { head })`). The credential becomes `APPROVED`, bound to this customer for good. |
| Replacement (bank-issued replacement token) | old `REVOKED`, new `ACTIVE` | new credential approved; old one revoked (final) |
| Recovery (bank-opened session) | all earlier credentials `REVOKED`, new `ACTIVE` | new credential approved; all earlier ones revoked |
| Lost device, closure | revoke via API | revocation first (final), then the API call. `revoke()` returns payments already past their final check. |
| Enrolment Auth Core made alone (compromise) | `ACTIVE` or anything | absent, so every payment confirmed with it is refused. With the chain export, its enrolment record is reported even when it is not used. |
| Key substituted by Auth Core | same `credentialId`, new key and record | the fingerprint differs from the approved one, so refused |

A credential ID is never approved again after a revocation, and never for a second customer.

## Paths to execution in this repository (phase 13 inventory)

| Path | Where | What is checked today | Risk of bypass | Change |
|---|---|---|---|---|
| Commit request (`POST /v1/authorizations/{id}/bank-commit-request`) | `auth-core` `bankTransactionService.requestCommit` | Auth Core's own checks: state, standing, sealed evidence with the enrolment key, under the row lock | A compromised Auth Core answers 202 for anything | Precondition only; the boundary never executes on it (test: unapproved key with 202, refused) |
| Commit result (`bank-commit-result`) | `finalizeBankTransaction` | records what the bank reports | Moves no money | The boundary reports `COMMITTED` after execution and `CANCELLED` after a refusal |
| `GET /v1/authorizations/{id}` (`confirmed`) | `confirmationView` | evidence check at read time | A bank executing on `confirmed: true` | The boundary does not read it |
| Webhooks to the bank (`authorization.verified`, `…commit_requested`) | `webhookService` | HMAC | A handler that executes on a webhook | Rule: a handler may only enqueue `execute` (bank-side; not in this repository) |
| Admin console | `routes/admin.ts` | — | Has no execution or commit function | none |
| Demo bank | `demo/bank-backend` | shows Auth Core's status | Executes nothing | A note on its page that the status is no reason to execute |
| End-to-end smoke test | `auth-core/scripts/e2e-smoke.mjs` | — | A test client that reports `COMMITTED` without executing anything | none: not an execution path |
| Sandbox commit | `sandbox/server/main.py` `commit()` | its own simulated verification | A self-contained simulator: it does not use Auth Core, moves no money, synthetic data only | none; outside this trust model |
| `bank-execution-check.mjs` | `auth-core/scripts` | the full decision | Its exit code can be ignored; it is not an integration | The boundary uses the library, not the CLI |
| **A bank's real backend: operator actions, API, jobs, retries, admin tools, payment adapter** | **not in this repository** | — | **unknown** | **External: integrate `execute()` and the adapter guard; bank-side tests of every such path** |

No other path in this repository moves a payment or changes a bank transaction state.

## Atomicity and concurrency

What is atomic, what is not, and how unknown outcomes are settled is in the [bank integration contract](../../bank-integration/README.md#what-is-atomic-and-what-is-not). In short:

- **One attempt at a time per payment.** A claim with a lease and an attempt ID. An attempt whose lease was taken over cannot move to `APPROVED`, and the gateway submits only for the attempt that holds `APPROVED`.
- **The approval is the database's.** `bank.approve` takes the credential from the evidence, binds the evidence to the payment and computes the order hash; the gateway checks the stored evidence again before it submits.
- **Revocation and execution** serialize on the credential's trust row. A payment approved after a revocation is refused; one already `APPROVED` or later is reported by `revoke()`.
- **The kept head** moves forward after `EXECUTED` (since phase 15 a separate call by the boundary; R-27); it only moves forward.
- **The payment system** is not part of any transaction. It is protected by an idempotency key, `OUTCOME_UNKNOWN`, reconciliation by lookup, and `REVIEW`.
