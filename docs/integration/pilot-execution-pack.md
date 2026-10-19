# Pilot execution pack: what the pilot bank integrates, operates and tests

Status: 2.0.0, phase 14. For the pilot bank's architects, payment operations and security. The reference implementation is in `bank-integration/`. It is **not integrated** with any bank. Nothing below is proven for a real bank backend or a real payment provider until the tests in section 10 have run in the bank's infrastructure.

## 1. Contract of the execution boundary

[`bank-integration/README.md`](../../bank-integration/README.md): components and their authority, rules, API, the provider contract. States and transitions: [payment state machine](../architecture/payment-state-machine.md).

## 2. Sequence

```text
bank backend            bank DB (registry, journal)     Auth Core            gateway (own process)      provider
 │ createPayment ───────────▶ CREATED
 │ create authorization ────────────────────────────────▶ 201
 │ attachAuthorization ─────▶ AWAITING_AUTHORIZATION
 │                                                       device confirms: VERIFIED
 │ execute(paymentId)
 │  claim ──────────────────▶ CHECKING (attempt, lease)
 │  bank-commit-request ────────────────────────────────▶ 202 (precondition only)
 │  evidence, chain ────────────────────────────────────▶ export
 │  statements, kept head ◀──
 │  bankExecutionDecision (pinned keys, approvals, revocations, terms, head)
 │  approveExecution ───────▶ APPROVED  ◀── revocation cut-off (trust row FOR SHARE)
 │  submit(paymentId, attempt) ── mutual TLS ─────────────────────────────▶ bank_submit: SUBMITTED
 │                                                                         │ stored order, hash check
 │                                                                         │ POST /payments ────────▶ succeeded | failed | pending
 │  answer ◀────────────────────────────────────────────────────────────── │                          (or nothing)
 │  record ─────────────────▶ EXECUTED | PROVIDER_FAILED | PENDING_PROVIDER | OUTCOME_UNKNOWN
 │  bank-commit-result ─────────────────────────────────▶ COMMITTED | FAILED (informational)
 │ reconcileDue (job)
 │  claim ──────────────────▶ RECONCILING
 │  lookup ── mutual TLS ───────────────────────────────────────────────────▶ GET /payments/{id} ──────▶ status | 404
 │  record ─────────────────▶ final | PENDING_PROVIDER | REVIEW (or SUBMITTED again, only with idempotent submission)
```

## 3. Threat model (summary)

The full table is in the [offline confirmation threat model](../security/offline-confirmation-threat-model.md), phases 12–14.

| Adversary | Can | Cannot (shown by tests) |
|---|---|---|
| Fully compromised Auth Core | enrol or substitute device keys and seal them; report `VERIFIED`, `confirmed`, 202, `COMMITTED`; forge webhooks; withhold, rewrite or re-seal evidence; refuse service | make the boundary approve a key the bank did not approve, other terms, unpinned evidence or a changed head; reach the gateway (no client certificate) or the bank's database (no credentials) |
| Second backend instance, or a module bypassing `execute()` | call the gateway with the boundary's certificate | send anything not `APPROVED` for that attempt; change the order sent; send an approval twice |
| Holder of the gateway's database role | call `bank_submit` | read or write tables, approve, change orders |
| Holder of the boundary's database role | approve executions (it is the trusted decision point) | set `SUBMITTED`; leave final states; change terms or an approved order; move heads back; delete history |
| Network faults, crashes | lose answers, kill processes | cause a second send without the provider's idempotency |

**Not covered:**

- a compromised bank backend: the boundary's role and certificate, the trust key, the registry;
- the schema owner's credentials;
- a compromised payment provider;
- denial of service by Auth Core;
- a compromised customer device or bank app;
- device attestation checked only by Auth Core.

## 4. Bank database requirements

- A database separate from Auth Core's, with no network path from Auth Core.
- Three roles:
  - **owner**: migrations only, never used by a service;
  - **boundary**: the backend;
  - **gateway**: the gateway process.

  `installSchema` grants exactly what the components need. Verify with the bank's DBA that nothing more is granted (`\dp`).
- PostgreSQL: the reference was run on 16.13 only; other versions are untested.
- Triggers and functions installed by migration and reviewed. Disabling a trigger needs the owner role; monitor for `ALTER TABLE … DISABLE TRIGGER`.
- Backups taken of the registry, the journal and the transition log together; restore drills that check the forward-only heads afterwards.
- Time from the database server (`now()`) drives leases. The lease is longer than the slowest normal attempt, and shorter than the time the bank accepts for a stuck payment before reconciliation.

## 5. HSM and trust keys

| Key | Requirement |
|---|---|
| Bank trust key (ECDSA P-256) | generated and used in the bank's HSM; signs approvals and revocations; dual control; rotation by adding the new public key to the configuration first |
| Pinned evidence public keys | from the key ceremony record and every rotation; configuration under change control |
| Gateway server key and the boundary's client key | the bank's PKI; short-lived certificates; allow-list of client names in the gateway configuration |
| Provider credentials | only in the gateway's process |

## 6. Adapter and provider requirements

The provider contract must state, and the bank must test:

1. A **stable unique operation ID** per payment, which the gateway sends as `operationId`: the bank transaction reference.
2. **Idempotent submission:** a second submission with the same operation ID never moves money again, also after a timeout and also when the first is still being processed. Set `idempotentSubmit: true` only if the contract says so.
3. **Authoritative lookup** by operation ID, with `succeeded`, `failed`, `pending` and a definite `not found`. Set `lookup: true` only if the contract says so, and only if `not found` is final once a stated time has passed after submission.
4. Statuses mapped exactly: anything not `succeeded`, `failed` or `pending` is unknown to the boundary.
5. A statement or report the operations team can use for manual review.

**If the provider guarantees neither idempotency nor lookup, automatic exactly-once execution is impossible in that contract.** The boundary then holds unknown outcomes for a person (`REVIEW`) and never resends.

## 7. Handling an unknown outcome

| State | Automatic | People |
|---|---|---|
| `OUTCOME_UNKNOWN` | `reconcileDue()` on a schedule. With lookup: the provider's answer settles it. `not_found` with idempotent submission: resent with the same operation ID. `not_found` without it: `REVIEW`. Without lookup: `REVIEW`. | alert if older than the bank's threshold |
| `PENDING_PROVIDER` | looked up on every run until settled | alert after the provider's settlement time |
| `SUBMITTED` with an expired lease (crash) | as `OUTCOME_UNKNOWN` | — |
| `HELD` | the next `execute` runs the full check again | alert on repeated holds (an unavailable service) |
| `REVIEW` | nothing | section 8 |

## 8. Reconciliation and manual review

1. **Daily:** `audit(paymentId)` for every `EXECUTED` and `PROVIDER_FAILED` of the day, against the provider's lookup or statement. Every disagreement is a finding (`bank_reconciliation_findings`); the final state is not changed automatically.
2. **For each `REVIEW`:**
   - an operator obtains the provider's statement for the operation ID;
   - decides `succeeded` or `failed`;
   - records it with `resolveReview(paymentId, outcome, { operator, note })`, with a second person approving under the bank's four-eyes rule.

   Do not resend a `REVIEW` payment: if it must be paid, the bank creates a new payment and authorization.
3. **For each finding:**
   - settle it with the provider (reversal, claim, correction) under the bank's procedures;
   - keep the finding;
   - report it as an incident if the cause is not explained.
4. **For each `REFUSED` with an approval, key, seal or head problem:** a security incident (a possible Auth Core compromise).

## 9. Responsibility matrix

R: responsible, A: accountable, C: consulted, I: informed.

| Activity | Bank | NEXUS-SIGN (vendor) | Payment provider |
|---|---|---|---|
| Customer confirmation protocol, evidence, Auth Core operation | I | R/A | — |
| Device key approval (fingerprint from the bank's app), revocation | R/A | C | — |
| Execution boundary integration, all execution paths through `execute()` | R/A | C (reference implementation, contract) | — |
| Gateway operation, provider credentials, mutual TLS PKI | R/A | C | C |
| Idempotent submission and lookup by operation ID | A | I | R |
| Reconciliation, review, findings | R/A | I | C |
| Trust key in the bank HSM; pinned keys; kept heads | R/A | C | — |
| Evidence key ceremony and rotation records | C | R/A | — |
| Incident response for a suspected Auth Core compromise | R/A | R (Auth Core side) | I |

## 10. Mandatory tests in the pilot bank's infrastructure

Each test is passed only with a record of the run (who, when, environment, result).

1. Every execution path in the bank's backend goes through `execute()`: inventory, code review and a test per path (operator, API, job, webhook, admin tool).
2. The gateway runs in its own process with its role; a direct call:
   - without a client certificate fails;
   - with another service's certificate fails;
   - with the boundary's certificate but without `APPROVED` fails;
   - for another attempt fails.
3. The database grants (`\dp`) match `installSchema`. The boundary role cannot set `SUBMITTED`; the gateway role cannot read tables.
4. With the real provider (test environment):
   - succeeded;
   - failed;
   - pending, then settled;
   - timeout after the provider executed;
   - lost response;
   - gateway killed after the provider executed;
   - resubmission with the same operation ID (money moved once);
   - lookup of every state;
   - `not found` within and after the provider's stated time.
5. Revocation: before the approval (refused); after it (reported as in flight; the bank's stop or reversal procedure exercised).
6. Two or more backend instances, and the reconciliation job, against one payment: one execution.
7. Crash of the backend at each transition; the next run finishes with one execution.
8. Compromised Auth Core cases, as in `bank-trust-compromise.test.mjs`:
   - an unapproved key;
   - a substituted key;
   - a re-sealed export;
   - a changed head;
   - forged webhooks.
9. Restore from backup; the heads and the journal remain consistent; nothing is executed again.
10. Load: the bank's peak payment rate with the expected number of instances; latency of the lock on the trust row.

## 11. What cannot be checked without the real backend and provider

- that every real execution path of the bank goes through the boundary;
- the real provider's idempotency, lookup semantics and settlement times;
- behaviour under the bank's network, load balancers and TLS termination;
- the bank's HSM signing of statements and its PKI for mutual TLS;
- operations: alerting, reconciliation, review with four-eyes, incident response;
- timing of leases against the real latency of Auth Core and the provider;
- data migration and restore in the bank's database.
