# Bank database authorization

Status: 2.0.0, phase 15. Implementation: [`bank-integration/schema.mjs`](../../bank-integration/schema.mjs). Tests: `auth-core/test/integration/bank-db-authorization.test.mjs` (DA 1–14, numbered in file order), together with EP (`bank-execution-processes`) and EB (`bank-execution-boundary`). Verified on PostgreSQL 16.13 only.

This is the reference schema in this repository. It is not a bank's database and has not been reviewed by a bank's DBA or an independent auditor.

## 1. What was wrong (phase 14, reproduced on `3cbea86`)

Reproduced on a clean test database, with the boundary's ordinary role:

| # | Attempt | Result on `3cbea86` |
|---|---|---|
| 1 | `UPDATE bank_executions SET state = 'APPROVED'` for a payment in `CHECKING`, with a credential the bank never approved | 1 row updated. The gateway then sent the payment: the provider was called once. Nothing checked the registry, the revocation or the order. |
| 2 | `INSERT INTO bank_execution_transitions …` with a made-up transition | inserted; the role also had `USAGE` on every sequence of the schema |
| 3 | `INSERT INTO bank_credential_trust … 'APPROVED'` with no statement | inserted: an approved credential without any signed approval |

Cause: the boundary role had `INSERT` and `UPDATE` on the journal, the log and the registry. The transition trigger checked which transitions are allowed, not who made them or how. `approveExecution()` was the only place with the checks, and nothing forced a caller through it.

## 2. Model

- **Own schema `bank`**, owned by a schema owner that is not a superuser and is used only for migrations. `PUBLIC` has no rights on the schema, its tables, sequences or functions.
- **No application role can write a table.** No `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, no sequence right, no `CREATE` on any schema, no `TEMPORARY` on the database.
- **Every change is a `SECURITY DEFINER` function** owned by the schema owner, with `SET search_path = pg_catalog, pg_temp` and every object of the schema written with its schema (`bank.executions`, `bank.order_hash(...)`). Each role may execute only its own functions.
- **The state machine knows the function.** A function announces itself with `bank.via('<name>')` immediately before its one row change. The trigger accepts the change only if (from, to, function) is in `bank.allowed_transitions`, then clears the announcement: one announcement, one row (DA 3).
- **The trigger writes the log.** In the same trigger, one row per transition: from, to, attempt, function, and `session_user` (the login role, which a `SECURITY DEFINER` function does not change and an ordinary role cannot change). No role has `INSERT` on the log; nobody, including the owner, can update, delete or truncate it (DA 2).
- **The approval is made from the database's own data.** The caller gives the attempt and the evidence it verified. The database takes the credential from the evidence and binds the evidence to this payment's authorization, customer, reference and signed terms. It checks the credential's registry row under `FOR SHARE` and computes the order hash itself from the stored payment (DA 5).
- **Signatures are checked twice outside the database.** PostgreSQL has no ECDSA (`pgcrypto` does not provide it). The boundary runs the bank's decision before `bank.approve`. The gateway runs it again on the evidence stored with the approval and the statements as they stood at the approval, before `bank.submit`. A holder of the boundary role alone cannot get a payment sent without a valid customer confirmation (DA 6).

## 3. Roles and privileges

Created by the bank's administrator, `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE`, not `BYPASSRLS`, with `CONNECT` on the database only. `installSchema` refuses a role that is a superuser, bypasses row security, or is a member of the owner (DA 14). `privilegeMatrix()` reads the catalog: direct and inherited rights (`has_*_privilege`), membership (`pg_has_role`) and attributes. DA 14 compares it with `intendedPrivileges()` after a clean install, after a reinstall over extra grants, and after a refused install.

| Role | Tables (read) | Tables (write) | Sequences | Functions (`EXECUTE`) | Schema `bank` | Schema `public` | Database | Member of |
|---|---|---|---|---|---|---|---|---|
| boundary | `payments`, `executions`, `execution_transitions`, `trust_statements`, `chain_heads`, `reconciliation_findings` | none | none | `create_payment`, `attach_authorization`, `claim`, `approve`, `refuse`, `hold`, `mark_unknown`, `mark_review`, `keep_head`, `add_finding` | `USAGE` | `USAGE` (PostgreSQL default, no `CREATE`) | `CONNECT` | none |
| gateway | none | none | none | `submit_basis`, `submit`, `resubmit`, `gateway_refuse`, `report`, `operation_for_lookup` | `USAGE` | `USAGE` | `CONNECT` | none |
| registry | none | none | none | `approve_credential`, `revoke_credential` | `USAGE` | `USAGE` | `CONNECT` | none |
| operator (one login per person) | `payments`, `executions`, `execution_transitions`, `reconciliation_findings` | none | none | `resolve_review` | `USAGE` | `USAGE` | `CONNECT` | none |
| schema owner | all | all (subject to the triggers) | all | all | owner | — | `CONNECT`, `CREATE` (to create the schema) | none; not used by services |
| PostgreSQL superuser | everything | everything | everything | everything | — | — | — | — |

Not granted to anyone: `credential_trust` and `allowed_transitions` (read only inside the functions), the internal functions `via`, `order_document`, `order_hash`, `evidence_problem`, `advance_head` and the trigger functions.

The gateway cannot read or change the registry or trust (DA 10, Z9 in the mutation run). The registry and the operator cannot touch payments or executions (DA 10).

**Later objects.** `installSchema` sets the owner's default privileges so that a function created later is not executable by `PUBLIC`, and tables and sequences created later in `bank` get no grants (DA 14: `bank.later`, `bank.later_fn()`).

**Inheritance.** A role that is a member of the boundary role (with `INHERIT`) gets the boundary's functions, with all their checks, and nothing more. It cannot `SET ROLE` to the owner or the gateway (DA 12).

## 4. `SECURITY DEFINER` functions

Common to all 19:

- **owner:** the schema owner (DA 13 checks every definer function in `bank`);
- **search_path:** `pg_catalog, pg_temp`, set on the function (DA 13 checks `proconfig`);
- **names:** every schema object qualified with `bank.`, so nothing in `public` or in a temporary schema is found. Functions are never looked up in `pg_temp`. Ordinary roles cannot create objects in `bank`, `public` or a temporary schema (DA 13);
- **`EXECUTE`:** only the role named below. Not `PUBLIC` (DA 13, DA 14);
- **arguments:** bound as parameters by the clients; nothing is executed as SQL text;
- **state changes:** one row, through the transition trigger and its log row.

| Function | `EXECUTE` | Arguments accepted | Reads / writes | Invariants checked in the function | Bypasses excluded (tests) |
|---|---|---|---|---|---|
| `create_payment(payment, reference, terms, authorization?)` | boundary | terms object with a 9-digit customer, reference, amount (digits), currency (3 letters), beneficiary object | W `payments` | unique payment, reference and authorization | writing `payments` directly (DA 1); a second payment for one authorization (EB «replayed») |
| `attach_authorization(payment, authorization)` | boundary | — | W `payments` | only from `CREATED`, once (trigger: once, terms immutable) | `UPDATE payments` (DA 1) |
| `claim(payment, lease_ms)` | boundary | lease 100 ms … 1 h | R/W `payments` (lock), `executions` | payment awaiting execution; one attempt at a time; live leases not taken; an expired approval withdrawn before a new attempt | `INSERT`/`UPDATE executions` (DA 1); take over a live claim (EB «live claim», Y7, Y7b) |
| `approve(payment, attempt, evidence, lease_ms)` | boundary | the attempt holding a live claim; evidence as a schema 3 `AUTHORIZATION` record; lease within limits | R `payments`, `credential_trust` (`FOR SHARE`), `trust_statements`; W `executions` | `CHECKING`, same attempt, live lease; evidence for this authorization, customer, reference, signed amount, currency, beneficiary, operation type, hash of the signed bytes; credential from the evidence, in the registry, for this customer, `APPROVED`, with a stored approval statement; order hash computed from the payment; once | direct `UPDATE … 'APPROVED'`, changing `credential_id` or `order_hash` (DA 1); expired lease, revoked, another customer's, unknown credential, old attempt, second approval, unbounded lease, evidence for other terms, another authorization, another customer, no evidence (DA 5); concurrent revocation (DA 8); rollback and a dropped connection (DA 9) |
| `refuse(payment, attempt, problems)` | boundary | — | W `executions` | same attempt, `CHECKING` | — |
| `hold(payment, attempt, reason, from[])` | boundary | `from` limited to `CHECKING`, `APPROVED` | W `executions` | same attempt | — |
| `mark_unknown(payment, attempt, reason)` | boundary | — | W `executions` | same attempt, `SUBMITTED` or `RECONCILING`; only makes the payment reconcile, never final | — |
| `mark_review(payment, attempt, reason)` | boundary | — | W `executions` | same attempt, `RECONCILING` | — |
| `keep_head(nexus, sequence, hash)` | boundary | 9 digits, sequence ≥ 1, 64 hex | W `chain_heads` | forward only (also the trigger) | `UPDATE chain_heads` (EP «chain head»); moving back through the function (EP) |
| `add_finding(payment, local, provider, detail)` | boundary | — | W `reconciliation_findings` | `recorded_by = session_user`; append-only | — |
| `submit_basis(payment, attempt)` | gateway | — | R `executions` (`FOR UPDATE`), `payments`, `trust_statements` | `APPROVED` or `RECONCILING`, same attempt, live lease; returns the order, whether it still has the approved hash, the stored evidence, the statements up to the approval, the expected terms | reading tables directly (DA 10) |
| `submit(payment, attempt)` | gateway | — | W `executions` | `APPROVED`, same attempt, live lease, order hash unchanged; once | CHECKING attempt, other attempt, changed reference, twice — called directly without the gateway's check (DA 4); boundary calling it (DA 10, EB) |
| `resubmit(payment, attempt)` | gateway | — | W `executions` | `RECONCILING`, same attempt, submitted before, live lease, order hash unchanged | from `APPROVED` (DA 4) |
| `gateway_refuse(payment, attempt, reason)` | gateway | — | W `executions` | same attempt, `APPROVED` or `RECONCILING` → `REVIEW` | — |
| `report(payment, attempt, outcome, reference, reason)` | gateway | outcome `succeeded`, `failed`, `pending`, `unknown` | W `executions` | same attempt, `SUBMITTED` or `RECONCILING`; nothing out of a final state | boundary recording `EXECUTED` (DA 10); another attempt, a final state, before submission (DA 4) |
| `operation_for_lookup(payment)` | gateway | — | R `payments`, `executions` | only after a submission | before submission (DA 4) |
| `approve_credential(entry, head_sequence?, head_hash?)` | registry | an approval statement: identifiers, fingerprint, signature field | W `credential_trust`, `trust_statements`, `chain_heads` | one customer per credential; never again after a revocation; `recorded_by = session_user` | `INSERT credential_trust` (DA 1); the gateway calling it (DA 10); unsigned statement (DA 6, EB «registry accepts only») |
| `revoke_credential(entry)` | registry | a revocation statement | W `credential_trust`, `trust_statements`; R `executions` | final; one customer; returns payments past the cut-off; serialized with `approve` | (DA 8) |
| `resolve_review(payment, outcome, note, reference?)` | operator | outcome `succeeded` or `failed`; a note | W `executions` | `REVIEW` only; `resolved_by = session_user` | the boundary calling it (DA 11); a name given by the caller (DA 11) |

## 5. What the database does not decide

- **Signatures.** The registry service verifies a statement before `approve_credential`; the database checks its shape. A holder of the registry role can store a statement with a bad signature. It counts nowhere: the boundary and the gateway verify every statement against the bank trust keys and refuse the decision (DA 6, EB «registry accepts only»).
- **The device signature and the HSM seal on the evidence.** `bank.approve` binds the evidence to the payment, but does not verify signatures. The boundary verifies them before the approval, and the gateway after it (DA 6).
- **Whether the boundary verified.** A compromised boundary can call `bank.approve` with any evidence. With a forged confirmation the gateway sends nothing (DA 6). With a genuine confirmation it can at most cause the payment that the customer actually confirmed, with those terms.
- **`bank.via` is a label, not an authority.** It is a configuration setting any session can set. It matters only to whoever can update the tables, and only the owner can. The owner setting it by hand still meets the trigger's other invariants (DA 3).

## 6. Install, reinstall, upgrade

- **Clean database:** the administrator runs `DATABASE_HARDENING`: no `TEMPORARY` for `PUBLIC`, no `CREATE` in `public`. Then the owner runs `installSchema`.
- **Reinstall:** `installSchema` first revokes every right of each given role on all tables, sequences and functions of `bank` and on the schema, and every `PUBLIC` right. Then it grants the matrix again. Extra grants made by hand do not survive (DA 14).
- **Upgrade from phase 14:** the phase 14 tables lived in `public` (`bank_*`). `installSchema` revokes the given roles' rights on those tables and on `bank_submit`, `bank_resubmit` and `bank_operation_for_lookup` if the owner owns them (DA 14). **Their data is not migrated.** A bank that ran phase 14 migrates payments, executions, statements and heads under its own change control, then drops the old tables.

## 7. Residual boundary: the owner and the PostgreSQL administrator

The schema owner can disable triggers, replace functions, change grants and rows. A PostgreSQL superuser can do all of that in any database. The tests use the owner on purpose to stage such changes (DA 7, EP «terms changed»), and the gateway's check catches a changed order or reference. But nothing in the database stops these roles from removing the checks themselves. This is a residual risk (R-26), compensated by operational control, which this repository cannot provide:

1. The owner role is used only for migrations, from a change-controlled pipeline, under dual control; no service and no person uses it interactively.
2. The superuser is held by the database operations team under break-glass procedures.
3. Statement logging (`log_statement = 'ddl'` at least) and `pgaudit` or equivalent for the owner and superuser, shipped to a log store the database team cannot change; alerts on `ALTER … DISABLE TRIGGER`, `CREATE OR REPLACE FUNCTION`, `GRANT`, `ALTER ROLE`, `SET ROLE` and any session of the owner outside a migration window.
4. After every migration: `privilegeMatrix()` compared with `intendedPrivileges()`, and the function definitions compared with the reviewed release (hash of `pg_get_functiondef`).
5. Independent reconciliation with the provider (pilot pack, section 8). It finds a payment that went out whatever happened in the database.

## 8. Not verified here

- PostgreSQL versions other than 16.13; managed services whose superuser is restricted differently.
- A bank's real roles, connection pooling (a shared pool login would make `session_user` meaningless) and its audit logging.
- Row-level security: not used; the schema relies on no table rights at all.
- Performance of the locks under the bank's load (pilot pack, section 10).
