# 0013. Lifecycle state machines enforced by the database

## Status

Accepted

## Date

2026-10-06

## Context

The lifecycles of authorizations, bank transactions, credentials and NEXUS IDs were enforced only by the application's SQL. A defect, a maintenance script or a direct write with the application's database credentials could reopen a verified authorization, change the amount or beneficiary of one that was already signed, re-sign it, revive a revoked credential, swap a credential's key or move an identity to another bank. The evidence chain would show the original, but Auth Core would act on the changed row.

## Decision

- Migration 017 adds `BEFORE UPDATE` triggers that permit only the specified transitions and refuse changes to binding columns:
  - authorization: `CREATED` → `DELIVERING` → `PENDING_USER` → (`SIGNED`) → `VERIFIED` → `CONSUMED`, and any state before `VERIFIED` → `EXPIRED`, `CANCELLED`, `REJECTED`; the transaction it binds is immutable; signature fields are set only on the transition to `VERIFIED`;
  - bank transaction: `PENDING` → `COMMIT_REQUESTED` (only for a `VERIFIED` or `CONSUMED` authorization) → `COMMITTED`, `FAILED` or `CANCELLED`;
  - credential: `PENDING` → `ACTIVE`, `ACTIVE` ↔ `SUSPENDED`, any → `REVOKED` (final); keys, identity, platform and key version immutable; the enrolment record attached once;
  - identity: `ACTIVE` ↔ `SUSPENDED`, any → `REVOKED` (final); the bank binding immutable; the sealed recovery record cannot be detached.
- A unique index allows one `ACTIVE` credential per identity; the migration stops if existing data has more.
- `scripts/db/roles.sql` makes a `NOLOGIN` role own the tables and triggers, so the role Auth Core connects as cannot disable them.

Superseded in part by [0016](0016-remove-compatibility-paths.md): migration 018 removes the unused authorization and credential states, and bank-side rotation no longer exists.

## Consequences

- An invalid write fails with `integrity_constraint_violation` instead of changing what was authorized. Application defects surface as errors.
- The triggers cover updates, not inserts or deletes. Inserted credentials are caught by the runtime integrity check against sealed enrolments ([ADR 0009](0009-evidence-schema-3.md)); inserted authorizations have no evidence record.
- A superuser or the database provider's administrative role can still disable triggers. This is covered by logging their DDL and by the sealed evidence, not by the triggers.
- The schema permits states the application does not use (`CREATED`, `DELIVERING`, `SIGNED`, `CONSUMED` for authorizations, `PENDING` and `SUSPENDED` for credentials).
- **Update (2.0, migration 018, ADR 0016; finding C-17):** those states were removed. The authorization states are now `PENDING_USER`, `VERIFIED`, `EXPIRED`, `REJECTED`, `CANCELLED`, `OFFLINE_PROVISIONAL` and `OFFLINE_UNSIGNED`; credentials are `ACTIVE` or `REVOKED`. The transitions listed under Decision are the original ones; the triggers of `schema.sql` are authoritative.
- Bank-side rotation, which inserts the new credential before revoking the old one, is refused by the one-`ACTIVE` index for an `ACTIVE` credential.
- Specification: [state machines](../architecture/state-machines.md). Test: `test/integration/state-machine.test.mjs`, including a property test of random transitions.

## Note

Changes made after this decision, in the same release:

- Bank-side rotation now revokes the old credential before inserting the new one, so the one-`ACTIVE` index no longer refuses it (`rotateCredential` in `credentialService.ts`).
- Migration 017 also adds `BEFORE DELETE` triggers that refuse deleting rows of `authorization_requests`, `credentials`, `nexus_identities`, `recovery_sessions` and `admin_approvals`, and `scripts/db/roles.sql` grants `nexus_app` `DELETE` only on `push_registrations`. Inserts remain uncovered by the triggers. Amended by migration 024 (audit finding C-05): authorization inserts are checked (`authorization_insert_state`); credential inserts still are not.
