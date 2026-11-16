# Lifecycle state machines

The lifecycles of authorizations, bank transactions, device credentials and NEXUS IDs are enforced by the database, not only by the application. Migration `017_state_machine.sql` adds a `BEFORE UPDATE` trigger to each of `authorization_requests`, `credentials` and `nexus_identities` that refuses any transition or column change outside the tables below with SQLSTATE `23000` (`integrity_constraint_violation`). Migration `018_remove_unused_schema.sql` reduces the authorization and credential states to those the application uses. Decision records: [ADR 0013](../adr/0013-database-enforced-state-machines.md), [ADR 0016](../adr/0016-remove-compatibility-paths.md).

The triggers make every other write, whether a defect or a direct write by a session with the application's database role, fail instead of silently changing what was authorized.

## Authorization

Column `authorization_requests.state`, trigger `authorization_lifecycle`.

| From | Permitted to |
|---|---|
| `PENDING_USER` | `VERIFIED`, `EXPIRED`, `CANCELLED`, `REJECTED`, `OFFLINE_PROVISIONAL` |
| `OFFLINE_PROVISIONAL` (migration 022) | `VERIFIED`, `OFFLINE_UNSIGNED` |
| `VERIFIED`, `EXPIRED`, `CANCELLED`, `REJECTED`, `OFFLINE_UNSIGNED` | none (final) |

Further rules in the same trigger:

| Rule | Columns |
|---|---|
| Never change | `authorization_id`, `client_id`, `nexus_id`, `credential_id`, `transaction_reference`, `operation_type`, `amount_minor`, `currency`, `beneficiary`, `policy_reference`, `policy_version` (since 022), `canonical_payload_hash`, `nonce`, `issued_at`, `created_at` |
| Change only in the update that moves the state from `PENDING_USER` or `OFFLINE_PROVISIONAL` to `VERIFIED` | `signature`, `signature_format`, `confirmation_method`, `verified_at` |
| Set once, from `PENDING_USER` to `VERIFIED` or `OFFLINE_PROVISIONAL` | `offline_code_tag`, `offline_code_accepted_at`, `offline_signature_deadline` (all three required for `OFFLINE_PROVISIONAL`) |
| Set once, from `OFFLINE_PROVISIONAL` to `OFFLINE_UNSIGNED` (required then) | `offline_unsigned_reason` |
| Must be set when the state is `VERIFIED` | `signature`, `verified_at` |
| Change only while the state is `PENDING_USER` | `expires_at` |

### What the application does

Auth Core inserts every authorization in `PENDING_USER` (`authorizationService.ts`). A confirmed authorization is set to `VERIFIED` with `consumed_at` in one update, and stays `VERIFIED`.

| Transition | Performed by |
|---|---|
| `PENDING_USER` → `VERIFIED` | `authorizationConfirmation.ts` (`transitionTerminal`): a valid device signature or offline code, under a row lock, after re-checking the plan, expiry, credential state and key, and the canonical bytes; seals the `AUTHORIZATION` evidence record in the same transaction |
| `PENDING_USER` → `OFFLINE_PROVISIONAL` | `authorizationConfirmation.ts` (`acceptOfflineCode`): a correct offline code with `OFFLINE_CONFIRMATION_MODE=deferred_signature` and no stored device signature |
| `OFFLINE_PROVISIONAL` → `VERIFIED` | `authorizationConfirmation.ts` (`submitDeferredSignature`): the device's signature from the bound credential, before the deadline, under the row lock; seals the evidence |
| `OFFLINE_PROVISIONAL` → `OFFLINE_UNSIGNED` | `expireUnsignedOfflineConfirmations` (expiry worker): deadline passed, or credential or identity no longer `ACTIVE` |
| `PENDING_USER` → `EXPIRED` | `authorizationConfirmation.ts`, when a confirmation arrives after `expires_at` |
| `PENDING_USER` → `REJECTED` | `authorizationConfirmation.ts` (signature or code attempt limit reached); `adaptiveVerificationService.ts` (verification plan failed) |
| `PENDING_USER` → `CANCELLED` | `credentialService.ts` (credential revoked or replaced); `recoveryService.ts` (recovery completed); `nexusIdentityService.ts` (identity suspended or revoked) |

## Bank transaction

Column `authorization_requests.bank_transaction_state` (default `PENDING`), same trigger.

| From | Permitted to | Condition |
|---|---|---|
| `PENDING` | `COMMIT_REQUESTED` | The authorization is `VERIFIED` |
| `COMMIT_REQUESTED` | `COMMITTED`, `FAILED`, `CANCELLED` | |
| `COMMITTED`, `FAILED`, `CANCELLED` | none (final) | |

`bank_transaction_reference` can change only in an update that also performs one of these transitions.

| Transition | Performed by |
|---|---|
| `PENDING` → `COMMIT_REQUESTED` | `bankTransactionService.ts` (`requestCommit`, `POST /v1/authorizations/{id}/bank-commit-request`): only for a `VERIFIED` authorization, while the identity and the confirming credential are `ACTIVE` and the confirmation is at most `BANK_COMMIT_MAX_AGE_SECONDS` old (409 `IDENTITY_NOT_ACTIVE`, `CREDENTIAL_NOT_ACTIVE`, `CONFIRMATION_TOO_OLD`) |
| `COMMIT_REQUESTED` → `COMMITTED`, `FAILED`, `CANCELLED` | `bankTransactionService.ts` (`finalizeBankTransaction`, `POST /v1/authorizations/{id}/bank-commit-result`) |

## Credential

Column `credentials.state`, trigger `credential_lifecycle`.

| From | Permitted to |
|---|---|
| `ACTIVE` | `REVOKED` |
| `REVOKED` | none (final) |

Suspension is a state of the NEXUS identity ([below](#identity)), not of a credential.

| Rule | Columns |
|---|---|
| Never change | `credential_id`, `nexus_id`, `key_algorithm`, `public_key_pem`, `auth_public_key_pem`, `offline_public_key_pem`, `offline_server_public_key_pem`, `offline_secret_encrypted`, `platform`, `key_version` |
| Set once (from `NULL`), then never change | `enrolment_evidence_id` |

A unique index (`idx_credentials_one_active`) allows at most one `ACTIVE` credential per NEXUS ID. Migration 017 stops, naming up to 20 identities, if existing data has more; the extra credentials are revoked before the migration is applied again.

`security_level`, `attestation_status`, `last_used_at` and the timestamps are not covered by the trigger.

### What the application does

Auth Core inserts credentials as `ACTIVE`, only through device enrolment (`POST /v1/mobile/bootstrap`) and recovery completion.

| Transition | Performed by |
|---|---|
| `ACTIVE` → `REVOKED` | `credentialService.ts`: bank revocation (`POST /v1/credentials/{id}/revoke`), [device replacement](device-replacement.md); `recoveryService.ts`: completed recovery; `nexusIdentityService.ts`: identity revoked |
| `enrolment_evidence_id` set | `evidenceService.ts` (`sealCredentialEnrolment`), in the transaction that registers the credential, or `sealCredentialBaseline` on upgrade |

Replacement and recovery revoke the previous credential before inserting the new one in the same transaction, as the unique index requires.

## Identity

Column `nexus_identities.status`, trigger `identity_lifecycle`.

| From | Permitted to |
|---|---|
| `ACTIVE` | `SUSPENDED`, `REVOKED` |
| `SUSPENDED` | `ACTIVE`, `REVOKED` |
| `REVOKED` | none (final) |

| Rule | Columns |
|---|---|
| Never change (the bank binding) | `nexus_id`, `client_id`, `bank_customer_ref` |
| Once set, cannot be set back to `NULL` | `recovery_evidence_id` |

| Transition | Performed by |
|---|---|
| `ACTIVE` → `SUSPENDED` | `nexusIdentityService.ts` (`suspendNexusIdentity`), from the admin console by one operator; cancels the identity's `PENDING_USER` authorizations |
| `SUSPENDED` → `ACTIVE` | `nexusIdentityService.ts` (`reactivateNexusIdentity`), executed by an approved [four-eyes request](../adr/0014-admin-scope-mfa-four-eyes.md) |
| `ACTIVE` or `SUSPENDED` → `REVOKED` | `nexusIdentityService.ts` (`revokeNexusIdentity`), executed by an approved four-eyes request; revokes the identity's credentials and cancels its `PENDING_USER` authorizations |

The bank API has no endpoint that changes an identity's status.

## Limits

- Recovery sessions (`recovery_session_lifecycle`, migration 017): the issued fields (identity, bank, nonce, salt, token hash, protocol, creation time) never change, the expiry can only be shortened, `attempt_count` and `failed_attempt_count` only grow, and `used_at` is set once.
- The lifecycle triggers fire on `UPDATE` only. Separate `BEFORE DELETE` triggers (`refuse_delete()`, migration 017) refuse deleting rows of `authorization_requests`, `credentials`, `nexus_identities`, `recovery_sessions` and `admin_approvals` for every role (SQLSTATE `42501`, `<table> rows are not deleted (DELETE refused)`), and `scripts/db/roles.sql` grants `nexus_app` `DELETE` only on `push_registrations`. Inserts: since migration 024 the `BEFORE INSERT` trigger `authorization_insert_state` refuses an authorization that does not start `PENDING_USER` with bank transaction `PENDING` and no signature, confirmation, offline or commit fields, and a `CHECK` limits `bank_transaction_state` to the five states above. Credentials are not covered at insert time: the application role can still insert a credential row in any state its `CHECK` allows. A credential inserted or re-inserted outside the application has no valid sealed enrolment and is refused by the [runtime integrity check](../protocol/evidence-format.md#runtime-integrity-check); an authorization inserted outside the application has no evidence record (`evidence` is `null` in `GET /v1/authorizations/{id}`) and does not appear in the identity's chain.
- The table owner or a superuser can disable or replace the triggers. `scripts/db/roles.sql` makes `nexus_owner` (`NOLOGIN`) the owner of every table and trigger function, so the role Auth Core connects as (`nexus_app`) cannot. A superuser, or the cloud provider's administrative role, still can; their DDL is to be logged (pgaudit or the provider's audit log) and the role restricted. The sealed evidence chain and the head the bank keeps make a change that bypassed the triggers detectable afterwards.
- `evidence_records` and `audit_logs` have their own append-only triggers (migrations 009 and 016); `nexus_app` has `INSERT` and `SELECT` only on them.

## Tests

`auth-core/test/integration/state-machine.test.mjs` runs against PostgreSQL 16 with all migrations applied: a verified authorization cannot be reopened, re-signed or altered; a pending one cannot become `VERIFIED` without a signature or have its transaction changed; random authorization and bank-transaction updates are accepted exactly when the tables above permit them (property test); credentials and identities as above, including one `ACTIVE` credential per identity after device enrolment; the states removed by migration 018 cannot be written, and 018 stops, naming the rows, when existing data uses them; rows of the five protected tables cannot be deleted. `test/integration/db-roles.test.mjs` checks the roles. Both run in the CI job `auth-core / integration`.
