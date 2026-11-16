# Database migrations

| Situation | What to apply |
|---|---|
| New installation | `src/db/schema.sql` only. It contains the complete current schema, including everything below, and can be applied repeatedly. Then `scripts/db/roles.sql`. |
| Existing deployment | The migrations newer than the deployment's current level, in numeric order, then `scripts/db/roles.sql` again. From 1.4.0 follow [upgrade to 2.0](../../docs/operations/upgrade-2.0.md). |

The migrations upgrade a database that already has the pre-1.0 Auth Core schema (`bank_clients` and the original identity tables); `002` is the first step from that baseline. They are written to be re-runnable (`IF NOT EXISTS`, `DROP ... IF EXISTS` before `CREATE TRIGGER`). None has a down script.

Run migrations as the table owner. After `scripts/db/roles.sql` has been applied that is `nexus_owner`, through a DBA account with `SET ROLE nexus_owner`; Auth Core's own role `nexus_app` cannot run them ([database roles](../../docs/operations/deployment.md#database-roles)).

| File | Content |
|---|---|
| `002_nexus_identity_authorization_v1.sql` | NEXUS identities, credentials, authorization protocol v1 |
| `003_recovery_credential_rotation.sql` | Recovery verifier, credential rotation, HSM evidence |
| `004_production_data_hardening.sql` | Constraints, indexes, bank transaction columns |
| `005_bank_transaction_integration.sql` | Bank transaction tracking, webhook delivery |
| `006_recovery_access_tokens.sql` | Recovery session access tokens |
| `007_authorization_signature_format.sql` | Device signature encoding (`der` / `raw`) |
| `008_adaptive_verification_escalation.sql` | Verification plans and sessions |
| `009_evidence_v2_append_only.sql` | Evidence schema 2 (`sealed_payload`), append-only trigger, webhook outbox columns |
| `010_device_keys_offline_confirmation.sql` | Device authentication and offline keys, confirmation method |
| `011_index_cleanup.sql` | Drops two duplicate indexes |
| `012_secure_push.sql` | Push mode per bank client, push registrations, push message outbox |
| `013_evidence_v3_credential_provenance.sql` | Evidence schema 3: `record_type` (`AUTHORIZATION`, `CREDENTIAL_ENROLLED`, `RECOVERY_CONFIGURED`), `chain_sequence`, `seal_key_id`; chain uniqueness indexes; `credentials.enrolment_evidence_id`, `nexus_identities.recovery_evidence_id` |
| `014_device_replacement.sql` | `push_messages.replacement_notice` |
| `015_recovery_v2.sql` | Recovery protocol 2: `nexus_identities.recovery_protocol`, `recovery_public_key_pem`, `recovery_wrapped_key`; `recovery_sessions.protocol`, `failed_attempt_count`, `created_at` |
| `016_audit_admin_mtls.sql` | `audit_logs.client_id` and `actor`, append-only triggers on `audit_logs`; `admin_users.client_id`, `totp_secret_encrypted`, `totp_last_step`, `session_version`; table `admin_approvals`; `bank_clients.mtls_cert_sha256` |
| `017_state_machine.sql` | Lifecycle triggers on `authorization_requests`, `credentials` and `nexus_identities`; triggers refusing `DELETE` on `authorization_requests`, `credentials`, `nexus_identities`, `recovery_sessions` and `admin_approvals`; at most one `ACTIVE` credential per identity |
| `018_remove_unused_schema.sql` | Drops `attestation_records`, `policy_decisions`, `credentials.suspended_at` and `nexus_identities.recovery_verifier`; authorization states reduced to `PENDING_USER`, `VERIFIED`, `EXPIRED`, `CANCELLED`, `REJECTED`, credential states to `ACTIVE`, `REVOKED` |
| `019_verification_results.sql` | Verification results: provider keys, result method and issuer per session |
| `020_secret_key_rotation.sql` | `secret_rewrap_allowed()`; the rotation tool may replace a credential's offline key ciphertext |
| `021_device_request_nonces.sql` | Device request nonces in PostgreSQL |
| `022_offline_deferred_signature.sql` | Offline confirmation v2: states `OFFLINE_PROVISIONAL` and `OFFLINE_UNSIGNED` (state column widened to 24), `confirmation_method` `OFFLINE_SIGNED`, columns `offline_code_tag`, `offline_code_accepted_at`, `offline_signature_deadline`, `offline_unsigned_reason`, append-only table `offline_deferred_signatures`; lifecycle trigger with the new transitions; `policy_reference` and `policy_version` immutable. Additive |
| `023_device_replacement_hold.sql` | Table `device_replacements`: bank-requested device replacements with a hold, decided by the enrolled device; lifecycle and no-delete triggers |

## Notes on 009

- Evidence records sealed before 009 keep their original hash and seal but have no `sealed_payload`; they are exported with an empty `sealedPayload` and reported as "unsupported" by `scripts/verify-evidence.mjs`. Records sealed afterwards are fully verifiable offline.
- After 009 the application role can no longer update or delete evidence. Data retention of evidence is handled by export and archival, not by deletion.

## Notes on 013 to 018

- **013** numbers the existing records of each chain from 1, ordered by `created_at` and `evidence_id`. This is the only update the migration makes to evidence: it disables `trg_evidence_append_only` for that statement and enables it again in the same transaction, so it must run as the table owner. Records sealed before schema 3 do not contain their number in the sealed payload; the verifier checks their position from the exported `chainSequence` and reports them as `legacy_records` (no key provenance). The `AUTHORIZATION` columns become nullable, with a check constraint that keeps them required for `AUTHORIZATION` records. Auth Core 1.4.0 cannot insert evidence after this migration.
- **013** adds `credentials.enrolment_evidence_id` without filling it. Auth Core 2.0 refuses to use a credential's keys without a sealed enrolment record, so run `node dist/cli/sealCredentialBaseline.js` once after the migrations and before traffic.
- **015** sets `recovery_protocol = 1` for identities that have a recovery verifier. Recovery for them is refused (409 `RECOVERY_PROTOCOL_RETIRED`) until the customer sets up a protocol 2 phrase. Existing `recovery_sessions` rows get `protocol = 1`, `failed_attempt_count = 0` and `created_at` set to the time of the migration.
- **016** fills `audit_logs.client_id` from the identity and `actor` from `details.actor` where they exist; older rows keep `NULL` otherwise. The append-only triggers are created after this backfill; from then on `UPDATE`, `DELETE` and `TRUNCATE` on `audit_logs` fail with `audit_logs is append-only`. Existing admin accounts get `client_id = NULL` (all banks) and no TOTP secret; re-provision them with `createAdminUser`. `bank_clients.mtls_cert_sha256` starts empty; with `REQUIRE_MTLS_HEADER` a client without fingerprints cannot obtain tokens.
- **017** stops with `identities with more than one ACTIVE credential: ...` when existing data violates the new unique index (`idx_credentials_one_active`); revoke the extra credentials and run it again. Its triggers refuse, for every role including the owner: changes to the bound transaction fields of an authorization, state transitions outside the lifecycle, signature fields set other than on the transition to `VERIFIED`, changes to a credential's keys, a second enrolment record on a credential, changes to an identity's bank binding, detaching an identity's recovery record, and deleting rows of `authorization_requests`, `credentials`, `nexus_identities`, `recovery_sessions` and `admin_approvals` (`<table> rows are not deleted (DELETE refused)`). A table owner or superuser can disable the triggers; that case is covered by the sealed evidence and the runtime credential integrity check, not by the triggers.
- **018** ([ADR 0016](../../docs/adr/0016-remove-compatibility-paths.md)) stops, naming the rows, when an authorization or credential is in a removed state or `attestation_records` or `policy_decisions` holds rows. Revoke such credentials as the table owner (the revoke endpoint accepts only `ACTIVE` credentials; the 017 trigger permits the change), export and empty the tables if needed, then run it again.
- **Rollback.** None of 013 to 018 can be reverted by a script. The rollback path is a restore of the backup taken before the upgrade, which discards everything written afterwards ([upgrade to 2.0](../../docs/operations/upgrade-2.0.md#rollback)).

## Verifying a migration run

The CI job `auth-core / integration (PostgreSQL, Redis, SoftHSM)` creates a database for each suite by applying `schema.sql` and then every migration on top, against PostgreSQL 16; `test/integration/db-roles.test.mjs` additionally applies `scripts/db/roles.sql` and runs the service as `nexus_app`. The CI job `auth-core / end-to-end (PostgreSQL, Redis)` applies `schema.sql` twice, every migration on top and `scripts/db/roles.sql`, and runs `scripts/e2e-smoke.mjs` against the service connected as `nexus_app`. Before upgrading production, restore a copy of the production database, apply the migrations, run `sealCredentialBaseline` and `scripts/e2e-smoke.mjs` against it.
