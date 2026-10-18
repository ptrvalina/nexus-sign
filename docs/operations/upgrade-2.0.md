# Upgrade to 2.0

From 1.4.0, follow this page from the start. From 2.0.0-rc.1, see [from 2.0.0-rc.1](#from-200-rc1) first. From 2.0.0-rc.2 to 2.0.0, see [the last section](#from-200-rc2-to-200).

2.0.0-rc.2 changes the database schema (migrations 013 to 018), the evidence format (schema 3), the recovery protocol (protocol 2), the bank client authentication (client certificate binding) and the admin console (TOTP, bank scope, four-eyes approval). Several changes are breaking for bank backends and for the bank's apps; they are listed at the end of this page. The upgrade needs a maintenance window without traffic, because 1.4.0 cannot write evidence after migration 013 and 2.0 refuses credentials until they are sealed (step 5).

Commands run from a checkout of the release tag in `auth-core/`, with the production configuration in the environment. `node dist/cli/...` needs a build (`npm run build`) or the release image.

## Before the window

| Item | Owner | Detail |
|---|---|---|
| Backup and restore test | Bank DBA | A restorable backup taken at the start of the window is the only rollback path ([rollback](#rollback)). Rehearse the whole procedure on a restored copy of production first, then run `scripts/e2e-smoke.mjs` against it. |
| Extra ACTIVE credentials | Operator | Migration 017 stops when an identity has more than one `ACTIVE` credential. Find them beforehand (query below) and revoke the extra ones with `POST /v1/credentials/{id}/revoke`. |
| `PENDING` and `SUSPENDED` credentials | Operator | Migration 018 stops while a credential is in one of these states, which 2.0.0-rc.2 removes. Find them (query below) and set them to `REVOKED` as the table owner (`UPDATE credentials SET state = 'REVOKED', revoked_at = now() WHERE state IN ('PENDING','SUSPENDED')`), after confirming with the bank that none is in use. |
| Devices without an authentication key | Bank, app teams | Devices enrolled by SDKs before 1.2 have no request-signing key. 2.0.0-rc.2 issues no bearer tokens, so these devices can no longer use the mobile API; the customers enrol again through device replacement. Count them with the query below. |
| `ADMIN_SECRET_ENCRYPTION_KEY` | Operator | Generate (`openssl rand -base64 32`) and store in the secrets manager. Needed in step 7. |
| `PKCS11_TOKEN_LABEL`, optionally `PKCS11_EVIDENCE_KEY_ID` | HSM team | Read the token label and, if the key label is not unique, the `CKA_ID` of the evidence key. The private key must be sensitive, non-extractable, sign-capable, EC P-256. |
| Client certificate fingerprints | Each bank | The SHA-256 fingerprint of every client certificate the bank presents to the gateway, including certificates in a rollover. |
| Gateway change | Bank network team | The gateway must send `x-client-cert-sha256` and overwrite it and `x-client-cert-verified` on every request ([deployment](deployment.md#gateway)). 2.0 refuses every bank call without the fingerprint header. |
| Android settings | App team, operator | `ANDROID_APP_CERT_SHA256`, `ANDROID_KEY_SECURITY_POLICY` and the status list job ([Android attestation status list](runbooks/android-attestation-status-list.md)). |
| App releases | App teams | Android apps must ship SDK 2.0 before the upgrade: 2.0 refuses Android enrolment and recovery without Keystore key attestation chains, which SDK 1.4 does not send. Recovery setup needs SDK 2.0 on both platforms (protocol 2). SDK 2.0 has API changes ([app teams](#breaking-changes-for-app-teams)). |
| Bank backend changes | Each bank | See [breaking changes for banks](#breaking-changes-for-bank-backends). |
| Redis | Operator | Meets the [Redis requirement](deployment.md#redis). |

```sql
SELECT nexus_id, count(*) FROM credentials WHERE state = 'ACTIVE' GROUP BY nexus_id HAVING count(*) > 1;
SELECT credential_id, nexus_id, state FROM credentials WHERE state IN ('PENDING','SUSPENDED');
SELECT count(*) AS devices_without_auth_key FROM credentials WHERE state = 'ACTIVE' AND auth_public_key_pem IS NULL;
SELECT count(*) AS protocol_1_identities FROM nexus_identities WHERE recovery_verifier IS NOT NULL;   -- on 1.4.0
SELECT count(*) AS protocol_1_identities FROM nexus_identities WHERE recovery_protocol = 1;          -- on 2.0.0-rc.1
```

The last query counts the identities whose customers will have to set up a new recovery phrase (step 9).

## Steps

1. **Stop traffic.** Scale Auth Core 1.4.0 to zero, or take it out of the gateway's routing. Record the time.

2. **Back up** the database and verify the backup can be restored. Record the backup identifier in the change record.

3. **Apply migrations 013 to 018 in order**, as the current schema owner (before step 4) or, on a database already set up with roles, as a DBA account with `SET ROLE nexus_owner`:

   ```sh
   for f in 013_evidence_v3_credential_provenance 014_device_replacement 015_recovery_v2 016_audit_admin_mtls 017_state_machine 018_remove_unused_schema; do
     psql "$MIGRATION_URL" -v ON_ERROR_STOP=1 -f "migrations/$f.sql" || break
   done
   ```

   Migration 017 stops with `identities with more than one ACTIVE credential: <ids> (revoke the extra credentials, then re-run)` if any are left; migration 018 stops with `credentials in a state that no longer exists: <ids>` or `authorizations in a state that no longer exists: <ids>`, or when `attestation_records` or `policy_decisions` hold rows. Migration 018 also deletes the protocol 1 recovery verifiers (`nexus_identities.recovery_verifier`). Auth Core 1.4.0 and 2.0.0-rc.1 never write the removed authorization states; if one is reported anyway, the row was written outside Auth Core: decide with the bank whether it is `EXPIRED` or `CANCELLED` and set it as the table owner with the `authorization_lifecycle` trigger disabled for that statement, recorded in the change record. The migrations are re-runnable: fix the cause and run the same loop again. Notes per migration are in [migrations/README.md](../../auth-core/migrations/README.md).

4. **Apply the database roles** and switch Auth Core to the application role:

   ```sh
   psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -f scripts/db/roles.sql
   ```

   Enable the `nexus_app` login (`ALTER ROLE nexus_app WITH LOGIN PASSWORD '...'`, or the provider's tooling), grant the migration DBA account membership in `nexus_owner`, and set `DATABASE_URL` to connect as `nexus_app` ([database roles](deployment.md#database-roles)).

5. **Seal the existing credentials**, once, before any traffic, with the 2.0 configuration (the production HSM settings included) and `DATABASE_URL` as `nexus_app`:

   ```sh
   node dist/cli/sealCredentialBaseline.js | tee baseline-$(date +%Y%m%d).log
   ```

   For every `ACTIVE` credential without an enrolment record, it seals a `CREDENTIAL_ENROLLED` record with reason `BASELINE`, attaches it to the credential and writes the audit event `credential_baseline_sealed`. It prints one line per credential and `Baseline complete: N credential(s) sealed.` A second run seals nothing. Keep the output with the change record. A baseline record states the keys the database held at that moment; it cannot prove how they got there.

   Without this step, every device request, confirmation and recovery setup of an existing credential is refused by the integrity check (audit event `integrity_violation`, reason `the credential has no sealed enrolment record`).

6. **Register the client certificate fingerprints** of each bank:

   ```sh
   node dist/cli/setClientCertificates.js <clientId> <hex>[,<hex>]
   ```

   (`npm run set-client-certificates -- ...` runs the same command.) It replaces only the client's registered fingerprints (SHA-256 of the DER certificate, hex, colons allowed) and prints them; secrets, access tokens, webhook URL and push mode are unchanged.

   Optionally, rotate a client's secrets in the same window with `registerClient` (`node dist/cli/registerClient.js <clientId> <webhookUrl> --push-mode=<BANK|NEXUS>`). Every run generates a new `client_secret`, revokes the client's access tokens and, with a webhook URL, a new `webhook_secret`; it sets the webhook URL and push mode to the values given, so pass the current ones, or the webhook is removed and the push mode reset to `BANK`. Hand the printed secrets to the bank over a secure channel. Re-registration also re-encrypts the webhook secret in the 2.0 format (bound to the client ID); webhook secrets encrypted by 1.4 still decrypt without it.

   Configure the gateway to send `MTLS_CERT_SHA256_HEADER` before Auth Core 2.0 serves traffic.

7. **Re-provision the admin accounts** with `ADMIN_SECRET_ENCRYPTION_KEY` set:

   ```sh
   node dist/cli/createAdminUser.js <username> <administrator|operator|auditor> --client=<clientId>   # bank-scoped
   node dist/cli/createAdminUser.js <username> <administrator|operator|auditor>                       # platform operator
   ```

   Each run sets the role and bank scope given, sets the password (from `NEXUS_ADMIN_PASSWORD`, or a generated one that is printed), enrols a new TOTP secret and prints `totp_secret` and `totp_uri` once, and ends the account's existing sessions. Accounts from 1.4 have no TOTP secret and cannot log in while `ADMIN_MFA_REQUIRED` is on, and have no bank scope (they see every bank) until re-provisioned with `--client`. Revocation and reactivation of identities now need two admins with access to the same bank, so provision at least two `operator` accounts per bank, or platform operators.

8. **Configure Android attestation** (when Android attestation is configured): `ANDROID_KEY_SECURITY_POLICY` (default `REQUIRE_HARDWARE_BACKED`), `ANDROID_APP_CERT_SHA256`, `ANDROID_REQUIRE_LOCKED_BOOTLOADER` (default on) and `ANDROID_ATTESTATION_STATUS_FILE`. Download the status list and schedule its refresh before starting 2.0 ([runbook](runbooks/android-attestation-status-list.md)).

9. **Recovery protocol 1.** Identities set up under 1.4 are marked `recovery_protocol = 1` by migration 015, and migration 018 deletes their verifiers. Their recovery sessions are refused with 409 `RECOVERY_PROTOCOL_RETIRED`. These customers must set up a new recovery phrase with an app on SDK 2.0 while their device is still enrolled; until then they recover by device replacement after re-identification. Plan the customer communication with the bank.

10. **Set the remaining 2.0 configuration** ([configuration](configuration.md)): `NODE_ENV=production` (now required), `PKCS11_TOKEN_LABEL`, `ADMIN_SECRET_ENCRYPTION_KEY`, `ADMIN_MFA_REQUIRED` unset or `true`, optionally `HSM_SESSION_POOL_SIZE`, `HSM_OPERATION_TIMEOUT_MS`, `BANK_COMMIT_MAX_AGE_SECONDS`, `ADMIN_APPROVAL_TTL_HOURS`, `PUSH_REPLACEMENT_TITLE`, `PUSH_REPLACEMENT_BODY`. Remove `ALLOW_INSECURE_DEVELOPMENT`, and `RECOVERY_V1_ACCEPTED` and `MOBILE_SESSION_TTL_SECONDS`, which no longer exist.

11. **Start Auth Core 2.0.0-rc.2.** Each pod must log `Starting NEXUS-SIGN Auth Core` with `"hsmAdapter":"pkcs11"` and `"env":"production"`, and `/readyz` must return 200. A `Production security posture is not acceptable` or `Invalid environment configuration` exit lists what is missing.

12. **Verify before reopening traffic:**

    - every non-revoked credential has an enrolment record (expected: 0):

      ```sql
      SELECT count(*) FROM credentials WHERE state <> 'REVOKED' AND enrolment_evidence_id IS NULL;
      ```

    - a test bank client obtains a token through the gateway; an unregistered certificate gets 401 and a `bank_certificate_mismatch` audit event;
    - an admin logs in with password and TOTP code;
    - `scripts/e2e-smoke.mjs` passes against the deployment with a test client;
    - one existing identity's evidence chain verifies ([evidence verification](runbooks/evidence-verification-failure.md)).

13. **Reopen traffic.** From here on, roll forward only.

## Rollback

Migrations 013 to 018 have no down scripts, and none is provided. Auth Core 1.4.0 does not run on the migrated schema: migration 013 makes `evidence_records.chain_sequence` mandatory, which 1.4.0 does not write, so 1.4.0 can no longer seal evidence.

| When | Rollback path |
|---|---|
| Before traffic is reopened (step 13) | Restore the backup from step 2, restore the 1.4.0 configuration (`DATABASE_URL`, removed variables) and start 1.4.0. Fingerprints, client secrets and admin passwords changed in steps 6 and 7 revert with the database; the banks go back to their previous secrets. |
| After traffic is reopened | Restoring the backup discards every identity, credential, authorization, evidence record and audit event written since step 2. Banks then hold evidence heads that the restored database does not contain, and their chain checks with `--expect-head` fail for those identities. Treat this as a [disaster recovery](disaster-recovery.md) event, not as a rollback. Prefer fixing forward. |

`scripts/db/roles.sql` changes table ownership; a restore of the pre-upgrade backup brings back the previous owners.

## Breaking changes for bank backends

Details and examples are in the [bank backend integration guide](../integration/bank-backend-guide.md).

| Change | What the bank backend does |
|---|---|
| Client certificate binding (NXS-012) | Tokens are issued and accepted only over a gateway connection with a certificate registered for the client. Register every certificate before it is used; a rollover needs both fingerprints registered. Mismatch: 401 and audit event `bank_certificate_mismatch`. |
| New client and webhook secrets | Only if the operator rotates them with `registerClient` in step 6. |
| BOOTSTRAP for an identity with an enrolled device (NXS-002) | Refused with 409 `ACTIVE_CREDENTIAL_EXISTS`. Pass `replacement: {method, reference}` after re-identifying the customer, use recovery, or revoke the old credential first. |
| Authorization creation (NXS-025) | 409 `CREDENTIAL_NOT_ATTESTED` for a credential whose attestation is not `VERIFIED`; the customer enrols again. |
| Bank commit (NXS-030) | 409 `IDENTITY_NOT_ACTIVE`, `CREDENTIAL_NOT_ACTIVE` or `CONFIRMATION_TOO_OLD` (older than `BANK_COMMIT_MAX_AGE_SECONDS`, default 3600 s). Ask the customer again with a new authorization. |
| Commit check (NXS-020) | Compare `canonicalPayloadHash` of the authorization with the value stored from the 201 creation response before committing. |
| Evidence schema 3 (NXS-004, NXS-005) | Chains contain `CREDENTIAL_ENROLLED` and `RECOVERY_CONFIGURED` records next to `AUTHORIZATION` records. Store the chain head returned with every confirmation and identity read; verify with `scripts/verify-evidence.mjs --expect-head` and `--public-keys`. |
| Recovery protocol 2 (NXS-003) | The recovery session response carries `recoveryPublicKeyPem` and `wrappedRecoveryKey`; forward the whole response to the app. 409 `RECOVERY_LOCKED` after 10 failed proofs in 24 hours, 409 `RECOVERY_PROTOCOL_RETIRED` for protocol 1 identities. |
| New webhooks | `credential.replaced`, `recovery.configured`, `identity.recovered`. A receiver that rejects unknown event types makes those deliveries fail. |
| Integrity failures | A confirmation of a credential that fails the integrity check returns 200 `FAILED` with `reason: credential_integrity`. Treat it as a security incident, not as a customer error. |
| Admin console | TOTP login, bank-scoped accounts, revocation and reactivation answered 202 and executed only after a second admin approves. |
| Bank-side provisioning removed (2.0.0-rc.2) | `POST /v1/nexus-identities/{nexusId}/credentials` and `POST /v1/credentials/{credentialId}/rotate` no longer exist. Devices enrol through the SDK; a new device replaces the old one through device replacement or recovery. |
| No SESSION tokens (2.0.0-rc.2) | `POST /v1/mobile/sessions` with `purpose: SESSION` returns 400. Request only `BOOTSTRAP` tokens. |

## Breaking changes for app teams

| Change | Platforms | Effect |
|---|---|---|
| Android key attestation (NXS-006) | Android | SDK 2.0 sets the attestation challenge and sends `keyAttestation: {signingKeyChain, authenticationKeyChain}`. With `REQUIRE_VALID_ATTESTATION` (production), enrolment and recovery from SDK 1.4 are refused with 403. Keys must meet `ANDROID_KEY_SECURITY_POLICY`; devices with an unlocked bootloader are refused. |
| Recovery protocol 2 (NXS-003) | Both | `POST /v1/mobile/recovery/setup` accepts only protocol 2, so recovery setup needs SDK 2.0. Protocol 1 phrases stop working in production; customers set up a new phrase. Shared vectors: `auth-core/test-vectors/recovery-v2.json`. |
| Secure lock screen (NXS-027) | Android | Enrolment is refused without a secure lock screen (`NoAuthenticationMethodEnrolled`). |
| Device passcode (NXS-027) | iOS | Keys are created with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`; a device without passcode cannot enrol. |
| Biometric change (NXS-026) | iOS | A changed biometric enrolment surfaces as `NEXUSSignError.credentialInvalidated`; the app enrols the device again. Android already reported `CredentialInvalidated`. |
| Emulator HTTP (NXS-028) | Android | `http://10.0.2.2` is accepted only with `allowEmulatorHostHttp = true` in `NEXUSSignConfig` (default `false`). |
| Recovery setup confirmation (NXS-024) | Both | `generateRecoveryPhrase` shows a biometric prompt, because the setup is signed with the signing key. Android: `generateRecoveryPhrase(activity: FragmentActivity)`; iOS: `generateRecoveryPhrase()` unchanged in signature. The prompt text is `recoverySetupPromptText` in `NEXUSSignConfig` (both platforms). |
| Recovery session (NXS-003) | Both | `NexusRecoverySession` has the new fields `recoveryPublicKeyPem` and `wrappedRecoveryKey`. The app passes on the bank backend's session response unchanged; a session without them is refused with `serverError(statusCode: 0, ...)` / `ServerError(0, ...)`. A wrong phrase is now reported before any request. |
| No SESSION tokens (2.0.0-rc.2) | Both | `NEXUSTokenPurpose` has only `BOOTSTRAP`; the token provider is called only by `bootstrap()`. A device enrolled by an SDK before 1.2 (no authentication key) gets `notRegistered` / `NotRegistered` and must be enrolled again through device replacement. |
| Replacement notice (NXS-002) | Both | With `PUSH_DELIVERY_ENABLED`, push mode `NEXUS` and a push registration on the replaced device, that device receives a `SECURITY` message (`PUSH_REPLACEMENT_TITLE`, `PUSH_REPLACEMENT_BODY`, `data.event = DEVICE_REPLACED`) although its credential is already revoked. How the host app presents it is the app team's decision. |

## From 2.0.0-rc.1

1. Before the window: run the `PENDING`/`SUSPENDED`, authentication-key and protocol 1 queries above and resolve what they find.
2. Stop traffic and back up the database (steps 1 and 2).
3. Apply migration 018 as the table owner (`psql "$MIGRATION_URL" -v ON_ERROR_STOP=1 -f migrations/018_remove_unused_schema.sql`), then `scripts/db/roles.sql` again.
4. Remove `RECOVERY_V1_ACCEPTED` and `MOBILE_SESSION_TTL_SECONDS` from the configuration (they are ignored), and start 2.0.0-rc.2. Auth Core and the command-line tools no longer read a `.env` file: supply the configuration as process environment (or `node --env-file=<file>`). A deployment that relied on a `.env` file stops at startup with `Invalid environment configuration` (`NODE_ENV` has no default).
5. Verify as in step 12, and reopen traffic.

Bank backends stop calling the removed endpoints and `purpose: SESSION`; apps move to SDK 2.0.0-rc.2 ([breaking changes](#breaking-changes-for-bank-backends)).

The SDK changes have not been compiled or tested on Apple or Android toolchains in the environment that produced this release candidate; they must be built and tested in CI and on physical devices ([release](release.md)).

## From 2.0.0-rc.2 to 2.0.0

Changes since 2.0.0-rc.2 that an upgrade must handle. Details: [CHANGELOG](../../CHANGELOG.md).

1. **Before the window:**
    - generate `METRICS_BEARER_TOKEN` (`openssl rand -base64 32`) and give it to the monitoring system;
    - with offline confirmation enabled, agree `OFFLINE_CONFIRMATION_MAX_AMOUNT` with the bank (per currency, minor units);
    - bank backends: beneficiary values over 140 characters, empty or padded with spaces are refused with 400 (FI-003); the audio/video completion endpoint takes `{ resultToken }` only (FI-002); receivers must accept the new webhook types `authorization.verified`, `authorization.rejected`, `authorization.expired` and `evidence.appended`;
    - app teams: SDK 2.0.0 refuses signed bytes with beneficiary values the server no longer issues (`invalid_value`); optional `certificatePins`; optional call modules.
2. **Stop traffic and back up** the database (steps 1 and 2 above).
3. **Migrations** 019, 020 and 021 as the table owner, then `scripts/db/roles.sql` again (it grants `nexus_app` DELETE on `device_request_nonces`).
4. **Configuration:** add `METRICS_BEARER_TOKEN`, `OFFLINE_CONFIRMATION_MAX_AMOUNT` (if offline confirmation is enabled) and, for verification calls, `WEBRTC_*` ([audio and video calls](audio-video-calls.md)). Leave `DEVICE_NONCE_STORE` unset (default `postgres`).
5. **Verification channels:** register provider keys or enable operator verification per bank (`verificationSetup.js`); channels without a verifier are no longer offered.
6. **Start 2.0.0** and run the checks of step 12 above.
7. **Optional, any time after the upgrade:** rotate the master keys ([key rotation](runbooks/key-rotation.md)); `rotateSecretKeys.js` also moves secrets written before 2.0.0 to the `k1` format.

Rollback after 2.0.0 has run with traffic: 2.0.0-rc.2 cannot read secrets written in the `k1` format (new webhook secrets, offline keys of devices enrolled after the upgrade, TOTP secrets created or re-encrypted). Restore the backup instead (see [rollback](#rollback)).
