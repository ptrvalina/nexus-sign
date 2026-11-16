# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org/); see [docs/compatibility-and-versioning.md](docs/compatibility-and-versioning.md) for what each version number covers.

## [Unreleased]

### Security

- CI: with `REQUIRE_ALL_INTEGRATION_SUITES=1` (set in the integration job) an integration suite that cannot run for lack of PostgreSQL, Redis or SoftHSM fails instead of skipping. Release: the workflow builds only when the tag equals `v` + `VERSION` and the `ci.yml` and `security.yml` runs for the tagged commit succeeded.
- Evidence for every outcome (audit finding B-04): declined, rejected, expired, cancelled and unsigned authorizations and revoked credentials are sealed into the NEXUS ID's evidence chain (record types `AUTHORIZATION_OUTCOME` and `CREDENTIAL_REVOKED`). A database trigger records each outcome with its reason in the transaction of the state change (migration 025), so no code path can end an authorization without it; the expiry worker seals it. `verify-evidence.mjs` checks and prints the new records. **Integration impact:** chains contain the new record types; a bank verifier built on an older `scripts/lib/evidence.mjs` reports them as unknown and must be updated. Test on PostgreSQL (`evidence-outcomes.test.mjs`, 4 cases).
- The HSM evidence key must have been generated in the HSM and never been extractable or non-sensitive (`CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`), as the master-key KEK already must (audit finding B-02). An imported evidence key, of which a copy may exist outside the HSM, is refused at startup. **Operations impact:** a deployment whose evidence key was imported must generate a new one in the HSM and rotate ([key rotation](docs/operations/runbooks/key-rotation.md)). Tested with a PKCS#11 module double; the SoftHSM suite was not run here.
- HSM (PKCS#11) in a worker thread (audit finding B-01, now closed): the PKCS#11 module runs in its own thread and the service talks to it by messages, so a stalled `C_Login`, `C_OpenSession`, `C_FindObjects` or `C_SignInit` no longer freezes the process. Every call is bounded by `HSM_OPERATION_TIMEOUT_MS`, the queue by `HSM_QUEUE_LIMIT`; consecutive timeouts or a worker crash open a circuit breaker (`HSM_BREAKER_THRESHOLD`, `HSM_BREAKER_COOLDOWN_MS`) that fails closed and makes readiness report the HSM down, and a fresh worker must pass a health check before calls resume. Inside the worker the operation deadline counts synchronous calls, and the session pool is filled at startup. Tested with real worker threads and a PKCS#11 double that stalls synchronously (the event loop's worst gap stays under 100 ms); the SoftHSM suite was not run here. Master-key unwrapping at startup still runs PKCS#11 on the main thread, before the service accepts traffic.
- Authorizations can only be created `PENDING_USER` with bank transaction `PENDING` and nothing confirmed (migration 024, audit finding C-05). The lifecycle trigger checked updates only, so a session with the application's database role could insert a row already `VERIFIED` and `COMMITTED` without a signature, or with any `bank_transaction_state` text. The migration stops, naming the rows, if existing data holds an unknown bank transaction state. Credential inserts are still not checked by the database (they are caught by the runtime integrity check against sealed enrolments).
- Gateway mTLS no longer refuses `POST /v1/mobile/authorizations/{id}/deferred-signature`. With `REQUIRE_MTLS_HEADER` on, the phone could not upload its offline signature, so every offline confirmation ended as `OFFLINE_UNSIGNED` and raised a false security event at the bank. A test now derives the device routes from `openapi.yaml`.
- Device replacement is held (audit finding A2-01). Before, one call by the bank backend enrolled a new device and revoked the customer's, so whoever held the bank backend's credentials could take over any NEXUS ID of that bank. `POST /v1/mobile/sessions` with `replacement` now records a request and answers 202 `REPLACEMENT_PENDING` until the customer approves it on the enrolled device (`POST /v1/mobile/device-replacements/{id}/approve`) or `DEVICE_REPLACEMENT_HOLD_SECONDS` passes (default 86400, production minimum 3600); the customer can cancel it (`…/cancel`). Enrolment uses the request once, in the transaction that revokes the old device. A plain `BOOTSTRAP` for an identity whose device was revoked is refused with 409 `REPLACEMENT_REQUIRED`, so "revoke, then enrol" does not skip the hold. Migration `023_device_replacement_hold.sql`; webhooks `credential.replacement_requested`, `credential.replacement_approved`, `credential.replacement_cancelled`; SDK methods `pendingDeviceReplacements`, `approveDeviceReplacement`, `cancelDeviceReplacement` (iOS and Android; not compiled in this change). **Integration impact:** the bank's enrolment flow must handle 202 and `REPLACEMENT_REQUIRED`; a lost phone without the recovery phrase gets its new device after the hold.
- The bank database verifies the customer's ECDSA P-256 signature, the approved key fingerprint and the bank's own signed approval and revocation statements itself (`bank.p256_verify`, `bank.trust_keys`), instead of trusting values the gateway passes in (audit findings C-02, C-04); a payment is submitted only inside the execution window (`bank.settings.execution_window_seconds`, default 3600; C-03); after a database restore, payments the restore may have re-opened are held until the provider confirms they were not executed (`bank.after_restore`, `bank.restore_marks`; C-01). Tested against OpenSSL (`bank-p256.test.mjs`). **Integration impact:** `installSchema` takes `bankTrustKeys`; existing statements are re-verified at installation.
- `verify-evidence.mjs` no longer reports a chain as plainly valid when its end was not checked (audit finding B-05): a chain export verified without `--expect-head` or `--heads` exits with 4 (`--allow-unchecked-head` restores 0); an empty chain, or one that ends before the `head` the export names, is `INVALID`. **Integration impact:** scripts that ran the verifier on chains without a head now get exit 4.
- A recovery phrase recovers an identity once, and the old device is told (audit finding A2-02). After a recovery, new recovery sessions and sessions opened before it answer 409 `RECOVERY_PHRASE_USED` until the recovered device sets up a new phrase; the old device gets the `SECURITY` replacement notice in push mode `NEXUS`. Before, the old device lost its credential silently and the same (possibly phished) phrase could recover the identity again. **Integration impact:** the bank's app must ask the customer to set up a new phrase after a recovery.
- Verification calls are listed, claimed and decided only by operators of the customer's bank; platform accounts without a bank (`createAdminUser` without `--client`) no longer see or decide any bank's calls (audit finding A2-03). `run-local.sh` creates a bank operator `operator` for local calls.
- The in-memory development HSM adapter is refused unless the process runs outside production with `ALLOW_INSECURE_DEVELOPMENT=true`, for every caller including `sealCredentialBaseline` (audit finding B-03). Before, that CLI run with `HSM_ADAPTER` unset sealed permanent records with a key lost at exit.
- Display text rules for the beneficiary and `transaction_reference` (authorization protocol v1, [display text rules](docs/protocol/authorization-protocol-v1.md#display-text-rules)): NFC and no compatibility characters (NFKC-stable); U+0020 as the only space, never doubled or at either end; ASCII digits only; no mix of Latin, Cyrillic, Greek, Armenian and Cherokee letters in one value; `iban` with check digits 02–98 that verify and `bic` in ISO 9362 format; applied to beneficiary values, `transaction_reference` and `operation_type`. Enforced by Auth Core when an authorization is created and by both SDKs and the sandbox on the signed bytes. Seventeen new invalid vectors; the valid vector that signed a Latin/Cyrillic look-alike name now uses a name written only in Cyrillic. **Integration impact:** a bank that sent such values gets 400 `VALIDATION_ERROR` and must send IBANs without spaces.

### Added

- Bank console screens for one customer's mandates and devices ([bank console](docs/operations/bank-console.md)). Mandates: list, terms, limits, state, debits allowed and refused, sealed evidence records, event log with reason and staff member; hold (a bank hold the customer cannot lift, 409 `MANDATE_HELD_BY_BANK`), release by a second member of staff (409 `SAME_STAFF_MEMBER` for the one who held it), withdraw. Devices: list with key protection, attestation, added on and why, last use; history of additions and replacements; the bank's device limit; security events; revoke a device; stop an open device request. Auditors and platform accounts read only; staff of another bank see nothing; every view and change is audited under the staff member's name. Test on PostgreSQL (`bank-console.test.mjs`, 4 cases); the HTTP routes and the screen were not run here.
- Shared vectors for payment mandate terms (`auth-core/test-vectors/mandate-terms-v1.json`, 3 valid, 15 invalid, with the iOS copy): Auth Core's encoder must produce the valid bytes exactly (`mandates.test.mjs`), and the Android SDK's pure-Kotlin `MandateTermsParser` must accept them field for field and refuse the others with the expected reason (`MandateTermsVectorsTest`). `android-sdk/scripts/jvm-core-tests.sh` compiles the SDK's platform-independent core with the Kotlin compiler of a Gradle distribution and runs its JVM tests (17) without an Android SDK; it is not the Android build.
- iOS and Android SDK methods for the customer's section (`devices`, `removeDevice`, `history`, `evidence`, `securityEvents`, `notifications`, `settings`, `updateSettings`, `suspendIdentity`), payment mandates (`mandates`, `mandate`, `mandateTerms`, which checks the domain, the mandate, the device, the display rules and the terms hash before anything is shown, `signMandate` with the biometric prompt built from the signed terms, decline, suspend, resume, revoke) and conversations (`conversations`, `openConversation`, `conversationMessages`, `sendMessage`, `markRead`, `requestAgent`, `closeConversation`). **Not compiled in the environment where they were written** (no Xcode or Gradle); the CI SDK jobs must build them before use.
- Conversations with the bank inside the bank's app ([conversations](docs/architecture/customer-conversations.md), migration 029): the customer writes from an enrolled device, the bank's own bot answers through the bank API (`/v1/conversations/{id}/bot-messages`) and hands over, an operator of that bank takes the conversation in the console and answers. Messages are idempotent, numbered under a lock, hash-chained (`GET /v1/conversations/{id}/integrity`), append-only, with delivery and read marks set once; attachments are bank-stored references with a SHA-256. Tests on PostgreSQL (4).
- Recurring payment mandates ([payment mandates v1](docs/protocol/payment-mandates-v1.md), migration 028): the bank proposes (`POST /v1/mandates`), the addressed device signs the canonical terms (domain `NEXUS-SIGN/MANDATE`), the customer declines, suspends, resumes or revokes from any active device, the bank withdraws but cannot change terms, and asks before each debit (`POST /v1/mandates/{id}/debits`, idempotent per `debitReference`), which is allowed only inside the signed terms by Auth Core and again by the database trigger `mandate_debits_check`. Every event is sealed as a `MANDATE` evidence record, which `verify-evidence.mjs` checks. The bank database executes a mandate debit only after verifying the signed terms, the device signature, the bank-approved key, the stop list, the period and the total limit itself (`bank.attach_mandate`, `bank.mandate_problem`, `bank.mandate_debits`, `bank.record_mandate_stop`). Tests on PostgreSQL (8 + 5).
- Several active devices per NEXUS ID (migration 027), up to the bank client's `max_devices_per_identity` (1 to 10, default 1, `cli/setDevicePolicy.js`). A further device is enrolled with `addition` on `POST /v1/mobile/sessions` (202 `ADDITION_PENDING` until an active device approves or the hold passes; webhooks `credential.addition_requested`, `credential.added`); it revokes nothing. The customer removes a device from any active device (`POST /v1/mobile/devices/{credentialId}/revoke`). The database enforces the limit with the identity row locked (trigger `credentials_device_limit`, replacing the unique index `idx_credentials_one_active`). **Compatibility:** with the default limit nothing changes for an existing bank. Tests on PostgreSQL (6).
- The customer's own section for the bank's app (presentation pages 19 to 22), device-signed: `GET /v1/mobile/devices`, `/history` (confirmed, declined, open), `/authorizations/{id}/evidence` (the sealed record of the customer's own payment), `/security-events`, `/notifications` (event feed), `GET`/`PUT /v1/mobile/settings` (per-payment and daily limits, the amount above which a video check is required, channel preferences) and `POST /v1/mobile/identity/suspend`. Settings are versioned and append-only (migration 026); a change that relaxes them applies after `CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS` (default 24 h, production minimum 1 h), tightening applies at once; limits are enforced when the bank creates an authorization, with the identity row locked so concurrent payments cannot pass the daily limit together. Bank API: `POST /v1/nexus-identities/{id}/suspend`, `/reactivate` (with the re-identification method and case reference) and `GET /v1/nexus-identities/{id}/devices`. Tests on PostgreSQL (7).
- Migration tool with a ledger (`npm run migrate`, audit finding C-06): installs from an empty database, adopts an existing database only at a stated version (`--adopt-at`), refuses changed, missing or out-of-order migrations, applies each migration with its ledger row in one transaction under an advisory lock; `--check` reports without changes. `schema.sql` states its version; `check-repository.sh` checks it. **Operations impact:** the first upgrade of an existing database runs with `--adopt-at 022` (2.0.0-rc.2). Tested on PostgreSQL, including an upgrade of the real 2.0.0-rc.2 schema compared with a fresh installation.
- `POST /v1/nexus-identities` is safe to retry (audit finding A1-04): when a non-revoked identity already exists for the same bank client and `bankCustomerRef`, it is returned with 200 and `replayed: true`. Before, a retry after a lost response got 409 without the NEXUS ID, and the bank could neither learn the ID nor create another. **Integration impact:** a bank that treated 409 as "duplicate customer" now gets 200 with the existing `nexusId`; 201 still means created. Test on PostgreSQL (`identity-create-retry.test.mjs`, fails on the old code).
- The customer can decline a payment on the enrolled device (`POST /v1/mobile/authorizations/{id}/decline`, reason `NOT_ME`, `WRONG_DETAILS` or `OTHER`; SDK `decline(authorization:reason:)`), and the bank can withdraw a pending one (`POST /v1/authorizations/{id}/cancel`). The authorization becomes `REJECTED` or `CANCELLED` under its row lock, open verification plans and calls end, and webhooks `authorization.declined` / `authorization.cancelled` tell the bank; a signature arriving afterwards fails (audit finding A1-03). SDK methods not compiled in this change.

- `demo/`: demo host apps for iPhone (`demo/ios`, Xcode project; CI job `ios-demo` builds it) and Android (`demo/android`; CI job `android-demo` builds the `nexus-sign-demo-apk` artifact), and a demo bank backend (`demo/bank-backend/demo-bank.mjs`) with an operator page and a device port that forwards only the device endpoints of Auth Core, for trying enrolment and payment signing on a real phone ([demo/README.md](demo/README.md)).
- `auth-core/scripts/run-local.sh`: runs Auth Core with PostgreSQL and Redis from `docker-compose.yml` on one machine in development mode (fresh database, schema and roles, bank client, admin account with TOTP, service on port 8080).
- Auth Core: webhooks `authorization.verified` (with the evidence position and the chain head the bank keeps for truncation checks), `authorization.rejected` and `authorization.expired`.
- Auth Core: a periodic sweep moves `PENDING_USER` authorizations past their expiry to `EXPIRED`, with their verification plan and open sessions (`AUTHORIZATION_EXPIRY_SWEEP_MS`).
- Auth Core: audio and video results are accepted only as a provider result token (ES256 JWS) that Auth Core verifies against a key registered for the bank, bound to the session, authorization, transaction terms, device credential and session nonce, fresh and single-use ([verification result v1](docs/protocol/verification-result-v1.md)); or as an operator decision in the admin console. Migration `019_verification_results.sql`; operator CLI `verificationSetup.js`.
- Auth Core: a verification channel is offered only if the bank has a verifier for it; a requirement no channel can meet is refused with 409 `VERIFICATION_CHANNEL_UNAVAILABLE`.
- In-app audio and video calls ([ADR 0017](docs/adr/0017-in-app-audio-video-calls.md)): Auth Core relays WebRTC signalling between the customer's device (`/v1/mobile/verification-sessions/{id}/call`, `/signals`, `/cancel`) and a bank operator in the admin console (Verification calls panel, `/admin/api/verification-calls`), issues per-session TURN credentials (`WEBRTC_*`), and records the operator's decision. A declined or unanswered call verifies nothing; at most three sessions per channel. Real media between two browsers is tested in `test/media/webrtc-call.test.mjs` (CI job `auth-core-media`). Operations: [docs/operations/audio-video-calls.md](docs/operations/audio-video-calls.md).
- Auth Core: master key rotation for stored secrets. Secrets name the master key that encrypted them (`k1$<key id>$...`); `WEBHOOK_/DEVICE_/ADMIN_SECRET_ENCRYPTION_KEY_PREVIOUS` list old keys accepted for decryption; `cli/rotateSecretKeys.js` (`npm run rotate-secret-keys`) re-encrypts every stored secret under the current key after checking that all of them decrypt. Migration `020_secret_key_rotation.sql` lets only that tool replace a credential's offline key ciphertext. Runbook: [key rotation](docs/operations/runbooks/key-rotation.md).
- Auth Core: master keys wrapped by an HSM key-encryption key. With `MASTER_KEY_SOURCE=hsm` (required in production) the configuration holds only `*_WRAPPED` values (AES-256-GCM made in the HSM, bound to the key's name), and Auth Core and its tools unwrap them in the HSM at startup; startup fails closed when they cannot be unwrapped. `cli/masterKeys.js` creates the KEK on SoftHSM and generates, migrates, re-wraps (KEK rotation) and checks wrapped keys without printing key material. [Key management](docs/engineering/KEY_MANAGEMENT.md).
- Auth Core: `OFFLINE_CONFIRMATION_MAX_AMOUNT` caps, per currency, what an offline code may confirm; above the cap no QR challenge is issued (409 `OFFLINE_LIMIT_EXCEEDED`) and a code is refused without using an attempt.
- Auth Core: `OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY` limits offline confirmations per credential; required in production with offline confirmation. Threat model: [offline confirmation](docs/security/offline-confirmation-threat-model.md).
- Auth Core: device request nonces are kept in PostgreSQL (`DEVICE_NONCE_STORE=postgres`, default; migration `021_device_request_nonces.sql`), so a Redis failover or restore cannot re-enable a replay. `scripts/db/roles.sql` grants `nexus_app` DELETE on that table for the expiry sweep.
- Auth Core: webhook `evidence.appended` with every new HSM-sealed chain head; `verify-evidence.mjs --heads=<file>` checks an export against the heads the bank kept and reports a removed tail.
- Auth Core: `METRICS_BEARER_TOKEN` protects `GET /metrics`.
- SDKs: in-app verification calls. The core SDKs open the session (`openVerificationCall`), provide device-signed signalling (`callSignalling`) and the call state machine (`VerificationCallController`: offer first, candidate buffering, ICE restart, retries with `messageId`, endings from the server's bye or the session expiry), without a WebRTC dependency. Optional modules `android-sdk-calls` (`com.nexis:nexus-sign-android-calls`) and `ios-sdk-calls` (`NEXUSSignCalls`) add libwebrtc media, run-time permissions, a call screen with camera and microphone indicators, and lifecycle handling. The WebRTC binaries have development approval only ([THIRD_PARTY_MEDIA.md](docs/engineering/THIRD_PARTY_MEDIA.md)).
- Auth Core: `POST /admin/api/verification-calls/{id}/release`: the operator hangs up without a result; the session is cancelled and the customer is told.
- Demo: payments can require an audio or video call (operator page); both demo apps place the call before signing.
- CI: jobs `android-sdk-calls`, `ios-sdk-calls` (module builds against the pinned WebRTC binaries, recording their checksums) and `sdk-call-conformance` (the Android SDK's call state machine against Auth Core).
- SDKs: optional TLS public-key pinning, `certificatePins` in `NEXUSSignConfig` on iOS and Android (`sha256/<base64 SPKI hash>`, at least two pins).
- Demo bank: the demo app's calls need the pairing code shown on the operator page; the iOS and Android demo apps ask for it. CI job `demo-bank` tests it.
- Offline confirmation v2, deferred device signature ([ADR 0018](docs/adr/0018-deferred-device-signature.md), [protocol](docs/protocol/offline-confirmation-v2-deferred-signature.md)). With `OFFLINE_CONFIRMATION_MODE=deferred_signature` (default, required in production) the QR is `NXS2.`, the phone signs the canonical bytes with its signing key before showing the code, and uploads the signature later (`POST /v1/mobile/authorizations/{id}/deferred-signature`). A correct code alone gives `PROVISIONAL` (state `OFFLINE_PROVISIONAL`); the signature makes it `VERIFIED` with `confirmationMethod: OFFLINE_SIGNED`; without it by `OFFLINE_SIGNATURE_DEADLINE_HOURS` (default 72), or when the credential or identity is no longer active, the state becomes `OFFLINE_UNSIGNED`. Webhooks `authorization.offline_provisional` and `authorization.offline_unsigned`. Migration `022_offline_deferred_signature.sql`. SDKs: `NexusOfflineChallenge.requiresDeviceSignature`, `submitPendingOfflineSignatures()`. `verify-evidence.mjs` verifies `OFFLINE_SIGNED` records and refuses code-only records with `--reject-offline-code`.

### Changed

- Auth Core: `bank-commit-request` re-verifies the authorization's sealed evidence before it accepts (HSM seal, binding to the authorization and its stored terms, device signature with the key sealed at enrolment; on a v2 deployment no code-only `OFFLINE_CODE` record); otherwise 409 `EVIDENCE_INVALID` and an `integrity_violation` audit event.
- Auth Core: `GET /v1/authorizations/{id}` and the webhooks `authorization.verified`, `authorization.offline_provisional` and `authorization.offline_unsigned` carry `confirmed` (true only for `VERIFIED`).
- Auth Core: `OFFLINE_CONFIRMATION_MODE=immediate` is a development setting: outside production it needs `ALLOW_INSECURE_DEVELOPMENT=true`.

- Offline confirmation: with offline confirmation enabled and `OFFLINE_CONFIRMATION_MODE` unset, a correct code now returns `PROVISIONAL` instead of `VERIFIED` (v2 is the default). Set `OFFLINE_CONFIRMATION_MODE=immediate` outside production to keep the previous behaviour. SDKs up to 2.0.0 refuse the `NXS2.` QR code.
- Database: `policy_reference` and `policy_version` of an authorization are immutable (trigger, migration 022).
- HSM: the key-encryption key must have `CKA_LOCAL` and `CKA_NEVER_EXTRACTABLE` (generated in the HSM); an imported KEK is refused at startup.

- **Breaking:** `POST /v1/authorizations/{id}/verification-sessions/{sessionId}/complete` takes `{ "resultToken": "<JWS>" }`. The previous body (`sessionNonce`, `result`, `providerReference`, `assertion`), whose assertion Auth Core did not verify, is refused with 400. `scripts/e2e-smoke.mjs` needs `NEXUS_SIGN_SMOKE_PROVIDER_KEY`.
- **Breaking:** `audioAvailable`/`videoAvailable` no longer default to available: a channel needs a registered provider key or operator verification (`verificationSetup.js`).
- **Breaking:** beneficiary values are limited to 140 characters (was 512) and must not be empty or start or end with a space; Auth Core refuses such authorizations with 400, and the SDKs refuse signed bytes that contain them (`invalid_value`).
- SDKs: the beneficiary display and the biometric prompt text put the account identifier (`iban`, `account`, `account_number`) before the name; the prompt text is `<amount> <currency> → <beneficiary>` and `<operation type> • <reference>` on the second line, identical on both platforms and in the test vectors.
- **Production configuration:** `MASTER_KEY_SOURCE=hsm` with `PKCS11_KEK_LABEL` and wrapped master keys; plaintext master keys are refused in that mode.
- **Production configuration:** startup in production now also requires `METRICS_BEARER_TOKEN` (at least 32 characters), `DEVICE_NONCE_STORE=postgres` (the default) and, with offline confirmation enabled, `OFFLINE_CONFIRMATION_MAX_AMOUNT`. See [upgrade to 2.0](docs/operations/upgrade-2.0.md).
- Stored secrets written by 2.0.0 use the `k1` format; an Auth Core before 2.0.0 cannot read them, so a downgrade after 2.0.0 has written secrets needs a database restore.
- Auth Core call signalling enforces the order of messages (only the device offers, one outstanding offer, only the operator answers, candidates after the sender's description, nothing after bye: 409 or 400 otherwise), accepts an optional `messageId` (a retry returns 200 with the original `seq`), and relays a `bye` from `server` when the session or authorization is closed elsewhere. Redis keys of a call share a Cluster hash tag.
- Evidence: verification factors carry `method` (`PROVIDER` or `OPERATOR`) and `issuer`.
- Auth Core: `GET /v1/authorizations/{id}` and `GET /v1/mobile/authorizations/{id}` report `EXPIRED` as soon as `expiresAt` has passed, instead of `PENDING_USER` until the next confirmation attempt.
- Auth Core: shutdown waits up to `SHUTDOWN_DRAIN_MS` for requests in flight before closing the HSM, database and Redis.
- Auth Core: a NEXUS ID collision between concurrent identity creations retries with a new ID instead of reporting a duplicate customer.
- Auth Core: the webhook destination check runs in the caller's transaction, so a webhook queued while row locks are held does not need a second pool connection.
- iOS SDK tests: the recovery tests read the vector's iteration count as a number (the forced string cast stopped the test process).
- Auth Core image: the runtime stage removes npm, npx, corepack and yarn shipped with the base image; the service runs with `node` only.
- CI: CodeQL keeps its results as the `codeql-sarif` artifact and does not upload them to code scanning, which private repositories can use only with GitHub Code Security. `.github/codeql/gate.mjs` fails the job on any result of security severity 7.0 or higher that is not listed, with its reason, in `.github/codeql/reviewed-findings.tsv`.
- Auth Core: the `Authorization` patterns for recovery Bearer tokens and OAuth Basic credentials match a single value without spaces in linear time (the previous patterns backtracked polynomially on long runs of spaces). The admin session cookie parser keeps cookie names in a `Map`, not as object properties.
- Tests: the SoftHSM capability probe runs with a configuration of its own; its script did not parse, so the HSM suites ran, and failed with `CKR_MECHANISM_INVALID`, on SoftHSM builds without `CKM_ECDSA_SHA256` instead of being skipped.
- Secret scan: the gitleaks allowlist covers all shared test vectors and their iOS copies, the Android key attestation fixtures, `.env.example` templates and PKCS#11 constant names.

## [2.0.0-rc.2] - 2026-10-07

Second release candidate. Removes compatibility paths and schema that only development or 1.x data used ([ADR 0016](docs/adr/0016-remove-compatibility-paths.md)). Upgrade steps, including from 2.0.0-rc.1: [docs/operations/upgrade-2.0.md](docs/operations/upgrade-2.0.md).

### Removed

- Bank-side credential provisioning and rotation: `POST /v1/nexus-identities/{nexusId}/credentials` and `POST /v1/credentials/{credentialId}/rotate` (unattested keys; available only without `REQUIRE_VALID_ATTESTATION`). Devices enrol through `POST /v1/mobile/bootstrap`; a new device replaces the old one through device replacement or recovery.
- Recovery protocol 1 and `RECOVERY_V1_ACCEPTED`. Identities still on protocol 1 are always refused with 409 `RECOVERY_PROTOCOL_RETIRED` and set up a new phrase. Migration 018 drops the stored protocol 1 verifiers (`nexus_identities.recovery_verifier`).
- `SESSION` mobile tokens and `MOBILE_SESSION_TTL_SECONDS`. `POST /v1/mobile/sessions` issues only `BOOTSTRAP` tokens (`purpose: SESSION` returns 400); enrolment and recovery require `authPublicKeyPem` and always answer `requestAuthentication: DEVICE_SIGNATURE`; tokens issued by earlier versions are refused. Devices enrolled by SDKs before 1.2 must be enrolled again through device replacement. SDKs: `NEXUSTokenPurpose` has only `BOOTSTRAP`.
- Unused schema (migration 018): tables `attestation_records` and `policy_decisions`; authorization states `CREATED`, `DELIVERING`, `SIGNED`, `CONSUMED`; credential states `PENDING`, `SUSPENDED` and `credentials.suspended_at`. The migration stops, naming the rows, if data uses any of them.
- Dependencies: `dotenv` (Auth Core reads only the process environment; development uses `node --env-file=.env`), `ts-node`, `ts-node-dev`; Android `androidx.core:core-ktx`, `kotlinx-coroutines-test`.
- Copies of the shared test vectors in the Android SDK and the sandbox, which now read `auth-core/test-vectors/` directly. The iOS copies remain and are checked by `test-vectors/check-vector-copies.mjs`.

### Changed

- iOS SDK: PBKDF2 for the recovery phrase uses CommonCrypto `CCKeyDerivationPBKDF` instead of a hand-written loop (same output, pinned by the recovery vectors).
- CI: the dependency audit and secret scan moved to `security.yml` (job `audit`); the separate `repository` job was removed (hygiene runs in `npm run check:all`).
- `unregisterPush()` (both SDKs) deletes the local push key even when the request to Auth Core fails.
- `openapi.yaml` describes only the remaining authentication: device signatures for enrolled devices, single-use BOOTSTRAP and recovery tokens.
- Repository hygiene refuses Redis snapshots (`*.rdb`).
- Node.js 22 or later is required (Node.js 20 is end of life, and its test runner does not expand `test/*.test.mjs`, so `npm test` failed on it); CI tests Node.js 22 and 24.
- Windows: the test harness, vector tools and route check resolve their own paths with `fileURLToPath` (a `URL.pathname` such as `/C:/...` is not a Windows path), and the test servers inherit `SystemRoot`, `TEMP` and `TMP`.
- Tests: the evidence verifier's exit codes (0 with keys passed out of band, 3 with the export's own keys, 1 with a foreign key) are covered by a regression test; migration 018's refusals and the narrowed CHECK constraints are tested directly.
- Documentation: protocol specifications in `docs/protocol/`; security model and threat model merged; attestation documents merged into `docs/security/attestation.md`; sandbox documents merged into `sandbox/README.md` and `sandbox/HOSTING.md`.

## [2.0.0-rc.1] - 2026-10-07

Release candidate. A major version: several `/v1` behaviours, the recovery protocol and the evidence format change in place as security fixes, under the security clause of the deprecation policy ([compatibility and versioning](docs/compatibility-and-versioning.md)). Upgrade steps: [docs/operations/upgrade-2.0.md](docs/operations/upgrade-2.0.md). What was and was not verified for this candidate: [docs/operations/verification-status.md](docs/operations/release.md).

### Security

- Recovery protocol 2 replaces the protocol 1 verifier, which worked as a password for anyone who could read it. The device generates a P-256 recovery key and registers only its public key and the private key wrapped under the phrase (PBKDF2, HKDF, AES-256-GCM); the registration is signed with the biometric signing key; a recovery proof is an ECDSA signature bound to the session, the nonce and the new signing key. Auth Core checks at session creation and completion that the stored configuration is the identity's latest sealed one, with the sealed salt and iteration count. Protocol 1 is refused unless `RECOVERY_V1_ACCEPTED` (a production blocker). Ten failed proofs in 24 hours lock recovery for the identity (409 `RECOVERY_LOCKED`). Specification: `docs/architecture/recovery-protocol-v2.md`; shared vectors `test-vectors/recovery-v2.json`.
- A `BOOTSTRAP` token for an identity that has an enrolled device is refused (409 `ACTIVE_CREDENTIAL_EXISTS`) unless the bank passes `replacement { method, reference }`. A replacement revokes the old credential, notifies the old device by secure push where push mode `NEXUS` is used, sends the `credential.replaced` webhook and is sealed in the evidence chain.
- Evidence schema 3: enrolment and recovery configuration records seal each credential's keys and attestation, every record has a sealed chain position and sealing key ID, and the chain head is returned to the bank with every confirmation. Auth Core checks a credential's keys against its sealed enrolment on every device request and confirmation (`integrity_violation`). The verifier takes `--public-keys` (current and retired keys) and `--expect-head`; without `--public-keys` it reports `EVIDENCE_SELF_CONSISTENT` and exits with code 3; a single authorization export must carry its enrolment record.
- Android Keystore key attestation is verified for every hardware key: certification path to the pinned Google roots (CA and key usage constraints, path length, no attested key as an issuer), revocation status list, KeyDescription challenge, package and signing certificate, biometric requirement of the signing key and locked bootloader. Policy `ANDROID_KEY_SECURITY_POLICY` (`REQUIRE_STRONGBOX`, `REQUIRE_HARDWARE_BACKED`, `ALLOW_TEE`, `ALLOW_SOFTWARE`). Platform and security level are taken from verified attestation, not from the request.
- Bank tokens are bound to the client certificate: the gateway forwards the verified certificate's SHA-256, and token issuance and every bank call require a fingerprint registered for that client.
- Admin console: accounts are scoped to one bank or the platform; revocation and reactivation need a second admin; TOTP is required (`ADMIN_MFA_REQUIRED`, a production blocker if off); a password or TOTP reset ends existing sessions; 30-minute idle timeout; cross-origin state changes are refused.
- Audit records carry the bank, the actor, the source address and the user agent, include logins, token issuance and admin reads of personal data, and cannot be updated, deleted or truncated.
- The database enforces the authorization, bank transaction, credential, identity and recovery session lifecycles, keeps the authorized transaction and credential keys immutable, refuses deleting security history and allows one `ACTIVE` credential per identity. `scripts/db/roles.sql` runs the service as a role that owns nothing.
- Production posture: `NODE_ENV` is required; development settings need `ALLOW_INSECURE_DEVELOPMENT=true` outside production; master keys are validated at startup; TTLs are bounded.
- PKCS#11: session pool, operation timeouts, retry once on a lost session, module re-initialisation, unique token and key selection with attribute checks; a missing output buffer in `C_Sign` that broke every seal is fixed.
- A bank commit is refused when the identity or the confirming credential is no longer `ACTIVE` or the confirmation is older than `BANK_COMMIT_MAX_AGE_SECONDS`.
- With `REQUIRE_VALID_ATTESTATION`, a credential without verified attestation cannot approve new transactions (409 `CREDENTIAL_NOT_ATTESTED`).
- Lone UTF-16 surrogates are refused in displayed fields; device nonces are remembered for 2 x skew + 60 s; webhook secrets are bound to their bank client as associated data; admin passwords use scrypt N=2^17 and are upgraded at the next login; APNs `DEVELOPMENT` registrations are refused in production; `trust proxy` normalises IPv4-mapped addresses.
- Webhook delivery works on Node.js 20 and later (the pinned DNS lookup now answers `all: true` requests).
- iOS SDK: keys require a device passcode; a changed biometric enrolment is reported as `credentialInvalidated`. Android SDK: enrolment requires a secure lock screen; `http://10.0.2.2` only with `allowEmulatorHostHttp`.
- Sandbox: the login failure tracker is bounded; sign-out survives a restart with `SANDBOX_REVOKED_SESSIONS_FILE`.

### Added

- Migrations 013 to 017. CLIs `sealCredentialBaseline`, `setClientCertificates`; `createAdminUser --client=<bank>` enrols a TOTP secret. Admin API `GET /admin/api/approvals`, `POST /admin/api/approvals/{id}/approve|reject`.
- Configuration: `ALLOW_INSECURE_DEVELOPMENT`, `PKCS11_TOKEN_LABEL`, `PKCS11_EVIDENCE_KEY_ID`, `HSM_SESSION_POOL_SIZE`, `HSM_OPERATION_TIMEOUT_MS`, `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM`, `RECOVERY_V1_ACCEPTED`, `PUSH_REPLACEMENT_TITLE`, `PUSH_REPLACEMENT_BODY`, `ANDROID_KEY_SECURITY_POLICY`, `ANDROID_REQUIRE_LOCKED_BOOTLOADER`, `ANDROID_APP_CERT_SHA256`, `ANDROID_ATTESTATION_STATUS_FILE`, `ADMIN_MFA_REQUIRED`, `ADMIN_SECRET_ENCRYPTION_KEY`, `ADMIN_APPROVAL_TTL_HOURS`, `MTLS_CERT_SHA256_HEADER`, `BANK_COMMIT_MAX_AGE_SECONDS`.
- Webhooks `credential.replaced`, `recovery.configured`, `identity.recovered`. Error `code` values for 409 responses.
- Integration suites against PostgreSQL, Redis and SoftHSM; seeded property and fuzz tests; CI jobs for the integration suites; security workflow (CodeQL, SBOM, Trivy) and release workflow (SBOM, build provenance).
- Documentation: ADRs 0009 to 0015, recovery protocol 2, state machines, device replacement, Android key attestation, upgrade guide, incident response, disaster recovery, attestation status list runbook.

### Changed

- `POST /v1/mobile/recovery/setup` accepts only protocol 2; recovery session responses carry `recoveryPublicKeyPem` and `wrappedRecoveryKey`; `generateRecoveryPhrase` needs biometric confirmation (Android: an activity).
- CI installs dependencies with `npm ci` only, and the image build requires `package-lock.json`. The lockfile is not part of this candidate and must be generated with registry access; until then those jobs fail.

### Known limitations

- The iOS and Android changes were not compiled or tested in the environment that produced this candidate.
- Not addressed: audio and video verification remain the bank's or provider's assertion; Redis replication requirements are documented, not enforced; App Attest assertions per operation; optional TLS key pinning in the SDKs; Gradle checksums and image digests.

## [1.4.0] - 2026-10-01

### Added

- Secure push (push mode `NEXUS`, package Full Pack): Auth Core delivers authorization requests and the bank's own notifications (incoming and outgoing payments, card spending, account and security notices) to the bank's app through APNs and FCM. Specification: `docs/architecture/secure-push.md`, decision record 0008.
  - Each message is sealed for one device with AES-256-GCM under a push key agreed by ECDH P-256 when the app registers. APNs receives a generic alert and the envelope, FCM a data-only message; the category is not sent and the plaintext is never stored.
  - The device confirms delivery with an HMAC receipt under the push key (`POST /v1/push-receipts/{id}`), which also works from the iOS notification service extension while the phone is locked.
  - Bank API: `POST /v1/push-messages`, `GET /v1/push-messages/{id}`; the authorization request push is queued in the transaction that creates the authorization (`pushNotification`, `push` in the response). Webhooks `push.delivered`, `push.failed` and `push.timeout`.
  - Mobile API: `POST` and `DELETE /v1/mobile/push-registration`, `GET /v1/mobile/push-messages/{id}`.
  - iOS SDK: `registerPush`, `unregisterPush`, `openPush`, `fetchPushMessage`, `confirmPushReceipt`, and `NEXUSSignPushReader` for the notification service extension; `pushKeychainAccessGroup` in `NEXUSSignConfig`.
  - Android SDK: `registerPush`, `unregisterPush`, `openPush`, `fetchPushMessage`, `confirmPushReceipt`; no Firebase dependency in the SDK.
  - Push mode per bank client (`register-client --push-mode=BANK|NEXUS`, default `BANK`), shown in the admin console.
  - Configuration `PUSH_DELIVERY_ENABLED`, `APNS_*`, `FCM_*`, `PUSH_MESSAGE_TTL_SECONDS`, `PUSH_ALERT_*`, `PUSH_AUTHORIZATION_*`; startup refuses a partly configured provider.
  - Metric `nexus_push_delivery_outcomes_total`; push delivery runbook.
  - Shared vectors `test-vectors/secure-push-v1.json`, run by Auth Core and both SDKs.
- Migration 012 (`push_mode`, `push_registrations`, `push_messages`).

### Changed

- Google service account access tokens are cached per service account and scope.
- `scripts/check-openapi-routes.mjs` also checks `PUT`, `PATCH` and `DELETE` routes.

### Fixed

- Documentation: `/readyz` includes the HSM self-test (monitoring guide), and the webhook runbook describes the 1.3 handling of webhook secrets that cannot be decrypted.

## [1.3.0] - 2026-10-01

### Security

- Auth Core: request logs no longer contain credentials. `Authorization`, `Cookie`, `X-NEXUS-Signature` and `Set-Cookie` headers are redacted.
- Auth Core: OAuth tokens, mobile tokens and admin sessions are stored in Redis under the SHA-256 of the token. Tokens issued before the upgrade stop working; clients obtain new ones as after expiry.
- Auth Core: a SESSION token is bound to the credential that was active when it was issued and stops working when that credential is revoked, rotated or replaced. Mobile and recovery requests are refused for a DISABLED bank client.
- Auth Core: consuming an authorization re-checks the verification plan, the expiry and the credential state in one transaction, with the plan row locked before the authorization row, so a step-up escalation that commits at the same moment as a signature takes effect.
- Auth Core: revoking a credential cancels its pending authorizations.
- Auth Core: the PKCS#11 adapter accepts only canonical DER signatures, so the HSM verdict and the offline evidence check agree.
- Protocol: displayed text may not contain control, format (bidi, zero-width) or line and paragraph separator characters (Unicode Cc, Cf, Zl, Zp). Auth Core refuses such values when an authorization is created; both SDKs and the sandbox refuse signed bytes that contain them. Four invalid vectors pin the rule.
- SDKs: amounts use a fixed ISO 4217 minor-unit table instead of the platform currency data, which follows CLDR and differs for several currencies (for example RSD and IQD).
- SDKs: `approve()` refuses an authorization addressed to another credential (`wrong_device`); the recovery session ID must be a UUID; enrolment and recovery run one at a time per process; `baseUrl` must use HTTPS except for a loopback address.
- iOS: while a key replacement is pending, the confirmed replacement key takes precedence over the previous one.
- Sandbox: `X-Forwarded-For` is used only for requests from a loopback or private address; access codes need at least 22 characters with some variety; evidence verification runs outside the shared lock.
- Admin console: a username is locked only after 50 failures across all addresses, so a stranger cannot lock out an operator; the per-address limits are unchanged.
- CI: GitHub Actions are pinned to commit SHAs and the gitleaks download is checked against its published checksum.

### Added

- Threat model, architecture decision records, configuration reference, monitoring guide, runbooks, bank backend integration guide, error and data model references, glossary, and the compatibility and versioning policy (`docs/`).
- `GET /v1/credentials/{id}` returns `offlineEnabled` and `deviceSignedRequests`.
- `/readyz` includes the HSM self-test, cached for 30 seconds.
- SDK version constants (`NEXUSSignVersion.current`, `NEXUS_SIGN_SDK_VERSION`) and a `User-Agent` header; the Android library can be published with `maven-publish`.
- Production startup requires `TRUSTED_PROXY_IPS`.
- Migration 011 drops two duplicate indexes. A fresh `schema.sql` and an upgraded database have identical schemas.
- Issue and pull request templates, Dependabot configuration and per-area code owners.

### Changed

- Auth Core: missing authentication returns 401 instead of 403; malformed JSON and oversized bodies return 400 and 413 instead of 500.
- Auth Core: a webhook whose secret cannot be decrypted counts as a failed delivery attempt instead of being retried without limit, and recording a webhook event does not decrypt the secret.
- Auth Core: the PKCS#11 adapter opens a new session after the HSM reports the previous one as lost.
- Auth Core: authorization handling is split into `authorizationRecord.ts`, `authorizationService.ts` (creation) and `authorizationConfirmation.ts` (signatures, offline codes, evidence).
- Auth Core: `schema.sql` defines every column in its `CREATE TABLE` statement.
- Sandbox: the stylesheet is kept in readable form.

## [1.2.0] - 2026-09-30

### Added

- Device-signed requests. At enrolment the SDKs create a second hardware key (Secure Enclave, Android Keystore) that signs every later request: method, path, time, a single-use nonce, credential and body hash. After enrolment the phone holds no access token; the bank backend is needed only to issue the single-use enrolment token. Once a device signs its requests, Auth Core neither issues nor accepts session tokens for that identity. Devices enrolled by earlier SDK versions keep using session tokens.
- Offline confirmation. A bank screen shows a QR code with the canonical transaction bytes (`GET /v1/authorizations/{id}/offline-challenge`). The phone verifies them without network, shows the transaction, asks for the biometric and displays an 8-digit code bound to those exact bytes, which the bank submits (`POST /v1/authorizations/{id}/offline-confirmation`). The code key is agreed with ECDH at enrolment; on the phone it is usable only through the prompt that shows the transaction. Codes share the five-attempt limit with signatures and are checked under a row lock. Evidence records them as `confirmationMethod: OFFLINE_CODE`. Enabled with `OFFLINE_CONFIRMATION_ENABLED`.
- One attestation for all device keys: App Attest and Play Integrity cover the signing, authentication and offline keys together.
- Shared device protocol vectors (`auth-core/test-vectors/device-protocols-v1.json`), generated independently of the server code and run by Auth Core, the Android SDK and the iOS SDK.
- Settings `DEVICE_REQUEST_MAX_SKEW_SECONDS`, `DEVICE_REQUEST_PATH_PREFIX`, `OFFLINE_CONFIRMATION_ENABLED`, `DEVICE_SECRET_ENCRYPTION_KEY`; migration 010.

### Changed

- Enrolment is two-phase, like recovery: new keys are promoted only after Auth Core confirms, together with the new credential ID in one durable write, so a failed re-enrolment keeps the working keys.
- Device public keys must be strict PEM (no trailing data or NUL bytes), because the PEM text is part of the attestation binding.
- Device secrets encrypted by Auth Core are bound to their credential (AES-GCM associated data).
- Android: StrongBox key generation falls back to the TEE on any StrongBox failure; new errors `DeviceLocked`, `OfflineConfirmationUnavailable`. iOS: new error `offlineConfirmationUnavailable`.
- The evidence verifier reports offline confirmations separately from device signatures.
- SDK error messages are the same on iOS and Android (for example `This device is not enrolled.`). Apps that match on message text should match on the error type instead.
- Auth Core: App Attest `authData` is length-checked against the declared credential ID length before it is read.
- Enrolment and recovery responses state `requestAuthentication`; the SDKs sign requests only when Auth Core confirms `DEVICE_SIGNATURE`, and accept authorization IDs only in UUID form before building a signed request.
- Sandbox: offline confirmation (enrolment key agreement, QR payload, 8-digit code, attempt limit) in the API, the browser device and the CLI simulator. The bank screen renders the challenge as a QR code (`sandbox/server/qr.py`, standard library only).

## [1.1.0] - 2026-09-29

### Added

- Independently verifiable evidence (schema 2). Each sealed record now contains the exact bytes the customer's device signed, the device signature and the device public key, next to the HSM seal and the hash-chain link. `scripts/verify-evidence.mjs` checks a single record or a NEXUS ID's whole chain without Auth Core: record hash, HSM seal, chain, and the customer's signature over the signed bytes. New endpoints `GET /v1/authorizations/{id}/evidence` and `GET /v1/nexus-identities/{nexusId}/evidence`. See `docs/architecture/evidence-format.md`.
- Append-only evidence table: a database trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` on `evidence_records` (migration 009).
- Device-side payload verification in both SDKs ("what you see is what you sign"). The SDK parses the canonical bytes strictly and cross-checks every response field against them. The confirmation screen and the biometric prompt are rendered only from the signed bytes. See `docs/architecture/authorization-protocol-v1.md`.
- Shared protocol vectors (`auth-core/test-vectors/signed-payload-v1.json`), run by Auth Core, both SDKs and the sandbox:
  - 5 valid payloads;
  - 18 invalid payloads with expected rejection reasons;
  - 7 response-mismatch cases;
  - amount formatting and recovery derivation cases.
- Mobile token purposes. `POST /v1/mobile/sessions` takes `purpose`: a `BOOTSTRAP` token is single-use and accepted only for enrolment; a `SESSION` token is issued only for an identity with an active credential. Both SDKs ask the host app for the purpose they need, cache the session token returned by bootstrap and retry once with a fresh token after a 401.
- Identity suspension and reactivation. Suspending a NEXUS ID cancels its open authorizations; mobile requests for a suspended or revoked identity are refused. New admin action *Reactivate*.
- Two-phase credential replacement during recovery. The working key is kept until the server confirms recovery: a separate keychain tag on iOS (with completion after an interrupted commit), two Keystore slots with an active pointer on Android.
- Sandbox (`sandbox/`) for bank workshops:
  - protocol v1 payloads and real ECDSA P-256 device signatures from the browser (WebCrypto, non-extractable key);
  - simulated bank, providers and HSM; evidence records re-verify the customer's signature;
  - hosted mode with per-guest access codes and isolated workspaces, deployed as a container behind Caddy (automatic HTTPS);
  - automated tests, including ECDSA signatures produced by OpenSSL, WebCrypto and the JVM.
- Tests: Auth Core unit tests (`npm test`), the end-to-end flow `auth-core/scripts/e2e-smoke.mjs` (runs in CI against PostgreSQL 16 and Redis 7), route and OpenAPI consistency checks, container image builds in CI, a Gradle wrapper for the Android SDK.
- Documentation: protocol, evidence format, adaptive verification model, security, operations, verification status and a migrations guide under `docs/` and `auth-core/migrations/README.md`.

### Changed

- Adaptive verification redesigned around two pointers: `requiredStep` (can only be raised) and `currentStep` (next factor, PUSH -> AUDIO -> VIDEO, skipping channels the bank does not operate). A failed AUDIO check escalates to VIDEO; a failed last factor rejects the authorization. The plan is created in the same transaction as the authorization, and an idempotent replay returns the original plan.
- Error responses: validation, permission, not-found, conflict and expiry cases return 400, 403, 404, 409 and 410 with a JSON `error` field; 500 is reserved for unexpected failures.
- Bank-provisioned credentials (`POST /v1/nexus-identities/{id}/credentials`, `…/rotate`) return 403 when `REQUIRE_VALID_ATTESTATION` is on; production credentials are enrolled by the device with attestation. Only P-256 public keys are accepted.
- Recovery setup is performed by the device only; the bank-side `/v1/recovery/setup` endpoints were removed.
- Webhooks are written to an outbox in the same transaction as the state change and delivered to the address that passed the SSRF check. Event names: `authorization.bank_transaction.commit_requested`, `…committed`, `…failed`, `…cancelled`.
- OAuth token endpoint accepts form-encoded, JSON or HTTP Basic client credentials and returns RFC 6749 error bodies; login throttling counts failures only.
- Tokens and admin sessions are re-checked against the current client and user status on every request; re-registering a client revokes its issued tokens.
- Beneficiary keys are restricted to `^[a-z][a-z0-9_]{0,63}$`, with at most 16 fields of up to 512 characters, so every implementation reproduces the signed bytes.
- The PKCS#11 module is loaded only when `HSM_ADAPTER=pkcs11`; the HSM health check verifies its probe signature with the published evidence key.
- SDKs: typed errors for biometric lockout and unavailability; KDF parameters from the server are range-checked before use; recovery phrases are accepted as typed or pasted; Android shows the prompt on the main thread, uses host-supplied prompt texts, handles keys invalidated by a biometric change (`CredentialInvalidated`) and uses the stable `androidx.biometric` 1.1.0; when attestation is unavailable, both SDKs send the reason and leave the decision to the server policy.
- iOS: the platform declaration now includes `.macOS(.v12)` so that `swift test` runs on macOS.

### Fixed

- SSRF: IPv4-mapped IPv6 literals such as `[::ffff:127.0.0.1]` passed the webhook address check. IPv6 addresses are now fully expanded before classification.
- Recovery attempts: failed attempts are now committed and audited, so the attempt limit is enforced.
- Mobile endpoints and gateway mTLS: device-facing endpoints are exempt from gateway mTLS through an explicit allow-list and authenticated by their own tokens.
- PUSH step: marked complete only after a valid signature.
- Evidence ordering: evidence is ordered by insert time, which keeps the hash chain linear under concurrent sealing.
- Idempotent retry: a retry with identical beneficiary data is recognized regardless of key order.
- Malformed signatures count as failed attempts instead of raising errors.
- iOS SDK:
  - timestamps with milliseconds are decoded;
  - a signing error releases its `CFError` exactly once;
  - the biometric context is bound to the signing key lookup.
- Sandbox: failed access codes sent as `Authorization: Bearer` are rate limited; session cookies are bound to the current access code and revoked on sign-out; malformed credentials and signatures return 4xx instead of 500; four-decimal currencies (CLF, UYW) are formatted correctly.

## [1.0.0] - 2026-09-26

- Auth Core: OAuth 2.0 client credentials for bank backends.
- Identity and credentials: NEXUS ID and credential lifecycle.
- Authorization protocol v1: ECDSA P-256 verification.
- Mobile sessions scoped to one NEXUS ID.
- Server-side attestation: App Attest and Play Integrity, bound to the session.
- Recovery: client-side key derivation and credential replacement.
- Evidence: sealed through the PKCS#11 HSM boundary.
- Bank transactions: commit request and result tracking.
- Webhooks: HMAC-signed with egress controls.
- Adaptive verification: Push -> Audio -> Video.
- Native SDKs: iOS (Secure Enclave) and Android (Keystore / StrongBox).
- Contract and schema: OpenAPI specification and SQL schema with migrations.
