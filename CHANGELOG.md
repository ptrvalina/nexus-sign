# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org/); see [docs/compatibility-and-versioning.md](docs/compatibility-and-versioning.md) for what each version number covers.

## [Unreleased]

### Added

- `demo/`: demo host apps for iPhone (`demo/ios`, Xcode project; CI job `ios-demo` builds it) and Android (`demo/android`; CI job `android-demo` builds the `nexus-sign-demo-apk` artifact), and a demo bank backend (`demo/bank-backend/demo-bank.mjs`) with an operator page and a device port that forwards only the device endpoints of Auth Core, for trying enrolment and payment signing on a real phone ([demo/README.md](demo/README.md)).
- `auth-core/scripts/run-local.sh`: runs Auth Core with PostgreSQL and Redis from `docker-compose.yml` on one machine in development mode (fresh database, schema and roles, bank client, admin account with TOTP, service on port 8080).
- Auth Core: webhooks `authorization.verified` (with the evidence position and the chain head the bank keeps for truncation checks), `authorization.rejected` and `authorization.expired` (FI-013, FI-019).
- Auth Core: a periodic sweep moves `PENDING_USER` authorizations past their expiry to `EXPIRED`, with their verification plan and open sessions (`AUTHORIZATION_EXPIRY_SWEEP_MS`, FI-013).
- Auth Core: audio and video results are accepted only as a provider result token (ES256 JWS) that Auth Core verifies against a key registered for the bank, bound to the session, authorization, transaction terms, device credential and session nonce, fresh and single-use ([verification result v1](docs/protocol/verification-result-v1.md), FI-002); or as an operator decision in the admin console. Migration `019_verification_results.sql`; operator CLI `verificationSetup.js`.
- Auth Core: a verification channel is offered only if the bank has a verifier for it; a requirement no channel can meet is refused with 409 `VERIFICATION_CHANNEL_UNAVAILABLE` (FI-017).
- In-app audio and video calls ([ADR 0017](docs/adr/0017-in-app-audio-video-calls.md)): Auth Core relays WebRTC signalling between the customer's device (`/v1/mobile/verification-sessions/{id}/call`, `/signals`, `/cancel`) and a bank operator in the admin console (Verification calls panel, `/admin/api/verification-calls`), issues per-session TURN credentials (`WEBRTC_*`), and records the operator's decision. A declined or unanswered call verifies nothing; at most three sessions per channel. Real media between two browsers is tested in `test/media/webrtc-call.test.mjs` (CI job `auth-core-media`). Operations: [docs/operations/audio-video-calls.md](docs/operations/audio-video-calls.md).
- Demo bank: the demo app's calls need the pairing code shown on the operator page; the iOS and Android demo apps ask for it (FI-016). CI job `demo-bank` tests it.

### Changed

- **Breaking:** `POST /v1/authorizations/{id}/verification-sessions/{sessionId}/complete` takes `{ "resultToken": "<JWS>" }`. The previous body (`sessionNonce`, `result`, `providerReference`, `assertion`), whose assertion Auth Core did not verify, is refused with 400. `scripts/e2e-smoke.mjs` needs `NEXUS_SIGN_SMOKE_PROVIDER_KEY`.
- **Breaking:** `audioAvailable`/`videoAvailable` no longer default to available: a channel needs a registered provider key or operator verification (`verificationSetup.js`).
- Evidence: verification factors carry `method` (`PROVIDER` or `OPERATOR`) and `issuer`.
- Auth Core: `GET /v1/authorizations/{id}` and `GET /v1/mobile/authorizations/{id}` report `EXPIRED` as soon as `expiresAt` has passed, instead of `PENDING_USER` until the next confirmation attempt (FI-013).
- Auth Core: shutdown waits up to `SHUTDOWN_DRAIN_MS` for requests in flight before closing the HSM, database and Redis (FI-014).
- Auth Core: a NEXUS ID collision between concurrent identity creations retries with a new ID instead of reporting a duplicate customer (FI-015).
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
- Not addressed: audio and video verification remain the bank's or provider's assertion (NXS-019); Redis replication requirements are documented, not enforced (NXS-021); App Attest assertions per operation (NXS-025); optional TLS key pinning in the SDKs (NXS-028); Gradle checksums (NXS-039) and image digests (NXS-040).

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
