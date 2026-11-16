# Configuration reference

Auth Core reads its configuration from environment variables once, at startup (`auth-core/src/config/env.ts`). A missing or malformed value, or a number outside its bounds, stops the process with `Invalid environment configuration` and the list of failing variables. `auth-core/.env.example` lists every variable with development values. The service and the tools read only the process environment and never load a file; in development `npm run dev` starts the server with `node --env-file=.env`, and the tools run the same way (`node --env-file=.env dist/cli/registerClient.js ...`). The command-line tools in `auth-core/src/cli/` load the same schema, so they also need a valid configuration, including `NODE_ENV`; they do not run the posture checks below.

Before the server listens, `auth-core/src/server.ts` runs these checks in order (`auth-core/src/config/productionPosture.ts`):

1. `configurationErrors()`, in every environment: settings that are inconsistent anywhere, the [insecure development rule](#allow_insecure_development) and the [master key check](#master-keys). Startup fails with the errors joined by `; `.
2. `productionBlockers()`, when `NODE_ENV=production`: startup fails with `Production security posture is not acceptable` and one line per unmet requirement. The full list is in [production blockers](#production-blockers).
3. Outside production, when development settings are allowed, a warning `Running WITHOUT production security controls (ALLOW_INSECURE_DEVELOPMENT=true); never use this configuration with real customers` with the field `insecureSettings`.
4. The HSM adapter is created and runs its sign-and-verify self-test; then `SELECT 1` on PostgreSQL and `PING` on Redis.

Every failure is logged as `Fatal error during startup` and the process exits with code 1.

Boolean variables are compared as exact, case-sensitive strings. Opt-in flags are on only for the value `true`; opt-out flags (default on) are off only for the value `false`. `DATABASE_SSL=TRUE` therefore leaves TLS off. List variables are comma-separated; surrounding spaces are removed.

## Service

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `NODE_ENV` | none (required) | `production` | One of `development`, `test`, `production`. There is no default: an unset value stops startup with `NODE_ENV is required: development, test or production`. `production` enables the production blockers, sets the log level to `info` (`debug` otherwise) and forces Redis TLS. |
| `ALLOW_INSECURE_DEVELOPMENT` | off | Must not be set | Opt-in flag. Outside production, allows the development settings listed in [ALLOW_INSECURE_DEVELOPMENT](#allow_insecure_development). |
| `PORT` | `8080` | None | HTTP listen port (positive integer). |
| `OAUTH_TOKEN_TTL_SECONDS` | `3600` | None | Integer from 60 to 86 400. Lifetime of bank backend access tokens issued by `POST /oauth/token`. |
| `REQUIRE_IDEMPOTENCY_KEY` | on | None | Opt-out flag. When on, `POST /v1/authorizations` without an `Idempotency-Key` header is rejected with 400. |
| `BANK_COMMIT_MAX_AGE_SECONDS` | `3600` | None | Integer from 60 to 604 800 (7 days). `POST /v1/authorizations/{id}/bank-commit-request` is refused with 409 `CONFIRMATION_TOO_OLD` when the customer's confirmation (`verified_at`) is older. |
| `AUTHORIZATION_EXPIRY_SWEEP_MS` | `10000` | None | Integer from 500 to 300 000. Interval of the sweep that moves `PENDING_USER` authorizations past `expiresAt` to `EXPIRED` and sends `authorization.expired`. Read paths report `EXPIRED` immediately regardless. |
| `SHUTDOWN_DRAIN_MS` | `15000` | None | Integer from 0 to 120 000. On `SIGTERM`/`SIGINT` Auth Core stops accepting connections and waits this long for requests in flight before closing them, the HSM sessions, the database pool and Redis. |
| `WEBRTC_STUN_URLS` | none | None | Comma-separated STUN URLs given to the device and the operator console for in-app calls ([audio and video calls](audio-video-calls.md)). |
| `WEBRTC_TURN_URLS` | none | None | Comma-separated TURN URLs of the bank's TURN server. Used only with `WEBRTC_TURN_SECRET`. |
| `WEBRTC_TURN_SECRET` | none | Secret | coturn `static-auth-secret` (at least 16 characters); per-session TURN credentials are derived from it. |
| `WEBRTC_TURN_CREDENTIAL_TTL_SECONDS` | `600` | None | Integer from 60 to 3600; TURN credentials also expire with the session. |

## Database and Redis

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `DATABASE_URL` | none (required) | Connect as `nexus_app` ([deployment](deployment.md#database-roles)) | PostgreSQL connection string. |
| `DATABASE_POOL_MAX` | `10` | None | Maximum connections per process. |
| `DATABASE_SSL` | off | `true` | Opt-in flag. When on, connects with TLS and verifies the server certificate. |
| `DATABASE_STATEMENT_TIMEOUT_MS` | `5000` | None | PostgreSQL `statement_timeout` for every connection. |
| `REDIS_URL` | none (required) | Must start with `rediss://` | Redis connection string. Requirements for the Redis deployment are in [deployment](deployment.md#redis). |
| `REDIS_TLS_REQUIRED` | off | `true` | Opt-in flag. When on (and always when `NODE_ENV=production`), connects with TLS and verifies the server certificate. |

## HSM

See [HSM and key management](../security/hsm-key-management.md) and [HSM unavailable](runbooks/hsm-unavailable.md).

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `HSM_ADAPTER` | `software` | `pkcs11` | `software` (development and tests; an in-memory key generated per process) or `pkcs11`. `software` outside production needs `ALLOW_INSECURE_DEVELOPMENT=true`. |
| `PKCS11_MODULE_PATH` | none | Required | Path of the vendor PKCS#11 library. |
| `PKCS11_PIN` | none | Required | User PIN for the token. From the secrets manager. |
| `PKCS11_TOKEN_LABEL` | none | Required | 1 to 32 characters. Token label (`CKA_LABEL` of the token). Exactly one present token must carry it; none or several stop startup. When set, `PKCS11_SLOT_INDEX` is ignored. |
| `PKCS11_SLOT_INDEX` | `0` | Not used when `PKCS11_TOKEN_LABEL` is set | Index into the list of slots that have a token present (non-negative integer). Development fallback only; the index can point at another token after tokens are added or the HSM restarts. |
| `PKCS11_EVIDENCE_KEY_LABEL` | none | Required | `CKA_LABEL` of the evidence key pair. Exactly one private key and one public key must match. |
| `PKCS11_EVIDENCE_KEY_ID` | none | Required when the label is not unique | `CKA_ID` of the evidence key, hex (an even number of hex digits). Added to the search for both key objects. |
| `PKCS11_EVIDENCE_KEY_VERSION` | `1` | None | Positive integer written as `hsm_key_version` on every evidence record. Auth Core does not derive or check it. Since evidence schema 3 each record also names its key by `seal_key_id` (SHA-256 of the public key), which verification uses. |
| `HSM_SESSION_POOL_SIZE` | `4` | None | Integer from 1 to 64. Logged-in PKCS#11 sessions used in parallel per process. Once as many timed-out calls as this number are still running, new operations fail at once (`HSM not answering`). Keep `UV_THREADPOOL_SIZE` (libuv worker threads, set to `16` in the Docker image) larger than this value. |
| `HSM_OPERATION_TIMEOUT_MS` | `5000` | None | Integer from 100 to 60 000. Deadline for one HSM call as seen by the service, whatever PKCS#11 function it is in (the module runs in a worker thread), and for waiting for a free session. |
| `HSM_QUEUE_LIMIT` | `256` | None | Calls allowed to wait for the HSM worker; more are refused at once (`HSM queue is full`). |
| `HSM_BREAKER_THRESHOLD` | `3` | None | Consecutive HSM timeouts that open the circuit breaker: calls then fail at once and readiness reports the HSM down. |
| `HSM_BREAKER_COOLDOWN_MS` | `10000` | None | How long the opened breaker refuses calls before a fresh HSM worker is started and health-checked. New (unreleased) |
| `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` | none | Required after an evidence key rotation | PEM public keys (concatenated) of evidence keys retired by rotation. Auth Core accepts them, next to the current HSM key, when it checks sealed enrolment and recovery records, and publishes them in evidence exports (`evidencePublicKeys`). See [key rotation](runbooks/key-rotation.md). |

The PKCS#11 private key must be an EC key on P-256 with `CKA_SIGN` true, `CKA_SENSITIVE` true and `CKA_EXTRACTABLE` false; otherwise opening a session fails with a message naming the attribute.

## Attestation

See [device attestation](../security/attestation.md).

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `REQUIRE_VALID_ATTESTATION` | off | `true` | Opt-in flag. When on, enrolment and recovery are refused (403) unless App Attest or Play Integrity with Android key attestation succeeds, and `POST /v1/authorizations` for a credential whose `attestation_status` is not `VERIFIED` is refused with 409 `CREDENTIAL_NOT_ATTESTED`. Off outside production needs `ALLOW_INSECURE_DEVELOPMENT=true`. |
| `APPLE_APP_ID` | none | iOS or Android pair required (see below) | App Attest App ID, `TEAMID.BUNDLEID`. Without it, iOS attestation cannot be verified. |
| `APPLE_APP_ATTEST_ROOT_CA_PEM` | none | Required when `APPLE_APP_ID` is set | Apple App Attest root CA, PEM. Outside production it is fetched from Apple on first use when unset. |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | none | iOS or Android pair required (see below) | Contents (not a path) of the Google Cloud service account key used for the Play Integrity decode API. |
| `ANDROID_PACKAGE_NAME` | none | iOS or Android pair required (see below) | Package name that Play Integrity tokens and key attestations must name. |
| `ANDROID_REQUIRED_DEVICE_VERDICT` | `MEETS_DEVICE_INTEGRITY` | Not `MEETS_BASIC_INTEGRITY` (Android configured) | One of `MEETS_BASIC_INTEGRITY`, `MEETS_DEVICE_INTEGRITY`, `MEETS_STRONG_INTEGRITY`. The device integrity verdict a Play Integrity token must contain. |
| `ANDROID_KEY_SECURITY_POLICY` | `REQUIRE_HARDWARE_BACKED` | Not `ALLOW_SOFTWARE` (Android configured) | One of `REQUIRE_STRONGBOX`, `REQUIRE_HARDWARE_BACKED` (TEE or StrongBox), `ALLOW_TEE` (the same acceptance as `REQUIRE_HARDWARE_BACKED`: TEE or StrongBox), `ALLOW_SOFTWARE` (development only). Where the Android Keystore key attestation must place the signing and authentication keys. A key that does not meet the policy is refused. |
| `ANDROID_REQUIRE_LOCKED_BOOTLOADER` | on | `true` (Android configured) | Opt-out flag. Refuses key attestations that report an unlocked bootloader or a boot state other than verified. |
| `ANDROID_APP_CERT_SHA256` | empty list | Non-empty (Android configured) | SHA-256 digests (hex; colons allowed, case ignored) of the bank app's signing certificates, comma-separated. Checked in the key attestation and the Play Integrity verdict. With an empty list neither check is made. |
| `ANDROID_ATTESTATION_STATUS_FILE` | none | Required (Android configured) | Path of Google's attestation status list, downloaded and refreshed by operations. Read on use and cached for one minute, so a refreshed file takes effect without a restart. A missing, unreadable or malformed file makes every Android key attestation fail (enrolment and recovery are refused as attestation failures). Auth Core does not check the file's age. See [Android attestation status list](runbooks/android-attestation-status-list.md). |
| `ATTESTATION_MAX_AGE_SECONDS` | `300` | None | Integer from 30 to 3600. Maximum difference between a Play Integrity token's timestamp and server time. |

Production needs at least one complete platform pair: `APPLE_APP_ID` with `APPLE_APP_ATTEST_ROOT_CA_PEM`, or `GOOGLE_SERVICE_ACCOUNT_JSON` with `ANDROID_PACKAGE_NAME`, or both. "Android configured" in the table means that the Android pair is set; the Android requirements are checked only then.

## Mobile and device protocol

See [device authentication and offline confirmation](../protocol/device-authentication-and-offline-confirmation.md). `BOOTSTRAP` tokens have a fixed lifetime of 300 s; there is no other mobile token.

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `DEVICE_REQUEST_MAX_SKEW_SECONDS` | `300` | None | Integer from 30 to 900. Accepted difference between `X-NEXUS-Timestamp` and server time. Each nonce is kept in Redis for twice this value plus 60 s. |
| `DEVICE_REQUEST_PATH_PREFIX` | empty | Set when the gateway strips a prefix | Path prefix the gateway removes before forwarding, for example `/nexus-sign`. Must match `^(/[A-Za-z0-9._~-]+)*$`. It is prepended to the request path before the device signature is checked. |

## Offline confirmation

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `OFFLINE_CONFIRMATION_ENABLED` | off | None | Opt-in flag. Enables the offline challenge and confirmation endpoints and the storage of offline keys at enrolment. |
| `OFFLINE_CONFIRMATION_MAX_AMOUNT` | none (no cap) | Production, when `OFFLINE_CONFIRMATION_ENABLED=true` | Highest amount per currency that an offline code may confirm, `CURRENCY:amountMinor` comma-separated (e.g. `PLN:100000,EUR:20000`). Currencies not listed are not offered offline; above the cap no QR challenge is issued (409 `OFFLINE_LIMIT_EXCEEDED`) and a code is refused without using an attempt. The cap exists because an offline code is an HMAC under a key Auth Core also holds ([ADR 0003](../adr/0003-offline-confirmation-hmac-codes.md)). New (unreleased, planned for 2.0.0). |
| `OFFLINE_CONFIRMATION_MODE` | `deferred_signature` | Production: must be `deferred_signature` when `OFFLINE_CONFIRMATION_ENABLED=true` | Offline confirmation protocol. `deferred_signature` (v2): QR `NXS2.`; a correct code leaves the authorization `OFFLINE_PROVISIONAL` until the device's signature arrives ([offline confirmation v2](../protocol/offline-confirmation-v2-deferred-signature.md)). `immediate` (v1): QR `NXS1.`; a correct code is `VERIFIED` at once; for development and old SDKs only. New (unreleased, planned for 2.0.0) |
| `OFFLINE_SIGNATURE_DEADLINE_HOURS` | 72 | None | v2: hours after an accepted code within which the device signature must arrive (1–720); afterwards `OFFLINE_UNSIGNED`. New (unreleased, planned for 2.0.0) |
| `OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY` | none (no limit) | Production, when `OFFLINE_CONFIRMATION_ENABLED=true` | Most offline confirmations one credential may make in 24 hours (1–1000). Above it a code is refused without using an attempt and `offline_confirmation_limit_reached` is audited ([threat model](../security/offline-confirmation-threat-model.md)). New (unreleased, planned for 2.0.0) |
| `DEVICE_REPLACEMENT_HOLD_SECONDS` | 86400 | Production: at least 3600 | How long a bank-requested device replacement waits before it can be used when the enrolled device neither approves nor cancels it ([device replacement](../architecture/device-replacement.md)). New (unreleased, planned for 2.0.0) |
| `DEVICE_NONCE_STORE` | `postgres` | Production: `postgres` | Where used device request nonces are remembered. `postgres`: table `device_request_nonces` (migration 021), deleted after their lifetime by the expiry sweep; `redis`: as before 2.0.0, a Redis failover or restore can forget nonces. New (unreleased, planned for 2.0.0) |
| `METRICS_BEARER_TOKEN` | none (open) | Production, at least 32 characters | Bearer token the monitoring system sends to `GET /metrics`; without it, metrics are readable by every client that passes the gateway check. New (unreleased, planned for 2.0.0) |
| `DEVICE_SECRET_ENCRYPTION_KEY` | none | Required when `OFFLINE_CONFIRMATION_ENABLED=true` or `PUSH_DELIVERY_ENABLED=true` (any environment) | AES-256-GCM master key for `credentials.offline_secret_encrypted` and `push_registrations.push_key_encrypted`. 32 bytes, base64. |
| `WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS`, `DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS`, `ADMIN_SECRET_ENCRYPTION_KEY_PREVIOUS` | none | During a master key rotation only | Previous master keys, comma-separated, accepted for decryption until `rotateSecretKeys.js` has re-encrypted the stored secrets ([key rotation](runbooks/key-rotation.md)). Each 32 bytes, base64, different from the current key. New (unreleased, planned for 2.0.0). |
| `MASTER_KEY_SOURCE` | `env` | Production: `hsm` | `env`: master keys in base64 in the variables above. `hsm`: only wrapped keys are configured and Auth Core unwraps them in the HSM at startup; plaintext master key variables are then refused ([key management](../engineering/KEY_MANAGEMENT.md)). New (unreleased, planned for 2.0.0) |
| `PKCS11_KEK_LABEL` | none | With `MASTER_KEY_SOURCE=hsm` | Label of the AES-256 key-encryption key on the token of `PKCS11_TOKEN_LABEL` (sensitive, not extractable, `CKA_DECRYPT`). Uses `PKCS11_MODULE_PATH` and `PKCS11_PIN` |
| `WEBHOOK_/DEVICE_/ADMIN_SECRET_ENCRYPTION_KEY_WRAPPED`, `…_PREVIOUS_WRAPPED` | none | With `MASTER_KEY_SOURCE=hsm` | Wrapped master keys made with `node dist/cli/masterKeys.js generate|wrap|rewrap`; previous ones comma-separated during a rotation |

## Secure push

Used by bank clients in push mode `NEXUS` ([secure push](../protocol/secure-push.md)). Startup refuses `PUSH_DELIVERY_ENABLED=true` without `DEVICE_SECRET_ENCRYPTION_KEY` and at least one complete provider, and refuses a partly configured provider in any case.

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `PUSH_DELIVERY_ENABLED` | off | None | Opt-in flag. Starts the push worker; enables `POST /v1/push-messages`, the authorization request push and the device replacement notice for bank clients in push mode `NEXUS`. |
| `APNS_TEAM_ID` | none | Set with the other `APNS_*` | Apple Developer Team ID (10 characters). |
| `APNS_KEY_ID` | none | Set with the other `APNS_*` | Key ID of the APNs auth key (10 characters). |
| `APNS_PRIVATE_KEY_PEM` | none | Set with the other `APNS_*` | Contents (not a path) of the APNs auth key file (`.p8`, PEM). |
| `APNS_TOPIC` | none | Set with the other `APNS_*` | Bundle ID of the bank's iOS app. |
| `FCM_PROJECT_ID` | none | Set with `FCM_SERVICE_ACCOUNT_JSON` | Firebase project of the bank's Android app. |
| `FCM_SERVICE_ACCOUNT_JSON` | none | Set with `FCM_PROJECT_ID` | Contents of a service account key allowed to send messages to that project (FCM HTTP v1). |
| `PUSH_MESSAGE_TTL_SECONDS` | `86400` | None | Integer from 60 to 2 419 200. How long a message is retried and kept by APNs and FCM; the upper limit for a message's `ttlSeconds`. |
| `PUSH_ALERT_TITLE` | `New message` | None | Up to 64 characters. The APNs alert text before the notification service extension replaces it with the decrypted message; shown as is if the extension cannot decrypt. Not sent to FCM. |
| `PUSH_ALERT_BODY` | empty | None | Up to 120 characters, as `PUSH_ALERT_TITLE`. |
| `PUSH_AUTHORIZATION_TITLE` | `Confirm payment` | None | Up to 120 characters. Title of the authorization request push when the bank gives none (`pushNotification.title`). |
| `PUSH_AUTHORIZATION_BODY` | `Open the app to review and confirm.` | None | Up to 600 characters. Body of the authorization request push when the bank gives none. |
| `PUSH_REPLACEMENT_TITLE` | `Your account was set up on a new device` | None | 1 to 120 characters; an empty value selects the default. Title of the `SECURITY` message sent to a device that was replaced ([device replacement](../integration/bank-backend-guide.md#device-replacement)). |
| `PUSH_REPLACEMENT_BODY` | `If this was not you, contact your bank immediately.` | None | Up to 600 characters; an empty value selects the default. Body of that message. |

The alert, authorization and replacement texts are configured once per deployment; a bank serving several languages passes `pushNotification` per authorization. The replacement notice has no per-request text.

## Webhooks

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `WEBHOOK_SECRET_ENCRYPTION_KEY` | none | Required | AES-256-GCM master key for `bank_clients.webhook_secret_encrypted`. 32 bytes, base64. Outside production it is needed only when a bank client has a webhook. |
| `WEBHOOK_ALLOWED_HOSTS` | empty list | Non-empty | Host names a webhook URL may use (compared in lower case). |
| `WEBHOOK_REQUIRE_HTTPS` | on | `true` (not `false`) | Opt-out flag. When on, webhook URLs must use `https`. |

## Admin console

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `ADMIN_COOKIE_SECURE` | on | `true` (not `false`) | Opt-out flag. Adds `Secure` to the `nexus_admin_session` cookie. Set to `false` only for local development over plain HTTP. |
| `ADMIN_MFA_REQUIRED` | on | `true` (not `false`) | Opt-out flag. When on, an account without an enrolled TOTP secret cannot log in. An account that has a TOTP secret always needs a code, whatever the setting. `false` outside production needs `ALLOW_INSECURE_DEVELOPMENT=true`. |
| `ADMIN_SECRET_ENCRYPTION_KEY` | none | Required | AES-256-GCM master key for `admin_users.totp_secret_encrypted`. 32 bytes, base64. `createAdminUser` refuses to enrol a TOTP secret without it. |
| `ADMIN_APPROVAL_TTL_HOURS` | `24` | None | Integer from 1 to 168. How long a revocation or reactivation request waits for a second admin before it expires. |

Admin sessions end after 30 minutes without a request and at the latest 8 hours after login; these limits are fixed in `adminAuthService.ts`.

## Gateway and mTLS

See the [gateway mTLS trust model](../security/threat-model.md#gateway-mtls-trust-model) and [deployment](deployment.md#gateway).

| Variable | Default | Production requirement | Purpose |
|---|---|---|---|
| `REQUIRE_MTLS_HEADER` | off | `true` | Opt-in flag. When on, every request except `/healthz`, `/readyz` and the device-facing routes listed in `src/middleware/mtlsGateway.ts` must come from a `TRUSTED_PROXY_IPS` address and carry `MTLS_VERIFIED_HEADER: SUCCESS` and a certificate fingerprint in `MTLS_CERT_SHA256_HEADER`; otherwise 403. This includes `/metrics` and `/admin`. Bank tokens are then issued and accepted only with a fingerprint registered for the client. Off outside production needs `ALLOW_INSECURE_DEVELOPMENT=true`. |
| `MTLS_VERIFIED_HEADER` | `x-client-cert-verified` | None | Header the gateway sets to `SUCCESS` after verifying the client certificate. |
| `MTLS_CERT_SHA256_HEADER` | `x-client-cert-sha256` | None | Header in which the gateway forwards the SHA-256 fingerprint of the verified client certificate: 64 hex digits, colons allowed, case ignored. |
| `TRUSTED_PROXY_IPS` | empty list | Non-empty | Gateway source addresses. Used for the mTLS check and for Express `trust proxy`, which determines the client address used in logs, throttling and audit records. IPv4-mapped IPv6 addresses (`::ffff:10.0.0.5`) compare as their IPv4 form, in the list and for the connecting address. With `REQUIRE_MTLS_HEADER=true` and an empty list, every non-device request is rejected with 403. |

## ALLOW_INSECURE_DEVELOPMENT

Outside production (`NODE_ENV` `development` or `test`), each of these settings stops startup with `<setting> is a development setting: set ALLOW_INSECURE_DEVELOPMENT=true to run with it outside production`:

| Setting | Control it switches off |
|---|---|
| `HSM_ADAPTER=software` | HSM-held evidence key |
| `REQUIRE_VALID_ATTESTATION` not `true` | Device attestation |
| `REQUIRE_MTLS_HEADER` not `true` | Gateway mTLS and client certificate binding |
| `ADMIN_MFA_REQUIRED=false` | Admin TOTP |

With `ALLOW_INSECURE_DEVELOPMENT=true` the process starts and logs the warning shown at the top of this page with the list of settings. In production `ALLOW_INSECURE_DEVELOPMENT=true` is itself a blocker, and each of these settings is a blocker of its own. A deployment labelled `development` or `test` therefore cannot run without these controls by accident.

## Master keys

`WEBHOOK_SECRET_ENCRYPTION_KEY`, `DEVICE_SECRET_ENCRYPTION_KEY` and `ADMIN_SECRET_ENCRYPTION_KEY` are checked at startup in every environment. A value that is set and not empty must be standard base64 (`A-Z`, `a-z`, `0-9`, `+`, `/`, up to two `=`; no line breaks, no URL-safe alphabet) and decode to exactly 32 bytes. Otherwise startup fails with `<NAME> must be 32 random bytes, base64-encoded`.

Generate a separate value for each key and store it in the secrets manager:

```sh
openssl rand -base64 32   # WEBHOOK_SECRET_ENCRYPTION_KEY
openssl rand -base64 32   # DEVICE_SECRET_ENCRYPTION_KEY
openssl rand -base64 32   # ADMIN_SECRET_ENCRYPTION_KEY
```

None of the three keys can be changed without losing access to the values it encrypts; see [key rotation](runbooks/key-rotation.md). The evidence signing key is generated in the HSM, not configured here.

## Production blockers

`productionBlockers()` reports each of the following, in this order, when `NODE_ENV=production`:

| Condition | Message |
|---|---|
| `ALLOW_INSECURE_DEVELOPMENT=true` | `ALLOW_INSECURE_DEVELOPMENT must not be set in production` |
| `HSM_ADAPTER` not `pkcs11` | `HSM_ADAPTER must be pkcs11 in production` |
| `REQUIRE_VALID_ATTESTATION` not `true` | `REQUIRE_VALID_ATTESTATION must be true in production` |
| Neither platform pair complete | `attestation must be configured for at least one platform: APPLE_APP_ID + APPLE_APP_ATTEST_ROOT_CA_PEM, and/or GOOGLE_SERVICE_ACCOUNT_JSON + ANDROID_PACKAGE_NAME` |
| `APPLE_APP_ID` without `APPLE_APP_ATTEST_ROOT_CA_PEM` | `APPLE_APP_ATTEST_ROOT_CA_PEM must be pinned in production` |
| Android configured, `ANDROID_KEY_SECURITY_POLICY=ALLOW_SOFTWARE` | `ANDROID_KEY_SECURITY_POLICY=ALLOW_SOFTWARE is not allowed in production` |
| Android configured, no `ANDROID_ATTESTATION_STATUS_FILE` | `ANDROID_ATTESTATION_STATUS_FILE (Google attestation status list) is required in production` |
| Android configured, empty `ANDROID_APP_CERT_SHA256` | `ANDROID_APP_CERT_SHA256 (the app signing certificate digests) is required in production` |
| Android configured, `ANDROID_REQUIRE_LOCKED_BOOTLOADER=false` | `ANDROID_REQUIRE_LOCKED_BOOTLOADER must be true in production` |
| Android configured, `ANDROID_REQUIRED_DEVICE_VERDICT=MEETS_BASIC_INTEGRITY` | `ANDROID_REQUIRED_DEVICE_VERDICT must be MEETS_DEVICE_INTEGRITY or MEETS_STRONG_INTEGRITY in production` |
| No `WEBHOOK_SECRET_ENCRYPTION_KEY` | `WEBHOOK_SECRET_ENCRYPTION_KEY is required in production` |
| `ADMIN_COOKIE_SECURE=false` | `ADMIN_COOKIE_SECURE must be true in production` |
| `ADMIN_MFA_REQUIRED=false` | `ADMIN_MFA_REQUIRED must be true in production` |
| No `ADMIN_SECRET_ENCRYPTION_KEY` | `ADMIN_SECRET_ENCRYPTION_KEY is required in production (admin TOTP secrets)` |
| No `PKCS11_MODULE_PATH` or no `PKCS11_PIN` | `PKCS11_MODULE_PATH and PKCS11_PIN are required in production` |
| No `PKCS11_TOKEN_LABEL` | `PKCS11_TOKEN_LABEL is required in production (slot numbers can change)` |
| No `PKCS11_EVIDENCE_KEY_LABEL` | `PKCS11_EVIDENCE_KEY_LABEL is required for HSM evidence sealing in production` |
| `DATABASE_SSL` not `true` | `DATABASE_SSL must be true in production` |
| `REDIS_TLS_REQUIRED` not `true` | `REDIS_TLS_REQUIRED must be true in production` |
| `REQUIRE_MTLS_HEADER` not `true` | `REQUIRE_MTLS_HEADER must be true in production` |
| Empty `TRUSTED_PROXY_IPS` | `TRUSTED_PROXY_IPS must list the mTLS gateway addresses in production` |
| Empty `WEBHOOK_ALLOWED_HOSTS` | `WEBHOOK_ALLOWED_HOSTS must be configured in production` |
| `WEBHOOK_REQUIRE_HTTPS=false` | `WEBHOOK_REQUIRE_HTTPS must be true in production` |
| `REDIS_URL` not starting with `rediss://` | `REDIS_URL must use rediss:// in production` |

The blockers check that a value is present, not that it works: an unreadable `ANDROID_ATTESTATION_STATUS_FILE`, a wrong certificate digest or an unreachable gateway address passes startup. A missing or unreadable status file is found at the first Android enrolment or recovery, which then fails key attestation (403 `Device attestation verification failed` with `REQUIRE_VALID_ATTESTATION`). `test/production-posture.test.mjs` and `test/integration/production-startup.test.mjs` cover the list.

Settings that are refused in every environment, independent of `NODE_ENV`:

- `DEVICE_SECRET_ENCRYPTION_KEY` missing while `OFFLINE_CONFIRMATION_ENABLED=true` or `PUSH_DELIVERY_ENABLED=true`;
- `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_PRIVATE_KEY_PEM`, `APNS_TOPIC` only partly set, or `FCM_PROJECT_ID` and `FCM_SERVICE_ACCOUNT_JSON` only partly set;
- `PUSH_DELIVERY_ENABLED=true` without one complete provider;
- a master key that is not 32 bytes, base64;
- the development settings above without `ALLOW_INSECURE_DEVELOPMENT=true`.
