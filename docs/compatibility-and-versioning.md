# Compatibility and versioning

## What is versioned

| Item | Version identifier | Where it is defined |
|---|---|---|
| Release | `VERSION` at the repository root (2.0.0-rc.2) | Also `version` in `auth-core/package.json`, `info.version` in `auth-core/openapi.yaml` and `sandbox/openapi.yaml`, `NEXUSSignVersion.current` (iOS) and `NEXUS_SIGN_SDK_VERSION` (Android); `npm run check:repository` fails when they differ |
| Auth Core API | Path prefix `/v1` | `auth-core/openapi.yaml` |
| Authorization protocol | `protocol_version: "1"`, `domain: "NEXUS-SIGN/TRANSACTION-AUTH"` | [authorization-protocol-v1.md](protocol/authorization-protocol-v1.md), `auth-core/test-vectors/signed-payload-v1.json` |
| Device protocols | `NEXUS-SIGN/DEVICE-REQUEST/v1`, `NEXUS-SIGN/OFFLINE/v1`, `NEXUS-SIGN/OFFLINE-CODE/v1`, QR prefixes `NXS1.` (v1, code only) and `NXS2.` (v2, deferred device signature) | [device authentication and offline confirmation](protocol/device-authentication-and-offline-confirmation.md), `auth-core/test-vectors/device-protocols-v1.json` |
| Evidence | `schemaVersion: "3"` in the sealed payload, record types `AUTHORIZATION`, `CREDENTIAL_ENROLLED`, `RECOVERY_CONFIGURED` | [evidence-format.md](protocol/evidence-format.md), [ADR 0009](adr/0009-evidence-schema-3.md) |
| Recovery protocol | `protocol: 2`; `NEXUS-SIGN/RECOVERY-WRAP/v2` (HKDF salt), `NEXUS-SIGN/RECOVERY-KEY/v2` (associated data), `NEXUS-SIGN/RECOVERY-SETUP/v2`, `NEXUS-SIGN/RECOVERY-PROOF/v2` (signing inputs) | [recovery protocol 2](protocol/recovery-protocol-v2.md), `auth-core/test-vectors/recovery-v2.json` |
| Android key attestation challenge | `NEXUS-SIGN/KEY-ATTESTATION/v1` | [attestation](security/attestation.md#android-key-attestation), `key_attestation` in `auth-core/test-vectors/device-protocols-v1.json` |
| Secure push | `NEXUS-SIGN/PUSH/v1`, `NEXUS-SIGN/PUSH-RECEIPT/v1`, envelope `v: 1` | [secure push](protocol/secure-push.md), `auth-core/test-vectors/secure-push-v1.json` |
| Webhook signature | `v1=` prefix of each comma-separated entry of `X-NEXUS-SIGN-Signature` (two entries during a secret rotation overlap) | [bank backend guide](integration/bank-backend-guide.md#webhooks) |
| Database schema | Numbered migrations (`002` to `022`) | `auth-core/migrations/`, `auth-core/src/db/schema.sql` |

Auth Core, the iOS SDK, the Android SDK and the sandbox are released together under the repository version. The Swift package and the Android library declare no version of their own; a host app takes both SDKs from the same repository release.

## Semantic versioning rules

The release version follows [Semantic Versioning](https://semver.org/). Each versioned item has its own rule for what counts as a breaking change.

| Item | Compatible within the version (minor or patch release) | Requires a new version |
|---|---|---|
| Auth Core API `/v1` | New endpoints, new optional request fields, new response fields, new error messages | Removing or renaming an endpoint or field, a new required request field, a changed meaning of a status code or field. A breaking change is published under a new path prefix (`/v2`) in a major release, with `/v1` kept for the deprecation period |
| Authorization protocol | Nothing in the signed bytes changes | Any change to the fields, formats, encoding or signature of the signed bytes. Such a change is a new protocol version with new vectors that Auth Core, both SDKs and the sandbox pass ([CONTRIBUTING.md](../CONTRIBUTING.md)) |
| Device protocols | Nothing in the signed or derived bytes changes | Any change to the request signing input, the key derivation, the code derivation, the key attestation challenge or the QR format, under a new domain string |
| Recovery protocol | Nothing in the derivation, wrapping or signing inputs changes | Any change to them, under a new protocol number and new domain strings, with new shared vectors |
| Secure push | New message categories and new optional plaintext fields, which older SDKs ignore | Any change to the key derivation, the envelope, the associated data or the receipt, under a new domain string and envelope version |
| Evidence schema | Nothing in the sealed payload changes | A new field, a removed field or a changed rule in the sealed payload. Records of earlier schema versions keep their hash and seal and stay in the chain |
| Webhook signature | Nothing in the signed string changes | A new prefix (`v2=`) |
| Database schema | Migrations add tables, columns, indexes and constraints that existing data satisfies | A migration that removes or rewrites data. Such migrations ship only in a major release and are described in the migrations guide |

Bank backends ignore unknown fields in Auth Core responses and in webhook bodies, so that additive changes in a minor release need no change on the bank side.

## Supported platforms

| Component | Requirement | Source |
|---|---|---|
| Auth Core | Node.js 22 or later; CI builds and tests on Node.js 22 and 24 | `engines` in `auth-core/package.json`, `.github/workflows/ci.yml` |
| PostgreSQL | 14 or later; CI runs PostgreSQL 16 | Header of `auth-core/src/db/schema.sql`, `auth-core/docker-compose.yml` |
| Redis | CI runs Redis 7. Auth Core uses `GETDEL`, which requires Redis 6.2 or later | `auth-core/docker-compose.yml`, `auth-core/src/services/mobileSessionService.ts` |
| iOS SDK | iOS 15 or later, Swift 5.9 (Xcode 15 or later), a device with a Secure Enclave and a device passcode. macOS 12 is declared only to run `swift test` | `ios-sdk/Package.swift` |
| Android SDK | Android 9 (API 28) or later, compile SDK 34, Java 17, Kotlin 1.9.24, Android Gradle Plugin 8.5.2. A secure lock screen. Hardware-backed keys: StrongBox when present, TEE otherwise | `android-sdk/build.gradle.kts` |
| Sandbox | Python 3.10 or later, standard library only | `sandbox/README.md` |

The iOS SDK is built and tested in CI on a macOS runner only.

Which Android devices can enrol depends on `ANDROID_KEY_SECURITY_POLICY`, because Auth Core takes the security level from the key attestation, not from the SDK. The SDK uses StrongBox when the device has it and falls back to the TEE when StrongBox key generation fails. Under `REQUIRE_HARDWARE_BACKED` (default) or `ALLOW_TEE` both are accepted; under `REQUIRE_STRONGBOX` only devices whose keys are generated in StrongBox can enrol; a key attested at `SOFTWARE` level is accepted only under `ALLOW_SOFTWARE`, which production refuses. Devices with an unlocked bootloader are refused while `ANDROID_REQUIRE_LOCKED_BOOTLOADER` is on (default).

Auth Core dependencies are installed only from a committed `auth-core/package-lock.json`: CI runs `npm ci` and its first step fails when the file is missing, and the Dockerfile copies the lockfile and runs `npm ci`. The lockfile must be generated with npm registry access, reviewed and committed; this release candidate does not contain it, so those jobs and the image build fail until it is committed ([verification status](operations/release.md)).

## SDK and Auth Core compatibility

- Auth Core is upgraded before host apps ship a newer SDK. An SDK release is supported against an Auth Core of the same or a later minor version within the same major version.
- 2.0 is a major release for the SDKs as well. With Auth Core 2.0:
  - recovery setup needs SDK 2.0 on both platforms: Auth Core accepts only recovery protocol 2, and SDK 1.4 can neither set up nor complete a protocol 2 recovery;
  - Android enrolment and recovery need SDK 2.0: with `REQUIRE_VALID_ATTESTATION` (production) Auth Core refuses them without Keystore key attestation chains, which SDK 1.4 does not send;
  - credentials enrolled with SDK 1.4 remain usable after the upgrade once `sealCredentialBaseline` has sealed them; the authorization protocol and the device protocols are unchanged;
  - SDK 2.0 refuses recovery sessions without `recoveryPublicKeyPem` and `wrappedRecoveryKey`, so it cannot recover against Auth Core 1.4.
  The SDK API changes of 2.0 are listed in the [iOS](../ios-sdk/README.md) and [Android](../android-sdk/README.md) SDK guides and in the [upgrade guide](operations/upgrade-2.0.md#breaking-changes-for-app-teams).
- Every enrolled device signs its requests; Auth Core 2.0.0-rc.2 issues no token to an enrolled device. Devices enrolled by an SDK before 1.2, without an authentication key, can no longer call the mobile API and are enrolled again through device replacement.
- Offline confirmation is available only for devices enrolled while `OFFLINE_CONFIRMATION_ENABLED=true`. Devices enrolled earlier enrol again to use it.
- Evidence records sealed before migration 009 (schema 1) have no sealed payload. `scripts/verify-evidence.mjs` reports them as unsupported and verifies the rest of the chain. Schema 2 records keep their hash and seal in schema 3 chains and are reported as `legacy_records` (no key provenance).
- All four implementations of protocol v1 and device protocols v1 run the shared vectors in `auth-core/test-vectors/`, and Auth Core and both SDKs run the secure push and recovery protocol 2 vectors (the sandbox implements neither). A release in which any implementation fails them is not published.

## Deprecation policy

- A deprecation is announced in `CHANGELOG.md` under a "Deprecated" heading, naming the endpoint, field, setting or behavior, its replacement and the release that removes it.
- A deprecated item stays available for at least one minor release after the release that announces it, and is removed only in a major release when it belongs to the `/v1` API or a versioned protocol.
- Deprecated endpoints and fields remain in `openapi.yaml`, marked `deprecated: true`, until they are removed.
- Security fixes can shorten this period when keeping the old behavior would leave a vulnerability open. The changelog entry states the reason.

## Release 2.0: changes to `/v1` in place

Release 2.0 changes the behaviour of existing `/v1` endpoints in place instead of publishing them under `/v2`. These changes close vulnerabilities found in the 1.4 review (NXS findings); keeping the 1.4 behaviour available under `/v1` for a deprecation period would have kept them open. This uses the security clause of the [deprecation policy](#deprecation-policy). The release is a major version because of them.

| Endpoint or behaviour | Change in 2.0 |
|---|---|
| Bank token issuance and every bank API call | With `REQUIRE_MTLS_HEADER`, refused (401, audit event `bank_certificate_mismatch`) unless the gateway's client certificate fingerprint is registered for the client |
| `POST /v1/mobile/sessions` | 409 `ACTIVE_CREDENTIAL_EXISTS` while the identity has an `ACTIVE` credential, unless the token request carries `replacement {method, reference}`. From 2.0.0-rc.2 it issues only `BOOTSTRAP` tokens; `purpose: SESSION` returns 400 |
| `POST /v1/nexus-identities/{nexusId}/credentials`, `POST /v1/credentials/{credentialId}/rotate` | Removed in 2.0.0-rc.2 (404). Devices enrol only through `POST /v1/mobile/bootstrap` |
| `POST /v1/mobile/bootstrap`, `POST /v1/recovery/sessions/{sessionId}/complete` | From 2.0.0-rc.2 `authPublicKeyPem` is required (400 without it); the response always carries `requestAuthentication: DEVICE_SIGNATURE` and no access token |
| `POST /v1/mobile/bootstrap`, recovery completion (Android) | Refused with 403 without Keystore key attestation chains that meet `ANDROID_KEY_SECURITY_POLICY`, when attestation is required |
| `POST /v1/mobile/recovery/setup` | Accepts only protocol 2: `salt`, `recoveryPublicKeyPem`, `wrappedRecoveryKey` and a `signature` by the biometric signing key |
| `POST /v1/recovery/sessions` | 409 `RECOVERY_PROTOCOL_RETIRED` for protocol 1 identities; 409 `RECOVERY_LOCKED` after 10 failed proofs in 24 hours; 409 `RECOVERY_INTEGRITY`; the response adds `recoveryPublicKeyPem` and `wrappedRecoveryKey` |
| `POST /v1/recovery/sessions/{sessionId}/complete` | The proof is an ECDSA signature by the recovery key over the protocol 2 proof signing input, not an HMAC of the nonce; 409 `RECOVERY_INTEGRITY` |
| `POST /v1/authorizations` | 409 `CREDENTIAL_NOT_ATTESTED` with `REQUIRE_VALID_ATTESTATION` for a credential whose attestation is not `VERIFIED` |
| `POST /v1/authorizations/{id}/bank-commit-request` | 409 `IDENTITY_NOT_ACTIVE`, `CREDENTIAL_NOT_ACTIVE`, `CONFIRMATION_TOO_OLD` |
| Device-signed requests, confirmations, recovery setup | Refused for a credential whose keys do not match its sealed enrolment record; existing credentials need `sealCredentialBaseline` once |
| Evidence exports (`GET /v1/authorizations/{id}/evidence`, `GET /v1/nexus-identities/{nexusId}/evidence`) | Evidence schema 3: new record types in the chain, `chainSequence`, `sealKeyId`, `evidencePublicKeys`, the chain `head`; a single authorization export carries `credentialEnrolment` |
| Webhooks | New event types `credential.replaced`, `recovery.configured`, `identity.recovered` |

Additive changes in the same release (new response fields such as `evidenceHead` and `evidence`, the `replacement` request field) follow the ordinary rules. The admin console API (`/admin/api`) is not part of the versioned `/v1` API; its changes (TOTP login, bank scope, four-eyes approval with 202 responses) are listed in the [upgrade guide](operations/upgrade-2.0.md#breaking-changes-for-bank-backends) with every step a deployment and a bank backend take.

Release history is in [CHANGELOG.md](../CHANGELOG.md).
