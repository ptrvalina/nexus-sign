# 0011. Android Keystore key attestation with a security level policy

## Status

Accepted

## Date

2026-10-06

## Context

Android enrolment was verified with Play Integrity only. Play Integrity speaks for the app and the device, not for an individual key: it says nothing about whether the signing key was generated in TEE or StrongBox, whether it requires biometric authentication, or whether it is the key the request carries. The security level stored with the credential was the value the client reported.

## Decision

- The Android SDK generates the signing and authentication keys with an attestation challenge `SHA-256("NEXUS-SIGN/KEY-ATTESTATION/v1" || 0x00 || enrolment challenge)` and sends both certificate chains with the Play Integrity token.
- Auth Core verifies each chain to one of the two Google root public keys embedded in the code, applies strict validity to Remote Key Provisioning chains, refuses certificates listed in Google's attestation status list (`ANDROID_ATTESTATION_STATUS_FILE`), checks that the leaf key is the enrolled key, and checks the KeyDescription: challenge, origin `GENERATED`, EC P-256 signing key, package name and app signing certificate digests (`ANDROID_APP_CERT_SHA256`), biometric authentication required for the signing key, and a locked bootloader with verified boot (`ANDROID_REQUIRE_LOCKED_BOOTLOADER`, default on).
- `ANDROID_KEY_SECURITY_POLICY` selects `REQUIRE_STRONGBOX`, `REQUIRE_HARDWARE_BACKED` (default; `ALLOW_TEE` is accepted with the same meaning) or `ALLOW_SOFTWARE` (development only, production blocker). A key below the policy fails; there is no silent fallback.
- The credential's platform and security level are taken from the verified evidence (the weaker of the two Android keys, `SECURE_ENCLAVE` for iOS), never from the client, wherever attestation is verified.
- The chains are sealed with the enrolment record so they can be re-checked later.

## Consequences

- An enrolled Android signing key is known to be hardware-backed (or StrongBox), bound to this enrolment and app, and unusable without a biometric, as far as the device's attestation can be trusted.
- Operations must download and refresh Google's status list. Auth Core does not check its age; a stale list accepts recently revoked attestation keys. An unreadable file fails Android enrolments.
- Devices with an unlocked bootloader cannot enrol under the default settings.
- The embedded roots must be updated when Google adds a root.
- Imported keys (offline key, push key) are not covered.
- The acceptance of a biometric-bound key and the SDK's key generation are verified on devices; the server tests use real device chains of keys without user authentication. See [Android key attestation](../security/attestation.md#android-key-attestation).
