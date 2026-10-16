# 0002. Device-signed requests after enrolment

## Status

Accepted

## Date

2026-09-30

## Context

After enrolment the SDK fetches authorizations, reads verification plans, escalates, opens verification sessions and submits signatures. A bearer token for these calls has to be obtained from the bank backend, stored on the phone and sent with every request. It can be copied from device storage, from logs or from a proxy, and replayed from anywhere until it expires.

The phone already holds hardware-backed keys, and Auth Core already verifies an attestation at enrolment.

## Decision

- At enrolment the SDK creates a P-256 authentication key next to the signing key (Secure Enclave or Android Keystore, not exportable, usable while the device is unlocked, no biometric prompt). Its public key is covered by the same attestation as the other device keys.
- Every mobile request carries `X-NEXUS-Credential`, `X-NEXUS-Timestamp`, `X-NEXUS-Nonce` and `X-NEXUS-Signature`: ECDSA P-256 over the domain string, method, path and query as sent, timestamp, nonce, credential ID and the SHA-256 of the body (`deviceRequestSigningInput` in `deviceProtocol.ts`).
- Auth Core accepts a timestamp within `DEVICE_REQUEST_MAX_SKEW_SECONDS` (default 300), verifies the signature, then records the nonce in Redis with `SET NX` for twice the window (`mobileAuth.ts`).
- Once an identity's active credential has an authentication key, Auth Core neither issues nor accepts `SESSION` tokens for it. Enrolment and recovery responses state `requestAuthentication: DEVICE_SIGNATURE` or `BEARER`.
- `SESSION` tokens remain for devices enrolled by an SDK without an authentication key. Each is bound to the credential that was active when it was issued and stops working when that credential is revoked, rotated or replaced, or when the bank client is `DISABLED`.
- The bank backend issues one `BOOTSTRAP` token per enrolment: single use, 300 s.

Superseded in part by [0016](0016-remove-compatibility-paths.md): since 2.0.0-rc.2 `SESSION` tokens and `requestAuthentication: BEARER` no longer exist.

## Consequences

- No reusable credential for the mobile API exists on an enrolled phone. A captured request cannot be replayed or moved to another path or body.
- Requests sent while the device is locked fail on Android with `DeviceLocked`.
- A phone with a wrong clock is told `serverTime` and corrects its offset, at most 24 hours, then retries once.
- A gateway that strips a path prefix needs `DEVICE_REQUEST_PATH_PREFIX`, because the device signs the path it sends.
- Each request costs one Redis write for the nonce.
- Details: [device authentication and offline confirmation](../protocol/device-authentication-and-offline-confirmation.md).
