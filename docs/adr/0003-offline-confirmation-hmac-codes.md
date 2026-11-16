# 0003. Offline confirmation with HMAC codes

## Status

Accepted

## Date

2026-09-30

## Context

Banks want customers to confirm a transaction shown on a branch screen, an ATM or web banking with a phone that has no network. The phone can read a QR code and the customer can type a short code back. A full ECDSA signature (about 70 bytes) cannot be typed by a customer, so the returned value has to be short and still bound to the exact transaction.

## Decision

- At enrolment the device sends an offline public key. Auth Core generates a fresh P-256 key pair for the credential, computes the ECDH shared secret and derives `K = HKDF-SHA256(Z, salt "NEXUS-SIGN/OFFLINE/v1", info credential ID, 32 bytes)`. It stores `K` encrypted with `DEVICE_SECRET_ENCRYPTION_KEY` (AES-256-GCM, associated data bound to the credential ID), discards its private key and returns its public key.
- On the device, iOS keeps the offline key in the Secure Enclave and computes `K` inside the biometric prompt for each confirmation. Android imports `K` once into the Keystore as a non-exportable HMAC key that needs a biometric for every use.
- The QR code carries `NXS1.` and the base64url canonical authorization bytes. The phone applies the same strict checks as online, shows the transaction and computes `HMAC-SHA256(K, "NEXUS-SIGN/OFFLINE-CODE/v1" || 0x00 || SHA-256(bytes))`, truncated as in RFC 4226 to 8 digits.
- Auth Core compares the code under a row lock on the authorization, in constant time. Wrong codes share the limit of five attempts with signature attempts; the fifth failure rejects the authorization.
- A correct code runs the same identity, credential and verification plan checks as a signature, and the evidence record has `confirmationMethod: OFFLINE_CODE` and `signatureFormat: hmac`.
- The feature is off unless `OFFLINE_CONFIRMATION_ENABLED=true`; startup refuses that setting without `DEVICE_SECRET_ENCRYPTION_KEY`.

## Consequences

- Guessing succeeds with probability 5 in 10^8 per authorization.
- The code proves that the enrolled device confirmed the displayed bytes after a biometric check. Auth Core also holds `K`, so the code is not verifiable by a third party. `scripts/verify-evidence.mjs` counts these records separately, and banks that need non-repudiation for a payment type require online confirmation for it.
- The phone cannot learn of a revocation while offline; Auth Core rejects codes for a revoked or suspended credential at confirmation.
- Without `DEVICE_SECRET_ENCRYPTION_KEY` the stored offline keys cannot be decrypted; the affected devices have to enrol again for offline confirmation.
- Shared vectors: `auth-core/test-vectors/device-protocols-v1.json`. Specification: [device authentication and offline confirmation](../protocol/device-authentication-and-offline-confirmation.md).

## Amendment 2026-10-18 (2.0.0, )

Whoever holds the database and `DEVICE_SECRET_ENCRYPTION_KEY` can compute a valid code for any pending authorization of an offline-enabled credential, and the resulting evidence record is sealed like any other. This is inherent in a short symmetric code and cannot be removed without giving up offline use. Mitigations:

- **Amount cap set by the deployment:** `OFFLINE_CONFIRMATION_MAX_AMOUNT` (per currency, minor units), required in production when offline confirmation is enabled. Currencies not listed are not offered offline. The cap lives in the deployment configuration, not in the database, so a database change alone cannot raise it.
- **Master key protection:** the key ring and re-encryption tool allow rotation; wrapping the master key in the HSM is still open.
- **Evidence:** records keep `confirmationMethod: OFFLINE_CODE`; the verifier counts them separately. Banks that need non-repudiation require online confirmation (device signature) for that payment type.
- **Option not implemented:** a deferred device signature, uploaded by the phone when it is online again, could upgrade an offline confirmation to a verifiable one. It needs a protocol and SDK change and an owner decision.

## Amendment (2026-10-18)

Superseded in part by [ADR 0018](0018-deferred-device-signature.md): with `OFFLINE_CONFIRMATION_MODE=deferred_signature` (default, required in production) a code no longer confirms an authorization by itself; the device's deferred signature over the same bytes is required. The code protocol of this ADR is unchanged and still used in both versions.
