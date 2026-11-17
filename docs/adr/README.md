# Architecture decision records

Each record states one decision, its context and its consequences.

| ADR | Decision | Status | Date |
|---|---|---|---|
| [0001](0001-canonical-json-signed-payload.md) | Sorted-key `JSON.stringify` bytes as the signed payload form, with a strict re-encode check on devices | Accepted | 2026-09-26 |
| [0002](0002-device-signed-requests.md) | Hardware-key request signatures after enrolment; legacy `SESSION` tokens bound to the credential | Accepted, superseded in part by 0016 | 2026-09-30 |
| [0003](0003-offline-confirmation-hmac-codes.md) | Offline confirmation with an ECDH-derived per-credential key, 8-digit HMAC codes and an attempt limit | Accepted | 2026-09-30 |
| [0004](0004-append-only-evidence-chain.md) | HSM-sealed, per-identity hash-chained, append-only evidence with the signed bytes and device key | Accepted | 2026-09-29 |
| [0005](0005-two-phase-key-replacement.md) | Two-phase key replacement for enrolment and recovery, serialized per process | Accepted | 2026-09-30 |
| [0006](0006-plain-dom-admin-console.md) | Plain DOM operator console without framework or build step | Accepted | 2026-09-26 |
| [0007](0007-iso-4217-minor-units-table.md) | Fixed ISO 4217 minor-unit table in the SDKs | Accepted | 2026-09-30 |
| [0008](0008-secure-push-delivery.md) | Push mode per bank client; messages sealed per device before storage, providers see only the envelope, HMAC receipts | Accepted | 2026-10-01 |
| [0009](0009-evidence-schema-3.md) | Evidence schema 3: sealed credential enrolment and recovery records, numbered chains, chain head returned to the bank, seal key IDs | Accepted | 2026-10-06 |
| [0010](0010-recovery-protocol-v2.md) | Recovery protocol 2: a P-256 recovery key wrapped under the phrase, biometric-signed setup, protocol 1 retired | Accepted, superseded in part by 0016 | 2026-10-06 |
| [0011](0011-android-key-attestation-policy.md) | Android Keystore key attestation verified to Google roots, with a security level policy; security level taken from the evidence | Accepted | 2026-10-06 |
| [0012](0012-explicit-device-replacement.md) | A new device for an enrolled identity only with the bank's replacement authorization; audited, sealed, reported and announced | Accepted | 2026-10-06 |
| [0013](0013-database-enforced-state-machines.md) | Lifecycle transitions and binding columns enforced by database triggers; one active credential per identity | Accepted, superseded in part by 0016 | 2026-10-06 |
| [0014](0014-admin-scope-mfa-four-eyes.md) | Admin accounts scoped to a bank, TOTP login, four-eyes revoke and reactivate, session version and idle timeout | Accepted | 2026-10-06 |
| [0015](0015-client-certificate-binding.md) | Bank token issuance and use bound to the registered client certificate fingerprints | Accepted | 2026-10-06 |
| [0016](0016-remove-compatibility-paths.md) | Remove bank-side provisioning and rotation, recovery protocol 1 and its verifiers, `SESSION` tokens and the unused schema | Accepted | 2026-10-07 |
| [0017](0017-in-app-audio-video-calls.md) | In-app audio and video calls over WebRTC, signalling relayed by Auth Core, answered by bank operators or closed by signed provider results; bank TURN; no recording | Accepted (WebRTC binaries in the SDKs pending owner approval) | 2026-10-16 |
| [0018](0018-deferred-device-signature.md) | Offline confirmation v2: the phone also signs the canonical bytes and uploads the signature later; a code alone leaves the payment `OFFLINE_PROVISIONAL`; QR `NXS2.`; required in production | Accepted (iOS not compiled, devices not tested) | 2026-10-18 |
