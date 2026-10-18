# Package for an independent security review

Prepared 2026-10-18 for an external assessor (gate G8). **This is not an independent assessment.** The forensic inventory of 2026-10-16 and all remediation were produced by the same process; everything here is input to a review, not its result.

Scope under review: NEXUS-SIGN Auth Core, the iOS and Android SDKs, the optional call modules, the admin console, at local branch `remediation/2.0.0` (head `e8e90e7` or later). The local history is not the GitHub history (R-20); the assessor should review the code as merged into the owner's repository.

## Read first

| Topic | Document |
|---|---|
| Product and architecture | [README](../../README.md), [architecture](../architecture/), [audit: architecture and data flows](../audit/forensic-inventory/2026-10-16/03_ARCHITECTURE_AND_DATA_FLOWS.md) |
| Threat model | [threat model](../security/threat-model.md), [offline confirmation threat model](../security/offline-confirmation-threat-model.md) |
| Protocols | [authorization protocol v1](../protocol/authorization-protocol-v1.md), [device authentication and offline confirmation](../protocol/device-authentication-and-offline-confirmation.md), [offline confirmation v2](../protocol/offline-confirmation-v2-deferred-signature.md), [verification result v1](../protocol/verification-result-v1.md), [evidence format](../protocol/evidence-format.md), [secure push](../protocol/secure-push.md) |
| Audio/video calls | [ADR 0017](../adr/0017-in-app-audio-video-calls.md), [operations](../operations/audio-video-calls.md), [third-party media](../engineering/THIRD_PARTY_MEDIA.md) |
| Key management | [key management](../engineering/KEY_MANAGEMENT.md), [key rotation runbook](../operations/runbooks/key-rotation.md), [attestation](../security/attestation.md) |
| Dependencies | [dependency inventory](DEPENDENCY_INVENTORY.md) (not authoritative) |
| Decisions | [decision log](../engineering/DECISION_LOG.md) |
| Findings and status | [findings register](../audit/forensic-inventory/2026-10-16/11_FINDINGS_REGISTER.csv), [remediation history](../engineering/REMEDIATION_HISTORY.md), [remaining risks](../engineering/REMAINING_RISKS.md), [release gates](../engineering/RELEASE_GATES.md), [acceptance matrix](../engineering/ACCEPTANCE_MATRIX.csv) |
| Test evidence | [implementation progress](../engineering/IMPLEMENTATION_PROGRESS.md) (commands and results of the latest full regression) |

## Suggested focus

1. **Signing boundary:** the SDK parsers and display code (`SignedTransaction.kt/.swift`) against the shared vectors; whether the host app can make the system prompt show something other than the signed bytes; prompt layout on devices (FI-003).
2. **Device request authentication:** `middleware/mobileAuth.ts`, nonce store (PostgreSQL), clock handling, the mTLS gateway exemption list (`middleware/mtlsGateway.ts`).
3. **Evidence:** sealing (`evidenceService.ts`, PKCS#11 adapter), chain and head checkpoints (`evidence.appended`, `verify-evidence.mjs --heads`), integrity checks before key use (`credentialIntegrity.ts`).
4. **Key management:** `masterKeyVault.ts`, `secretBox.ts`, `cli/masterKeys.ts`, `cli/rotateSecretKeys.ts`, migration 020 (the trigger exception for re-encryption).
5. **Offline confirmation v2:** `submitDeferredSignature`, `acceptOfflineCode` and `expireUnsignedOfflineConfirmations` in `authorizationConfirmation.ts`, migration 022 (trigger), `offline-deferred-signature.test.mjs`; whether any path reports `VERIFIED` on a code alone; the residual cases in the threat model (forged v1 and enrolment records by a controlled Auth Core, provisional acted upon); the SDK ordering (signature stored before the code).
6. **Verification results and calls:** `crypto/jws.ts`, `verificationResult.ts` (claims, single use, key lookup), `verificationCall.ts` (Lua state machine, authorization of device and operator, closure), admin routes and console (`public/admin/calls.js`), TURN credential issuance.
7. **Admin console:** session and TOTP, CSRF, bank scope, four-eyes approvals.
8. **Mobile platforms:** key storage and access control (Secure Enclave, Keystore/StrongBox), pinning, the call modules' permission and lifecycle handling.

## Known limitations the assessor should not need to rediscover

- No native build, no device run, no vendor HSM, no authentic lockfile, no dependency or container scans, no load tests (REMAINING_RISKS.md R-01 … R-12).
- WebRTC binaries: provenance, checksums and licence inventory unverified (R-04).
- Offline codes are symmetric; v2 needs the device signature for `VERIFIED`, residual cases in R-07. Per-operation attestation is absent (R-08).
- A call shows a person; it does not identify them (R-17).

## Environment to reproduce the test results

PostgreSQL 16, Redis 7, SoftHSM 2.7 (built against OpenSSL, with `CKM_ECDSA_SHA256` and `CKM_AES_GCM`), Node.js 22, Chromium (Playwright 1.56.1) for media tests, JDK 17 for the Android JVM tests. CI jobs in `.github/workflows/ci.yml` provide the same services.
