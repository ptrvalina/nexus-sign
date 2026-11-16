# Product feature compliance matrix

Every function the product presentation (`NEXUS-SIGN.EN.pdf`, 34 pages, "describes the target version of NEXUS-SIGN") shows, checked against this repository on branch `engineering/production-readiness`. It answers one question per row: does the code do what the page shows, and what was actually run to show it.

This is an internal engineering assessment, not a regulatory compliance mapping (PSD2/RTS SCA, EBA guidelines or similar are not assessed) and not a certification.

## Status values

| Status | Meaning |
|---|---|
| IMPLEMENTED | Code exists and tests for it were run in the review environment and passed |
| UNVERIFIED | Code exists, but its tests could not run in the review environment (see [why](#why-tests-could-not-run)); the code was read, not executed |
| PARTIAL | Part of what the page shows exists; the missing part is named |
| MISSING | No code in the repository does it |
| BLOCKED EXTERNAL | Can only be shown with something outside the repository: physical phones, a production HSM, a bank system |
| N/A | The page states a business, process or positioning point, not a software function |

No row is `MOCKED` (nothing is simulated in place of a real implementation in production code; test doubles exist only in tests) and no row is `FAILED` (no test of a listed function fails for a reason in the code).

### Why tests could not run

The review environment has no access to the npm registry, Maven, Gradle or Swift toolchains, no SoftHSM and no phones. Concretely: the Auth Core HTTP suites need `express`, `ioredis` and `prom-client`, which are not installed; the HSM suites need SoftHSM 2; the SDKs need Xcode and Gradle. What did run is listed in the [production readiness report](PRODUCTION_READINESS_REPORT.md#what-was-run).

## Summary

| Status | Rows |
|---|---|
| IMPLEMENTED | 8 |
| UNVERIFIED | 12 |
| PARTIAL | 10 |
| MISSING | 11 |
| BLOCKED EXTERNAL | 2 |
| N/A | 6 |

Total: 49 rows over the 34 pages (a page can show several functions). Rows marked IMPLEMENTED can still contain an UNVERIFIED part (for example the SDK side of a server feature); the row says so.

The largest gaps between the presentation and the code are the customer communication features (chat, bot, handover, customer-initiated calls, pages 11 to 13), recurring payment mandates (pages 17 to 19), the customer's own views and settings (device list, history, limits, security log, pages 19 to 22) and several devices per customer (page 20).

## Matrix

| Page | Function shown | Status | Evidence in the repository / what is missing |
|---|---|---|---|
| 1 | Transaction authorization inside the bank perimeter, keys on the device, verifiable evidence | UNVERIFIED | Auth Core (`auth-core/`), SDKs, evidence chain. End-to-end HTTP suites not run here; protocol vectors and unit tests ran |
| 2 | Problem statement (OTP gap) | N/A | |
| 3 | Consent bound to amount, currency, payee and validity; SDK inside the bank's app | IMPLEMENTED | Canonical signed bytes, [authorization protocol v1](../protocol/authorization-protocol-v1.md); `test:vectors` (8 valid, 54 invalid vectors) and property/fuzz unit tests passed. SDK embedding: UNVERIFIED (not compiled here) |
| 4 | Scenario map | N/A | Index of pages 5 to 22; each function is a row below |
| 5 | Push → confirmation screen rendered from the signed bytes → Face ID → device signature and record | UNVERIFIED | Push sealing: `secure-push` unit tests passed. Screen built from the signed bytes and biometric prompt: SDK code (`SignedTransaction.swift`, `SignedTransaction.kt`), not compiled or run on a phone |
| 6 | Seven-step chain: NEXUS ID, credential, binding, signature, single-use verification, HSM, evidence | UNVERIFIED | All steps exist in code. Single-use consumption (`invariants`), HSM sealing (`hsm`, `evidence-forgery-hsm`) suites need `ioredis` / SoftHSM |
| 7 | Device setup: platform attestation, key in the secure module, NEXUS ID | PARTIAL | Enrolment, attestation binding and Android key attestation exist. App Attest and Play Integrity verification (`appAttestService.ts`, `playIntegrityService.ts`) have no tests with real or recorded tokens. Key generation on device: BLOCKED EXTERNAL (phones) |
| 8 | Nine-digit NEXUS ID independent of the phone number; bank binds its customer to it | IMPLEMENTED | `nexusIdentityService.ts`; `identity-create-retry` (PostgreSQL, 3 tests) and regression unit tests passed. No written NEXUS ID specification yet ([known limitations](KNOWN_LIMITATIONS.md)) |
| 9 | Notifications: incoming payments, card debits, sealed per device | IMPLEMENTED | Push mode `NEXUS`, [secure push](../protocol/secure-push.md); unit tests passed |
| 9 | Event feed of past notifications | MISSING | No API lists a device's past messages (only `GET /v1/mobile/push-messages/{id}`) |
| 10 | Channels push, audio, video; audio and video never replace the signature | UNVERIFIED | Adaptive verification and provider result tokens ([verification result v1](../protocol/verification-result-v1.md)); suites `verification-call`, `verification-results` need `ioredis` |
| 11 | Chat with the bank in the app, transaction card in the chat, protected attachments, history kept by the bank | MISSING | No messaging component |
| 12 | Bot assistant, handover to an agent with chat history | MISSING | |
| 12–13 | Customer-initiated audio and video call to the bank without a phone number | PARTIAL | WebRTC calls exist only as a verification step of one authorization, opened for that authorization ([ADR 0017](../adr/0017-in-app-audio-video-calls.md)). A general call to the bank from the app does not exist. DTLS-SRTP is what WebRTC uses, but Auth Core does not enforce it (audit finding A2-11). SDK call modules not built here |
| 13 | Agent sees that the caller's identity is confirmed by the device key | UNVERIFIED | Call sessions are opened with a device-signed request and bound to the credential; the operator console (`public/admin/calls.js`) shows the session. Suite `verification-call` needs `ioredis` |
| 14 | Elevated risk: bank policy requires a video check, then the customer signs as usual | UNVERIFIED | Verification plan and escalation (`adaptiveVerificationService.ts`); suites need `ioredis`; SDK call module not built |
| 15 | "It wasn't me": the customer rejects, the bank is alerted | IMPLEMENTED | `POST /v1/mobile/authorizations/{id}/decline`, webhook `authorization.declined`; `authorization-decline` (PostgreSQL, 3 tests) passed. SDK `decline` method: UNVERIFIED |
| 15 | Look-alike characters and altered details are detected | IMPLEMENTED | [Display text rules](../protocol/authorization-protocol-v1.md#display-text-rules) in Auth Core, both SDKs and the sandbox; vectors, fuzz tests and a cross-language comparison (JavaScript, Python, Java rules agree on all generated cases) passed. SDK copies: UNVERIFIED (not compiled) |
| 15 | Payee in the request does not match the bank's data | PARTIAL | The SDK refuses a screen that differs from the signed bytes. There is no check of the payee against a bank payee registry; that is the bank's anti-fraud |
| 15 | Request validity period, expired requests refused | UNVERIFIED | `expires_at` in the signed bytes, expiry sweep; regression unit test of the reported state passed; `expiry` suite needs `ioredis` |
| 16 | Offline: QR code at a branch or ATM, phone checks and shows, 8-digit code bound to the transaction, added to the evidence chain | UNVERIFIED | Offline confirmation v2 (deferred device signature); device protocol vectors passed; `offline-*` suites need `ioredis`. The code is valid until the authorization's expiry, which the bank sets |
| 17–18 | Recurring payment mandate: payee, per-payment limit, frequency, validity signed with the device key; every debit checked; revocation in one step, recorded in the evidence chain | MISSING | No mandate model, API, signed mandate format or evidence record type |
| 19 | Customer's transaction history | MISSING | No customer-facing history API; the bank's own app would show its data |
| 19 | Customer's view of the evidence of a transaction | MISSING | Evidence is exported to the bank (`GET /v1/authorizations/{id}/evidence`), not to the device |
| 20 | "My devices": all devices that hold keys | MISSING | No device-facing list of credentials |
| 20 | Several active devices (phone and tablet) | MISSING | The database allows one `ACTIVE` credential per NEXUS ID (`idx_credentials_one_active`); a second device replaces the first. This is a design decision of the current version, not an omission in one place |
| 20 | Connecting a new device is approved from the old one | UNVERIFIED | Server: replacement hold, approve and cancel from the enrolled device; `device-replacement-hold` (PostgreSQL, 6 tests) passed. SDK methods not compiled; HTTP suite `device-replacement` needs `ioredis` |
| 20 | Changing Face ID or fingerprint revokes the confirmation keys | PARTIAL | iOS detects a changed biometric enrolment (`KeyManager.swift`), Android keys are bound to biometrics; the two platforms behave differently (audit finding D-07). BLOCKED EXTERNAL: needs phones |
| 21 | Customer suspends the NEXUS ID | MISSING | No device-facing suspend |
| 21 | Bank suspends the NEXUS ID | PARTIAL | Operator console (`POST /admin/api/identities/{id}/suspend`); no bank API call for it |
| 21 | Recovery with identity check and bank verification; new keys on the new phone, old device revoked and told | UNVERIFIED | Recovery protocol 2, single-use phrase and notice to the old device; `recovery-phrase-once` (PostgreSQL, 2 tests) passed; `recovery` HTTP suite needs `ioredis`. Video identification is the bank's own process |
| 22 | Customer chooses channels, sets limits and the threshold for a video check | MISSING | Limits exist only as bank configuration (for example `OFFLINE_CONFIRMATION_MAX_AMOUNT`) and bank policy references |
| 22 | Security log of logins and devices, export | MISSING | Audit log exists for the bank (`audit_logs`, console), not for the customer |
| 23 | Bank console: confirmations, requests queue, mandates, devices, audit | PARTIAL | Console has stats, audit log, webhook deliveries, verification call queue, identity view, four-eyes approvals. No list of authorizations, no mandates (missing), no devices view |
| 24 | Layer between the bank's app, Auth Core and bank systems (IAM, anti-fraud, core banking, SIEM) | PARTIAL | API, webhooks and audit log are the integration points; no ready connectors for SIEM or anti-fraud products |
| 25 | Deployed in the bank perimeter; push created and sent by the bank's infrastructure | IMPLEMENTED | Push mode `BANK`; deployment guide. Configuration and posture unit tests passed |
| 26 | Hardware key on the device | BLOCKED EXTERNAL | SDK key generation in Secure Enclave / StrongBox; needs phones ([device acceptance checklist](DEVICE_ACCEPTANCE_CHECKLIST.md)) |
| 26 | Transaction binding: any change to amount or payee makes verification fail | IMPLEMENTED | Vectors and fuzz tests; in the bank database `bank.p256_verify` matched OpenSSL on all generated cases (`bank-p256`, `bank-db-authorization`: 20 tests passed) |
| 26 | Replay protection: validity, nonce, atomic single use | UNVERIFIED | `invariants` and `nonce-store` suites need `ioredis` |
| 27 | Evidence record: request, credential, canonical hash, signature and time, credential state, channel, policy, result and reason; hash-chained, append-only, checked by an independent tool | PARTIAL | Sealed only for `VERIFIED` authorizations; declined, rejected and expired outcomes are not sealed records (audit finding B-04). The verifier refuses empty and unchecked chain ends. `evidence.test.mjs` did not run here (needs `prom-client`) |
| 28 | Native SDKs for iOS (Swift) and Android (Kotlin) | UNVERIFIED | Sources and tests exist; not compiled here (no toolchains) |
| 28 | REST API with OpenAPI contract | IMPLEMENTED | `check:openapi`: 49 routes match `openapi.yaml` |
| 29 | On premises or private cloud | PARTIAL | Docker image and [deployment guide](../operations/deployment.md); no Kubernetes manifests or Helm chart |
| 29 | Any HSM vendor through PKCS#11 | BLOCKED EXTERNAL | Adapter exists, tested against a PKCS#11 module double here; designed and tested on SoftHSM 2.7 only; no production HSM validated |
| 30 | Bank measures confirmation success, latency, fallback | PARTIAL | Metrics: HTTP request counts and durations, push and webhook outcomes. No confirmation success or fallback metric |
| 30–31 | Business value, approach comparison | N/A | The comparison's technical claims (binding, device key, NEXUS ID, structured record) correspond to the rows above |
| 32 | Implementation path (workshop, integration, acceptance with penetration test, pilot, launch) | N/A | Process. No penetration test has been done |
| 33 | Commercial model | N/A | |
| 34 | Summary | N/A | Aggregate of the rows above |
