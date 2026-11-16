# Product feature compliance matrix

Every function the product presentation (`NEXUS-SIGN.EN.pdf`, 34 pages, the target version of NEXUS-SIGN) shows, checked against this repository on branch `engineering/production-readiness` at the commit that last changed this file. One question per row: does the code do what the page shows, and what was actually run to show it.

This is an internal engineering assessment. It is not a regulatory mapping (PSD2/RTS SCA and similar are not assessed), not a certification and not a penetration test.

## Status values

| Status | Meaning |
|---|---|
| IMPLEMENTED AND VERIFIED | Code exists and its tests ran in the review environment and passed |
| IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Code exists; the part that remains unproven needs something this environment does not have: the SDK toolchains (Xcode, Gradle), phones, SoftHSM or a production HSM, the HTTP stack packages (`express`, `ioredis`, `prom-client`), or the bank's systems. The server part is verified where the row says so |
| PARTIAL | Part of what the page shows exists; the missing part is named |
| NOT APPLICABLE | The page states a business, process or positioning point, not a software function |

What "verified" covers: service-level tests on PostgreSQL 16 with the full schema and all migrations (14 suites, 79 tests), unit tests, protocol vectors, OpenAPI contract check, the sandbox and the demo bank. The Auth Core HTTP suites (22, need `ioredis`), the SoftHSM suites (8), the SDK builds and anything on a phone did not run. The [final engineering report](FINAL_ENGINEERING_REPORT.md#7-test-results) lists commands and results.

## Summary

| Status | Rows |
|---|---|
| IMPLEMENTED AND VERIFIED | 7 |
| IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | 29 |
| PARTIAL | 8 |
| NOT APPLICABLE | 5 |

49 rows over 34 pages. No row is MISSING. Eight rows remain PARTIAL; each is listed under [remaining gaps](#remaining-gaps). Before this branch: 8 IMPLEMENTED, 12 UNVERIFIED, 10 PARTIAL, 11 MISSING, 2 BLOCKED EXTERNAL, 6 N/A (statuses of the earlier version of this matrix).

## Matrix

| Page | Function shown | Status | Evidence / what is missing |
|---|---|---|---|
| 1 | Transaction authorization inside the bank perimeter, keys on the device, verifiable evidence | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Auth Core, SDKs, evidence chain. End-to-end needs the HTTP suites, phones and an HSM |
| 2 | Problem statement | NOT APPLICABLE | |
| 3 | Consent bound to amount, currency, payee, validity | IMPLEMENTED AND VERIFIED | Canonical bytes, [protocol v1](../protocol/authorization-protocol-v1.md); `test:vectors` (8 valid, 54 invalid), property and fuzz tests; in the bank database `bank-p256` and `bank-db-authorization` (20 tests) |
| 4 | Scenario map | NOT APPLICABLE | Index of pages 5–22 |
| 5 | Push → confirmation screen from the signed bytes → Face ID → signature | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Secure push unit tests pass; the screen and biometric prompt are SDK code, not compiled here |
| 6 | Seven-step chain (NEXUS ID → credential → binding → signature → single use → HSM → evidence) | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Evidence sealing verified on PostgreSQL with the software HSM; single-use (`invariants`) and SoftHSM suites not run |
| 7 | Device setup with platform attestation | PARTIAL | Enrolment and attestation binding exist. App Attest and Play Integrity verification has no tests with recorded tokens (open) |
| 8 | Nine-digit NEXUS ID, independent of phone and SIM | IMPLEMENTED AND VERIFIED | `identity-create-retry` (3), regression unit tests |
| 9 | Notifications (payments, card debits), sealed per device | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Unit tests pass; the bank's real push contour is external |
| 9 | Event feed of notifications | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | `GET /v1/mobile/notifications`, `customer-account` test "a payment creates a feed entry" passes; SDK `notifications()` not compiled |
| 10 | Push, audio, video; audio and video never replace the signature | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Adaptive verification; call suites need `ioredis`; SDK call modules not built here |
| 11 | Chat with the bank, transaction card, protected attachments, history | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Server verified: `conversations` (4 tests: flow, isolation, retries, tamper). Attachments are bank-stored with a SHA-256. SDK not compiled. [Conversations](../architecture/customer-conversations.md) |
| 12 | Bot assistant and handover to an operator | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Handover and operator queue verified (`conversations`); the bot itself is the bank's, connected through `conversation.message` webhooks and `/v1/conversations/{id}/bot-messages` |
| 12–13 | Customer-initiated call to the bank, outside a payment check | PARTIAL | Calls exist as a verification step of one authorization. A general call from the app is not implemented |
| 13 | Agent sees that the caller is confirmed by the device key | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Device-signed call sessions; `verification-call` suite needs `ioredis` |
| 14 | Video check required by the bank's policy and by the customer's own threshold | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Customer threshold verified (`customer-account` "above the customer's threshold the plan requires a video check"); bank policy suites need `ioredis` |
| 15 | "It wasn't me", the bank is alerted, the outcome is sealed | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Verified on PostgreSQL (`authorization-decline` 3, `evidence-outcomes` 4); SDK `decline` not compiled |
| 15 | Look-alike characters and altered details detected | IMPLEMENTED AND VERIFIED | Display rules in Auth Core, SDKs, sandbox; vectors, fuzz, cross-language comparison (JavaScript, Python, Java agree). SDK copies not compiled |
| 15 | Payee checked against the bank's data | PARTIAL | The SDK refuses a screen that differs from the signed bytes; a payee registry check is the bank's anti-fraud and is not in NEXUS-SIGN |
| 15 | Validity period; expired requests refused and recorded | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Expiry outcome sealed (`evidence-outcomes`); the HTTP `expiry` suite needs `ioredis` |
| 16 | Offline QR, 8-digit code, recorded in the evidence chain | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Offline v2 with deferred signature; vectors pass; `offline-*` suites need `ioredis`; phones needed |
| 17–18 | Recurring payment mandate: terms signed on the device, every debit checked, suspension, revocation, evidence | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Server and bank database verified: `mandates` (8), `bank-db-mandates` (5). Signing on the device is SDK code, not compiled. [Payment mandates v1](../protocol/payment-mandates-v1.md) |
| 19 | Customer's history (confirmed, declined, open) | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Server verified (`customer-account`); SDK `history()` not compiled |
| 19 | Customer's view of a payment's evidence | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Server verified (`customer-account`, evidence of a declined payment); SDK not compiled |
| 20 | "My devices" | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Server verified; SDK `devices()`, `removeDevice()` not compiled |
| 20 | Several active devices (phone and tablet) | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Server verified: `multiple-devices` (6), including two concurrent writers against the limit. Default limit 1 per bank client |
| 20 | New device approved from an existing one | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | `device-replacement-hold` (6), `multiple-devices`; SDK not compiled |
| 20 | Changing Face ID or fingerprint invalidates the keys | PARTIAL | iOS and Android behave differently (finding D-07, open); needs phones |
| 21 | Customer suspends the NEXUS ID | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Server verified (`customer-account`: open payments cancelled with a sealed outcome, new ones refused); SDK not compiled |
| 21 | Bank suspends and reactivates the NEXUS ID | IMPLEMENTED AND VERIFIED | Bank API `suspend`/`reactivate` with the re-identification reference; service tests on PostgreSQL. The HTTP route is checked by the OpenAPI contract only |
| 21 | Recovery with identity check; old device revoked and told | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | `recovery-phrase-once` (2); HTTP `recovery` suite needs `ioredis`; the identity check itself is the bank's process |
| 22 | Customer sets channels, limits, video threshold | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Server verified (`customer-account`: tightening at once, relaxing after the hold, concurrent payments against the daily limit); SDK not compiled |
| 22 | Security log | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Server verified (`customer-account`: no operator names or addresses); SDK not compiled |
| 23 | Bank console: confirmations, queue, mandates, devices, audit | PARTIAL | Console: stats, audit log, webhooks, call queue, conversation queue, identities, four-eyes approvals. Mandates and devices are in the bank API but have no console screens; no authorization list screen |
| 24 | Layer between the bank's app, Auth Core and bank systems (IAM, anti-fraud, core, SIEM) | PARTIAL | API, webhooks, audit log; no ready SIEM or anti-fraud connectors |
| 25 | Deployed in the bank perimeter; push by the bank's infrastructure | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Push mode `BANK`; configuration and posture unit tests pass; a real bank deployment is external |
| 26 | Hardware key on the device | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Secure Enclave / StrongBox code; [device acceptance checklist](DEVICE_ACCEPTANCE_CHECKLIST.md) |
| 26 | Any change to amount or payee breaks verification | IMPLEMENTED AND VERIFIED | Vectors, fuzz, in-database ECDSA against OpenSSL |
| 26 | Replay protection: validity, nonce, single use | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | `invariants`, `nonce-store` need `ioredis`; mandate debits and conversation messages are idempotent and verified |
| 27 | Evidence for every outcome; hash-chained, append-only, independent verifier | IMPLEMENTED AND VERIFIED | `evidence-outcomes` (4), mandate chain tests in `mandates` (tamper and removal detected); verifier `scripts/lib/evidence.mjs`. `evidence.test.mjs` itself did not run (needs `prom-client`) |
| 28 | Native SDKs, Swift and Kotlin | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Not compiled here; CI jobs `ios-sdk` and `android-sdk` must build them |
| 28 | REST API with OpenAPI contract | IMPLEMENTED AND VERIFIED | `check:openapi`: 85 routes match; YAML parses and every `$ref` resolves |
| 29 | On premises or private cloud | PARTIAL | Docker image and deployment guide; no Kubernetes manifests or Helm chart |
| 29 | Any HSM through PKCS#11 | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Worker-thread adapter verified against a module double (`hsm-worker-host` 6, `pkcs11-adapter-deadline` 3); SoftHSM suites not run; no production HSM validated |
| 30 | Bank measures success, latency, fallback | PARTIAL | Prometheus metrics: HTTP request counts and durations, push and webhook delivery outcomes. No confirmation-success, fallback or HSM-availability metric; the bank derives outcomes from webhooks |
| 30–31 | Business value, comparison | NOT APPLICABLE | |
| 32 | Implementation path | NOT APPLICABLE | No penetration test has been done |
| 33 | Commercial model | NOT APPLICABLE | |
| 34 | Summary | IMPLEMENTED — EXTERNAL VERIFICATION REQUIRED | Aggregate of the rows above |

## Remaining gaps

| Row | What is missing | Why it is not closed here |
|---|---|---|
| Page 7, attestation | Tests of App Attest and Play Integrity verification with recorded tokens | Needs tokens from real devices or Google/Apple test fixtures; none are available offline |
| Page 12–13, customer-initiated call | A call from the app to the bank outside a payment check | Requires a call-routing design (queue of operators, call without an authorization subject); not started |
| Page 15, payee registry | Checking the payee against the bank's own data | The bank's anti-fraud function; NEXUS-SIGN guarantees only that the screen equals the signed bytes |
| Page 20, biometric change | One behaviour on iOS and Android | Finding D-07; any change must be tested on phones |
| Page 23, console | Screens for mandates, devices and authorizations | The data is in the bank API; screens not built yet |
| Page 24, connectors | SIEM and anti-fraud adapters | Bank-specific; the API and webhooks are the integration points |
| Page 29, deployment | Kubernetes manifests or Helm chart | Not started |
| Page 30, metrics | Confirmation success, fallback and HSM availability metrics | Not added yet; the data exists in webhooks, outcomes and the HSM breaker state |
