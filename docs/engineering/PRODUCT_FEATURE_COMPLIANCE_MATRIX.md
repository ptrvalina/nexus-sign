# Functional coverage matrix

Every function of the product presentation (`NEXUS-SIGN.EN.pdf`, 34 pages), checked against branch `engineering/production-readiness`. Format and statuses of the Final Production Readiness Closure directive (v3.0). This is an internal engineering assessment, not a certification, regulatory mapping or penetration test.

## Statuses used

| Status | Rule applied |
|---|---|
| VERIFIED LOCALLY | The function's logic in this repository was exercised by tests that ran in the review environment (PostgreSQL 16, Redis 7, Node 22, the JVM, Chromium). HTTP wiring is checked against the OpenAPI contract only (`express` and `ioredis` are not installed here). No SDK part is needed, or only the server and database are involved |
| IMPLEMENTED — NOT VERIFIED | Code exists; at least one part (an SDK on a device, Swift, the Android build, an HTTP suite, SoftHSM, a cluster) did not run here |
| PARTIAL | Part of what the page shows is not in NEXUS-SIGN; the missing part is named |
| VERIFIED ON REAL DEVICE, VERIFIED WITH BANK INFRASTRUCTURE, INDEPENDENTLY AUDITED | Not reached by any row: nothing ran on a phone, a bank system or an HSM, and there has been no external audit |

Cell values: **run** — code exists and its tests ran here; **code** — code exists, not run here; **JVM** — Kotlin core compiled and tested on the JVM, not the Android build; **HTTP** — covered only by HTTP suites that did not run; **bank** — the bank's function; **—** — not applicable.

## Summary

| Status | Software functions |
|---|---|
| VERIFIED LOCALLY | 7 |
| IMPLEMENTED — NOT VERIFIED | 36 |
| PARTIAL | 1 |
| NOT IMPLEMENTED | 0 |
| **Total software functions** | **44** |
| Non-software items (separate list) | 5 |

Change since the previous matrix (7 verified, 29 external verification, 8 partial): the customer-initiated call, console screens for payments, mandates and devices, D-07, SIEM export, Kubernetes manifests, metrics and attestation tests were implemented; the statuses were also made stricter (a row with any unrun SDK part is not verified).

## Software functions

| ID | Page | Function | Business requirement | Backend | API | iOS | Android | UI | Security | Unit | Integration | E2E | Evidence | Final status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | 1 | Authorization inside the bank perimeter, keys on the device, verifiable evidence | Core value proposition | run | code | code | JVM | — | run | run | run | not run | Aggregate of F02–F44 | IMPLEMENTED — NOT VERIFIED |
| F02 | 3 | Consent bound to amount, currency, payee, validity | Signature covers every displayed field | run | code | code | JVM | — | run | run | run | not run | Vectors TS+Kotlin (8 valid, 59 invalid); bank-db-authorization 17; bank-p256 3; Swift not run | IMPLEMENTED — NOT VERIFIED |
| F03 | 5 | Push → confirmation screen from signed bytes → biometric → signature | Customer confirms on own device | run | code | code | JVM | SDK | run | run | — | not run | Secure push unit tests; labelled prompt (D-02) in TS/Kotlin vectors; screen and prompt need a device | IMPLEMENTED — NOT VERIFIED |
| F04 | 6 | Seven-step chain NEXUS ID → credential → binding → signature → single use → HSM → evidence | Chain of trust | run | code | code | JVM | — | run | run | run | not run | evidence-outcomes 4, mandates 9; invariants (HTTP) and SoftHSM suites not run | IMPLEMENTED — NOT VERIFIED |
| F05 | 7 | Device setup with platform attestation | Only genuine apps on genuine devices enrol | run | code | code | code | SDK | run | run | — | not run | attestation-parsers 16 (test chains, not device tokens); attestation-policy (HTTP) not run | IMPLEMENTED — NOT VERIFIED |
| F06 | 8 | Nine-digit NEXUS ID independent of phone and SIM | Stable identifier | run | code | — | — | console | run | run | run | — | identity-create-retry 3 | VERIFIED LOCALLY |
| F07 | 9 | Notifications sealed per device | Private push content | run | code | code | code | SDK | run | run | — | not run | secure-push vectors (TS); Android/iOS tests not run; bank push contour external | IMPLEMENTED — NOT VERIFIED |
| F08 | 9 | Notification feed | Customer sees events | run | code | code | code | SDK | — | — | run | not run | customer-account 7 | IMPLEMENTED — NOT VERIFIED |
| F09 | 10 | Push, audio, video; calls never replace the signature | Adaptive verification | run | code | code | JVM | console | run | run | HTTP | not run | verification-call (HTTP) not run; call engine 18 JVM tests | IMPLEMENTED — NOT VERIFIED |
| F10 | 11 | Chat with the bank, transaction card, attachments, history | In-app conversation | run | code | code | code | console | run | — | run | not run | conversations 4 | IMPLEMENTED — NOT VERIFIED |
| F11 | 12 | Bot assistant and handover to an operator | Bank bot + human | run | code | code | code | console | run | — | run | not run | conversations 4; the bot itself is the bank's (webhooks + API) | IMPLEMENTED — NOT VERIFIED |
| F12 | 12–13 | Customer-initiated call to the bank | Talk to the bank from the app | run | code | code | JVM | console | run | run | run | CI only | customer-calls 4 (PostgreSQL + Redis); CustomerCallWireTest 4; browser media test written, not run | IMPLEMENTED — NOT VERIFIED |
| F13 | 13 | Agent sees the caller is confirmed by the device key | Authenticated call | run | code | code | JVM | console | run | — | HTTP | not run | Device-signed signalling; verification-call (HTTP) not run | IMPLEMENTED — NOT VERIFIED |
| F14 | 14 | Video check by bank policy and customer threshold | Risk-based step-up | run | code | code | code | SDK | run | — | run | not run | customer-account threshold test; policy suites (HTTP) not run | IMPLEMENTED — NOT VERIFIED |
| F15 | 15 | "It wasn't me", bank alerted, outcome sealed | Fraud report | run | code | code | code | SDK | run | — | run | not run | authorization-decline 3, evidence-outcomes 4 | IMPLEMENTED — NOT VERIFIED |
| F16 | 15 | Look-alike characters and altered details detected | Display safety | run | code | code | JVM | SDK | run | run | run | not run | Vectors in TS, Kotlin, Python sandbox (74); D-02 rules added; Swift not run | IMPLEMENTED — NOT VERIFIED |
| F17 | 15 | Payee checked against the bank's data | Payee verification | bank | — | — | — | — | — | — | — | — | Display side done (D-02); Verification of Payee is the bank's (PSP) function, not in NEXUS-SIGN | PARTIAL |
| F18 | 15 | Validity period; expired refused and recorded | Time-bound consent | run | code | code | code | — | run | run | run | not run | Expiry outcome sealed (evidence-outcomes); expiry (HTTP) not run | IMPLEMENTED — NOT VERIFIED |
| F19 | 16 | Offline QR, 8-digit code, recorded in evidence | Works without network | run | code | code | JVM | SDK | run | run | HTTP | not run | device-protocols vectors TS+Kotlin; offline-* (HTTP) not run; D-01 open | IMPLEMENTED — NOT VERIFIED |
| F20 | 17–18 | Recurring payment mandate | Signed terms, checked debits | run | code | code | JVM | console | run | run | run | not run | mandates 9, bank-db-mandates 5, mandate vectors TS+Kotlin (20) | IMPLEMENTED — NOT VERIFIED |
| F21 | 19 | Customer history | Transparency | run | code | code | code | SDK | — | — | run | not run | customer-account 7 | IMPLEMENTED — NOT VERIFIED |
| F22 | 19 | Customer view of a payment's evidence | Verifiable record | run | code | code | code | SDK | run | — | run | not run | customer-account 7 | IMPLEMENTED — NOT VERIFIED |
| F23 | 20 | My devices | Device management | run | code | code | code | SDK + console | run | — | run | not run | customer-account, bank-console 5 | IMPLEMENTED — NOT VERIFIED |
| F24 | 20 | Several active devices | Phone and tablet | run | code | code | code | console | run | — | run | not run | multiple-devices 6 (incl. race) | IMPLEMENTED — NOT VERIFIED |
| F25 | 20 | New device approved from an existing one | Safe addition | run | code | code | code | SDK + console | run | — | run | not run | device-replacement-hold 6, multiple-devices 6, bank-console 5 | IMPLEMENTED — NOT VERIFIED |
| F26 | 20 | Biometric change invalidates keys | Same behaviour on both platforms | — | — | code | code | SDK | run | — | — | not run | D-07 fixed in iOS code; device procedure in biometric-behaviour.md | IMPLEMENTED — NOT VERIFIED |
| F27 | 21 | Customer suspends the NEXUS ID | Self-protection | run | code | code | code | SDK | run | — | run | not run | customer-account 7 | IMPLEMENTED — NOT VERIFIED |
| F28 | 21 | Bank suspends and reactivates | Bank control, four eyes | run | OpenAPI | — | — | console | run | run | run | — | Service tests on PostgreSQL; HTTP route checked by the contract only | VERIFIED LOCALLY |
| F29 | 21 | Recovery with identity check | Lost device | run | code | code | code | SDK | run | run | run | not run | recovery-phrase-once 2; recovery (HTTP) not run; identity check is the bank's | IMPLEMENTED — NOT VERIFIED |
| F30 | 22 | Customer sets channels, limits, video threshold | Customer control | run | code | code | code | SDK | run | — | run | not run | customer-account 7 | IMPLEMENTED — NOT VERIFIED |
| F31 | 22 | Security log | Customer sees security events | run | code | code | code | SDK | run | — | run | not run | customer-account 7 | IMPLEMENTED — NOT VERIFIED |
| F32 | 23 | Bank console: payments, queues, mandates, devices, audit | Operations | run | console API | — | — | run (stubbed API) | run | — | run | — | bank-console 5, conversations 4, customer-calls 4, console-customer-screen (Chromium); HTTP routes not run | VERIFIED LOCALLY |
| F33 | 24 | Layer to bank IAM, anti-fraud, core, SIEM | Integration | run | OpenAPI | — | — | — | run | — | run | — | audit-export 2 (ECS JSON, CEF); webhooks; anti-fraud adapters are bank-specific | VERIFIED LOCALLY |
| F34 | 25 | In the bank perimeter; push via bank infrastructure | Data stays at the bank | run | — | code | code | — | run | run | — | — | Push mode BANK; posture checks; a bank deployment is external | IMPLEMENTED — NOT VERIFIED |
| F35 | 26 | Hardware key on the device | Non-exportable keys | — | — | code | code | — | — | — | — | not run | Secure Enclave / StrongBox code; device checklist | IMPLEMENTED — NOT VERIFIED |
| F36 | 26 | Any change to amount or payee breaks verification | Integrity | run | — | code | JVM | — | run | run | run | — | Vectors, fuzz, in-database ECDSA vs OpenSSL | VERIFIED LOCALLY |
| F37 | 26 | Replay protection: validity, nonce, single use | Anti-replay | run | code | code | code | — | run | run | HTTP | not run | invariants and nonce-store (HTTP) not run; mandate and message idempotency verified | IMPLEMENTED — NOT VERIFIED |
| F38 | 27 | Evidence for every outcome; chained; independent verifier | Non-repudiation | run | — | — | — | — | run | run | run | — | evidence-outcomes 4, mandates 9, backup-restore 4, offline verifier | VERIFIED LOCALLY |
| F39 | 28 | Native SDKs, Swift and Kotlin | Integration in the bank app | — | — | code | JVM (39) | — | — | run | — | not run | Kotlin core on JVM 39 tests; Android and iOS builds not run | IMPLEMENTED — NOT VERIFIED |
| F40 | 28 | REST API with OpenAPI contract | Integration | run | run | — | — | — | — | run | — | — | 92 routes match; structural validation passes | VERIFIED LOCALLY |
| F41 | 29 | On premises or private cloud | Deployment | — | — | — | — | — | run | — | — | not run | Kubernetes manifests checked against productionBlockers; not applied to a cluster | IMPLEMENTED — NOT VERIFIED |
| F42 | 29 | Any HSM through PKCS#11 | HSM independence | run | — | — | — | — | run | run | SoftHSM | not run | hsm-worker-host 6, adapter deadline 3; SoftHSM suites not run; no bank HSM | IMPLEMENTED — NOT VERIFIED |
| F43 | 30 | Bank measures success, latency, fallback | Observability | run | — | — | — | — | — | — | HTTP | — | Confirmation, outcome, backlog, HSM breaker metrics; metrics-access (HTTP) not run | IMPLEMENTED — NOT VERIFIED |
| F44 | 34 | Summary | — | run | code | code | JVM | run | run | run | run | not run | Aggregate | IMPLEMENTED — NOT VERIFIED |

## Non-software items

These pages state positioning, process or commercial terms; there is nothing to implement.

| ID | Page | Item |
|---|---|---|
| N1 | 2 | Problem statement |
| N2 | 4 | Scenario map (index of pages 5–22) |
| N3 | 30–31 | Business value and comparison |
| N4 | 32 | Implementation path (pilot, pentest, bank acceptance) |
| N5 | 33 | Commercial model |

## What keeps rows from the next status

| Needed | Rows it unblocks |
|---|---|
| CI green on the branch: `express`/`ioredis` HTTP suites, iOS and Android builds, SoftHSM suites, browser media tests | Most rows to VERIFIED LOCALLY |
| The device acceptance checklist on real iPhones and Android phones | F01–F05, F07–F31, F35, F39 to VERIFIED ON REAL DEVICE |
| The HSM acceptance procedure on the bank's HSM; a pilot deployment | F04, F34, F41, F42 to VERIFIED WITH BANK INFRASTRUCTURE |
| The bank's Verification of Payee | F17 |
| External penetration test and cryptographic review | INDEPENDENTLY AUDITED |
