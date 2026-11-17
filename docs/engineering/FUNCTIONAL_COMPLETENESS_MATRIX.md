# Functional completeness matrix

Every function of the product presentation (`NEXUS-SIGN.EN.pdf`, 34 pages: 44 software functions and 5 non-software items, 49 in all), checked against branch `engineering/production-readiness` in the fourth cycle, with the results of CI ([CI validation](CI_VALIDATION.md)). This is an internal engineering assessment, not a certification, regulatory mapping or penetration test. No function was added or removed in this cycle.

## Statuses used

| Status | Rule applied |
|---|---|
| VERIFIED IN CI | The function lives in Auth Core, the database or the console; its tests (unit, PostgreSQL/Redis, HTTP, SoftHSM, end-to-end, browser) passed in CI, and no phone or bank system is part of it |
| VERIFIED IN CI — DEVICE/BANK PENDING | Code exists on every side it needs; the server tests passed in CI and the SDKs built and passed their unit and vector tests in CI; what remains is a part only a real phone, the bank's HSM or the bank's systems can show |
| PARTIAL | Part of what the page shows is not in NEXUS-SIGN; the missing part is named |
| NOT IMPLEMENTED | — (no row) |
| VERIFIED ON REAL DEVICE, VERIFIED WITH BANK INFRASTRUCTURE, INDEPENDENTLY AUDITED | Not reached by any row: nothing ran on a phone, a bank system or the bank's HSM, and there has been no external audit |

Cell values: **run** — code exists and its tests passed in CI; **build** — SDK code that compiled for the platform and passed its unit and vector tests in CI (iOS: `swift test` and a device build; Android: Gradle build, unit tests, Lint); **device** — the end-to-end part on a phone, not run; **bank** — the bank's function; **—** — not applicable.

## Summary

| Status | Software functions |
|---|---|
| VERIFIED IN CI | 10 |
| VERIFIED IN CI — DEVICE/BANK PENDING | 33 |
| PARTIAL | 1 (F17, the bank's Verification of Payee) |
| NOT IMPLEMENTED | 0 |
| **Total software functions** | **44** |
| Non-software items (separate list) | 5 |

Change since the third cycle (7 verified locally, 36 implemented but not verified, 1 partial): every server, database and HSM suite and both SDK builds now pass in CI. The eight functions that were partial before the third cycle (customer-initiated call F12, console screens F32, D-07/F26, SIEM export F33, Kubernetes manifests F41, metrics F43, attestation tests F05, and F17) were checked again: seven are complete in code and pass in CI; F17 stays PARTIAL because Verification of Payee belongs to the bank. Checked for each row: code present, connected to the business process (route, service and database), error handling (every refusal has a reason code tested by vectors or suites), tests, documentation, and no mock or stub in the product code (mocks exist only in tests).

## Software functions

| ID | Page | Function | Business requirement | Backend | API | iOS | Android | UI | Security | Unit | Integration | E2E | Evidence | Final status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | 1 | Authorization inside the bank perimeter, keys on the device, verifiable evidence | Core value proposition | run | run | build | build | — | run | run | run | device | Aggregate of F02–F44 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F02 | 3 | Consent bound to amount, currency, payee, validity | Signature covers every displayed field | run | run | build | build | — | run | run | run | device | Vectors TS+Kotlin (8 valid, 59 invalid); bank-db-authorization 17; bank-p256 3; Swift passed in CI | VERIFIED IN CI — DEVICE/BANK PENDING |
| F03 | 5 | Push → confirmation screen from signed bytes → biometric → signature | Customer confirms on own device | run | run | build | build | SDK | run | run | — | device | Secure push unit tests; labelled prompt (D-02) in TS/Kotlin vectors; screen and prompt need a device | VERIFIED IN CI — DEVICE/BANK PENDING |
| F04 | 6 | Seven-step chain NEXUS ID → credential → binding → signature → single use → HSM → evidence | Chain of trust | run | run | build | build | — | run | run | run | device | evidence-outcomes 4, mandates 9; invariants (HTTP) and SoftHSM suites passed in CI | VERIFIED IN CI — DEVICE/BANK PENDING |
| F05 | 7 | Device setup with platform attestation | Only genuine apps on genuine devices enrol | run | run | build | build | SDK | run | run | — | device | attestation-parsers 16 (test chains, not device tokens); attestation-policy (HTTP, passed in CI) | VERIFIED IN CI — DEVICE/BANK PENDING |
| F06 | 8 | Nine-digit NEXUS ID independent of phone and SIM | Stable identifier | run | run | — | — | console | run | run | run | — | identity-create-retry 3 | VERIFIED IN CI |
| F07 | 9 | Notifications sealed per device | Private push content | run | run | build | build | SDK | run | run | — | device | secure-push vectors (TS); Android and iOS tests passed in CI; bank push contour external | VERIFIED IN CI — DEVICE/BANK PENDING |
| F08 | 9 | Notification feed | Customer sees events | run | run | build | build | SDK | — | — | run | device | customer-account 7 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F09 | 10 | Push, audio, video; calls never replace the signature | Adaptive verification | run | run | build | build | console | run | run | run | device | verification-call (HTTP, passed in CI); call engine 18 JVM tests | VERIFIED IN CI — DEVICE/BANK PENDING |
| F10 | 11 | Chat with the bank, transaction card, attachments, history | In-app conversation | run | run | build | build | console | run | — | run | device | conversations 4 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F11 | 12 | Bot assistant and handover to an operator | Bank bot + human | run | run | build | build | console | run | — | run | device | conversations 4; the bot itself is the bank's (webhooks + API) | VERIFIED IN CI — DEVICE/BANK PENDING |
| F12 | 12–13 | Customer-initiated call to the bank | Talk to the bank from the app | run | run | build | build | console | run | run | run | run | customer-calls 4 (PostgreSQL + Redis); CustomerCallWireTest 4; browser media test passed in CI | VERIFIED IN CI — DEVICE/BANK PENDING |
| F13 | 13 | Agent sees the caller is confirmed by the device key | Authenticated call | run | run | build | build | console | run | — | run | device | Device-signed signalling; verification-call (HTTP, passed in CI) | VERIFIED IN CI — DEVICE/BANK PENDING |
| F14 | 14 | Video check by bank policy and customer threshold | Risk-based step-up | run | run | build | build | SDK | run | — | run | device | customer-account threshold test; policy suites (HTTP, passed in CI) | VERIFIED IN CI — DEVICE/BANK PENDING |
| F15 | 15 | "It wasn't me", bank alerted, outcome sealed | Fraud report | run | run | build | build | SDK | run | — | run | device | authorization-decline 3, evidence-outcomes 4 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F16 | 15 | Look-alike characters and altered details detected | Display safety | run | run | build | build | SDK | run | run | run | device | Vectors in TS, Kotlin, Python sandbox (74); D-02 rules added; Swift passed in CI | VERIFIED IN CI — DEVICE/BANK PENDING |
| F17 | 15 | Payee checked against the bank's data | Payee verification | bank | — | — | — | — | — | — | — | — | Display side done (D-02); Verification of Payee is the bank's (PSP) function, not in NEXUS-SIGN | PARTIAL |
| F18 | 15 | Validity period; expired refused and recorded | Time-bound consent | run | run | build | build | — | run | run | run | device | Expiry outcome sealed (evidence-outcomes); expiry (HTTP, passed in CI) | VERIFIED IN CI |
| F19 | 16 | Offline QR, 8-digit code, recorded in evidence | Works without network | run | run | build | build | SDK | run | run | run | device | device-protocols vectors TS+Kotlin; offline-* (HTTP, passed in CI); D-01 open | VERIFIED IN CI — DEVICE/BANK PENDING |
| F20 | 17–18 | Recurring payment mandate | Signed terms, checked debits | run | run | build | build | console | run | run | run | device | mandates 9, bank-db-mandates 5, mandate vectors TS+Kotlin (20) | VERIFIED IN CI — DEVICE/BANK PENDING |
| F21 | 19 | Customer history | Transparency | run | run | build | build | SDK | — | — | run | device | customer-account 7 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F22 | 19 | Customer view of a payment's evidence | Verifiable record | run | run | build | build | SDK | run | — | run | device | customer-account 7 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F23 | 20 | My devices | Device management | run | run | build | build | SDK + console | run | — | run | device | customer-account, bank-console 5 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F24 | 20 | Several active devices | Phone and tablet | run | run | build | build | console | run | — | run | device | multiple-devices 6 (incl. race) | VERIFIED IN CI — DEVICE/BANK PENDING |
| F25 | 20 | New device approved from an existing one | Safe addition | run | run | build | build | SDK + console | run | — | run | device | device-replacement-hold 6, multiple-devices 6, bank-console 5 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F26 | 20 | Biometric change invalidates keys | Same behaviour on both platforms | — | — | build | build | SDK | run | — | — | device | D-07 fixed in iOS code; device procedure in biometric-behaviour.md | VERIFIED IN CI — DEVICE/BANK PENDING |
| F27 | 21 | Customer suspends the NEXUS ID | Self-protection | run | run | build | build | SDK | run | — | run | device | customer-account 7 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F28 | 21 | Bank suspends and reactivates | Bank control, four eyes | run | OpenAPI | — | — | console | run | run | run | — | Service tests on PostgreSQL; HTTP routes passed in CI | VERIFIED IN CI |
| F29 | 21 | Recovery with identity check | Lost device | run | run | build | build | SDK | run | run | run | device | recovery-phrase-once 2; recovery (HTTP, passed in CI); identity check is the bank's | VERIFIED IN CI — DEVICE/BANK PENDING |
| F30 | 22 | Customer sets channels, limits, video threshold | Customer control | run | run | build | build | SDK | run | — | run | device | customer-account 7 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F31 | 22 | Security log | Customer sees security events | run | run | build | build | SDK | run | — | run | device | customer-account 7 | VERIFIED IN CI — DEVICE/BANK PENDING |
| F32 | 23 | Bank console: payments, queues, mandates, devices, audit | Operations | run | console API | — | — | run (stubbed API) | run | — | run | — | bank-console 5, conversations 4, customer-calls 4, console-customer-screen (Chromium); HTTP routes passed in CI | VERIFIED IN CI |
| F33 | 24 | Layer to bank IAM, anti-fraud, core, SIEM | Integration | run | OpenAPI | — | — | — | run | — | run | — | audit-export 2 (ECS JSON, CEF); webhooks; anti-fraud adapters are bank-specific | VERIFIED IN CI |
| F34 | 25 | In the bank perimeter; push via bank infrastructure | Data stays at the bank | run | — | build | build | — | run | run | — | — | Push mode BANK; posture checks; a bank deployment is external | VERIFIED IN CI — DEVICE/BANK PENDING |
| F35 | 26 | Hardware key on the device | Non-exportable keys | — | — | build | build | — | — | — | — | device | Secure Enclave / StrongBox code; device checklist | VERIFIED IN CI — DEVICE/BANK PENDING |
| F36 | 26 | Any change to amount or payee breaks verification | Integrity | run | — | build | build | — | run | run | run | — | Vectors, fuzz, in-database ECDSA vs OpenSSL | VERIFIED IN CI |
| F37 | 26 | Replay protection: validity, nonce, single use | Anti-replay | run | run | build | build | — | run | run | run | device | invariants and nonce-store (HTTP, passed in CI); mandate and message idempotency verified | VERIFIED IN CI |
| F38 | 27 | Evidence for every outcome; chained; independent verifier | Non-repudiation | run | — | — | — | — | run | run | run | — | evidence-outcomes 4, mandates 9, backup-restore 4, offline verifier | VERIFIED IN CI |
| F39 | 28 | Native SDKs, Swift and Kotlin | Integration in the bank app | — | — | build | build | — | — | run | — | device | Android unit tests and Lint, iOS swift test (CI); Android and iOS builds passed in CI | VERIFIED IN CI — DEVICE/BANK PENDING |
| F40 | 28 | REST API with OpenAPI contract | Integration | run | run | — | — | — | — | run | — | — | 92 routes match; structural validation passes | VERIFIED IN CI |
| F41 | 29 | On premises or private cloud | Deployment | — | — | — | — | — | run | — | — | device | Kubernetes manifests checked against productionBlockers; not applied to a cluster | VERIFIED IN CI — DEVICE/BANK PENDING |
| F42 | 29 | Any HSM through PKCS#11 | HSM independence | run | — | — | — | — | run | run | run | device | hsm-worker-host 6, adapter deadline 3; SoftHSM suites passed in CI; no bank HSM | VERIFIED IN CI — DEVICE/BANK PENDING |
| F43 | 30 | Bank measures success, latency, fallback | Observability | run | — | — | — | — | — | — | run | — | Confirmation, outcome, backlog, HSM breaker metrics; metrics-access (HTTP, passed in CI) | VERIFIED IN CI |
| F44 | 34 | Summary | — | run | run | build | build | run | run | run | run | device | Aggregate | VERIFIED IN CI — DEVICE/BANK PENDING |

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
| The device acceptance checklist on real iPhones and Android phones | F01–F05, F07–F31, F35, F39 to VERIFIED ON REAL DEVICE |
| The HSM acceptance procedure on the bank's HSM; a pilot deployment | F04, F34, F41, F42 to VERIFIED WITH BANK INFRASTRUCTURE |
| The bank's Verification of Payee | F17 |
| External penetration test and cryptographic review | INDEPENDENTLY AUDITED |
