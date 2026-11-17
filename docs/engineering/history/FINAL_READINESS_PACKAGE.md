# NEXUS-SIGN — Final production readiness package

> **Record of the third cycle.** Superseded for status by [engineering readiness](../ENGINEERING_READINESS.md) (fourth cycle), which has the CI results this package could not have. Numbers below are as of the third cycle.

Directive: *Master Engineering Directive — Final Production Readiness Closure, v3.0*. Branch `engineering/production-readiness`, 41 commits on top of `2.0.0-rc.2` (`5999984`), of which 14 in this cycle (`770092f` … the commit of this package). Nothing has been pushed, published or deployed; no real bank data or keys were used.

---

## A. Executive summary

**Final decision: NOT COMPLETE — BLOCKERS REMAIN.**

All 44 software functions of the product presentation have code; none is NOT IMPLEMENTED. This cycle closed in code the seven partial functions that are NEXUS-SIGN's to close: the customer-initiated call to the bank, console screens for payments, mandates and devices, one biometric behaviour on iOS and Android (D-07), SIEM export, Kubernetes manifests, confirmation and HSM metrics, and tests of the attestation checks. D-02 is fixed in code on all four implementations; D-01 has a documented decision. The eighth partial, checking the payee against the bank's records, is the bank's own function (Verification of Payee) and stays PARTIAL.

What blocks the next status is verification, not code: nothing has run on a phone, on the bank's HSM or in the bank's infrastructure; the iOS SDK has never been compiled; the HTTP, SoftHSM and browser-media suites have not run on this branch because CI has not run (nothing pushed); there has been no external penetration test.

| | Before this cycle | Now |
|---|---|---|
| Functions VERIFIED LOCALLY / implemented, not verified / PARTIAL / not implemented | 7 / 29 / 8 / 0 (old scale) | 7 / 36 / 1 / 0 (stricter scale) |
| Open High / Medium findings | 0 / 2 | 0 / 1 (D-01, decided) |
| Service-level suites passing here | 14 suites, 79 tests | 18 suites, 95 tests |
| Kotlin tests run on the JVM | 17 | 39 |

## B. Functional coverage matrix

[`FUNCTIONAL_COMPLETENESS_MATRIX.md`](../FUNCTIONAL_COMPLETENESS_MATRIX.md): 44 software functions with backend, API, iOS, Android, UI, security, unit, integration, E2E, evidence and final status; the 5 non-software items listed separately. VERIFIED LOCALLY 7, IMPLEMENTED — NOT VERIFIED 36, PARTIAL 1 (F17 payee check, the bank's), NOT IMPLEMENTED 0. No row reaches VERIFIED ON REAL DEVICE, VERIFIED WITH BANK INFRASTRUCTURE or INDEPENDENTLY AUDITED.

## C. Security findings register

[`SECURITY_FINDINGS.md`](../SECURITY_FINDINGS.md), ASVS 4.0 / MASVS 2.0 groups. Critical 0. High 4, all fixed. Medium 16: 15 fixed, D-01 open with the decision *accepted for a controlled pilot under conditions, not for production* (a captured iOS offline secret yields only `OFFLINE_PROVISIONAL`; protocol fix before production). Low 44 (6 fixed, 38 open), Info 19. This is an internal review, not a penetration test.

## D. Test execution report

Review environment: Linux, Node 22, PostgreSQL 16, Redis 7 (started locally for the tests), OpenJDK with the Kotlin 2.0.21 compiler of Gradle 8.14.3, Python 3.13, Chromium with Playwright. No Xcode, no Android SDK, no SoftHSM, no Docker daemon, no `express`/`ioredis`/`prom-client` packages, no network for package installs.

| Check | Result |
|---|---|
| Service and database suites (PostgreSQL, Redis) | **18 suites, 95 tests passed, 0 failed**: audit-export 2, authorization-decline 3, authorization-insert-state 4, backup-restore 4, bank-console 5, bank-db-authorization 17, bank-db-mandates 5, bank-p256 3, conversations 4, customer-account 7, customer-calls 4, device-replacement-hold 6, evidence-outcomes 4, identity-create-retry 3, mandates 9, migrations 7, multiple-devices 6, recovery-phrase-once 2 |
| HTTP suites | **22 suites (144 tests) not run**: need `express`/`ioredis` |
| SoftHSM suites | **8 not run**: no SoftHSM |
| Unit tests (`npm test`) | 122 tests: 113 passed, 8 failed for missing packages (`prom-client`, `ioredis`, `express`; the same failures as the unchanged base), 1 skipped. Includes the 16 new attestation tests (all passed) |
| Protocol vectors | Passed: signed payload 8 valid / 59 invalid; 6 shared files with one identical iOS copy each |
| OpenAPI | 92 routes match the routers; document structurally valid (84 paths, 52 schemas) |
| Repository hygiene | Passed |
| Kubernetes manifests | 9 documents; Auth Core's `configurationErrors()` and `productionBlockers()` pass over them; negative cases fail as expected |
| Kotlin core on the JVM | **39 tests passed** (signed payload, mandate terms, device protocols, bank trust, configuration, call engine, customer-call wire) |
| Sandbox (Python) | 74 passed |
| Demo bank | 7 passed |
| Console customer screen in Chromium (stubbed API) | Passed |
| Browser media tests (`test/media/*`) other than the console screen | Not run (need the HTTP server) |
| iOS (`swift test`), Android build and unit tests | **Not run** |
| Devices, bank HSM, bank systems, penetration test | **Not done** |

Commands for each level: [security testing guide](../SECURITY_TESTING_GUIDE.md).

## E. Mobile SDK build report

| | iOS (Swift) | Android (Kotlin) |
|---|---|---|
| Compiled in the review environment | No (no Swift toolchain) | Platform-independent core only: 10 source files compiled with Kotlin 2.0.21 and `-Werror`, 39 JUnit tests passed. Not the Android build: no Android SDK, Keystore, BiometricPrompt, OkHttp |
| Changed in this cycle | Customer calls, D-02 prompt labels and rules, D-07 key deletion, mandate payee look-alike check | Same, plus `MandateTerms.kt`, `CallSignallingClients.kt` split out so the call wire format compiles on the JVM |
| What builds them | CI job `ios-sdk` (`swift test`, demo `xcodebuild`) | CI job `android-sdk` (`gradlew compileDebugUnitTestKotlin`, conformance tests) |
| Mock security controls | None used as a pass: no simulated Secure Enclave or StrongBox result is reported | Same |

## F. HSM integration report

The PKCS#11 adapter runs in a worker thread with per-call timeouts, a bounded queue and a circuit breaker (verified against a stalling module double: `hsm-worker-host` 6, `pkcs11-adapter-deadline` 3). The eight SoftHSM suites did not run (SoftHSM cannot be installed here); CI runs them and fails if they cannot run. SoftHSM is not a bank HSM. The [HSM acceptance procedure](../../operations/hsm-acceptance.md) states what each suite proves and the vendor checks only the bank's HSM can answer (concurrent logins, session limits, timeout and breaker under a network cut, cluster failover, key attributes, restart, audit). New metrics `nexus_hsm_breaker_state`, `nexus_hsm_in_flight` and `nexus_evidence_unsealed_outcomes` support that procedure.

## G. Architecture documentation

| Document | Content |
|---|---|
| [Functional specification](../FUNCTIONAL_SPECIFICATION.md) | Actors, every function with its rules and interface, what is outside NEXUS-SIGN |
| [Cryptographic architecture](../CRYPTOGRAPHIC_ARCHITECTURE.md) | Key inventory, signed structures, cross-platform byte compatibility (TS and Kotlin verified, Swift not run), known limits |
| [Security architecture](../SECURITY_ARCHITECTURE.md) | Trust, controls by layer, the bank's independent decision, threat → control |
| [Security testing guide](../SECURITY_TESTING_GUIDE.md) | Levels L0–L8, commands, property → tests, manual and external tests |
| New in this cycle | [Customer calls](../../architecture/customer-calls.md), [biometric behaviour](../../architecture/biometric-behaviour.md), [bank console](../../operations/bank-console.md), [HSM acceptance](../../operations/hsm-acceptance.md), [Kubernetes manifests](../../../deploy/kubernetes/README.md), SIEM export in [monitoring](../../operations/monitoring.md#siem-export-of-the-audit-log) |

## H. Release readiness report

**Release state.** `VERSION` is `2.0.0-rc.2` with unreleased changes listed in `CHANGELOG.md`. No tag, release or artifact was created; CI has never run on this branch, so there are no CI results and no reproducibly built artifacts. `release.yml` builds only a tag equal to `VERSION` whose commit passed CI. Deliverables of this cycle are a git bundle and a patch of the branch, not release artifacts.

**The 20 acceptance criteria of section 22 for READY FOR CONTROLLED BANKING PILOT:**

| # | Criterion | Met | Basis |
|---|---|---|---|
| 1 | All 49 functions have a documented status | Yes | Matrix (B) |
| 2 | All mandatory pilot functions implemented | Yes, except F17 | F17 is the bank's Verification of Payee |
| 3 | No open Critical or High defects | Yes | Register (C) |
| 4 | All mandatory server tests passed | **No** | 18 service suites pass; 22 HTTP and 8 HSM suites not run |
| 5 | iOS SDK built | **No** | No Swift toolchain; never compiled |
| 6 | Android SDK built | **No** | Kotlin core compiled on the JVM only |
| 7 | Both SDKs checked on real devices | **No** | No devices |
| 8 | D-01 and D-02 closed with evidence | **No** | D-02 fixed in code and vectors, not on a device; D-01 open with a decision |
| 9 | All eight HSM suites executed | **No** | No SoftHSM here |
| 10 | Bank HSM check done | **No** | Procedure written (F) |
| 11 | All 22 HTTP suites executed | **No** | Packages missing here |
| 12 | Migrations checked from an empty database | Yes | `migrations` 7; restore `backup-restore` 4 |
| 13 | OpenAPI passes full structural validation | Yes | `validate-openapi.py` (in CI too) |
| 14 | All four technical documents prepared | Yes | (G) |
| 15 | Audio, video and push checked in the bank scenarios | **No** | Service tests only; media tests need the HTTP server; no bank push contour |
| 16 | Recurring payments checked end to end | **No** | Server and bank database verified; device signing not run |
| 17 | Bank execution layer checked on a real integration | **No** | Only the reference execution boundary in tests (SoftHSM suites, not run) |
| 18 | External penetration test done | **No** | |
| 19 | Critical and High remarks of the external audit closed | **No** | No external audit |
| 20 | CI reproducibly builds release artifacts | **No** | CI not run |

Met: 6 of 20 (1, 3, 12, 13, 14, and 2 with the F17 exception). READY FOR CONTROLLED BANKING PILOT is forbidden.

**READY FOR PRODUCTION**, assessed separately: not reachable before the pilot, and additionally needs D-01 closed by the protocol change, the open Low findings reviewed, load and resilience tests, the bank's HSM in production configuration, the bank's acceptance and regulatory review (PSD2/RTS SCA not assessed here).

## I. Remaining external dependencies

| Dependency | Owner | Unblocks |
|---|---|---|
| Permission to push the branch and run CI | You | Criteria 4–9, all HTTP/SoftHSM/media/SDK results |
| Apple Developer Program membership and devices for signing and App Attest in production | You / the bank | iOS device tests, App Attest production environment |
| Real iPhones (Face ID, Touch ID) and Android phones (with and without StrongBox) | Bank QA | Device acceptance, D-02 and D-07 on devices |
| The bank's HSM test partition and HSM team | Bank | HSM acceptance |
| Bank Verification of Payee | Bank | F17 |
| Push contour, gateway, PostgreSQL/Redis HA in the bank | Bank | Pilot deployment |
| Independent penetration test and cryptographic review | External firm | Criteria 18, INDEPENDENTLY AUDITED |
| Load and resilience test environment | Bank | Criterion 19 |
| D-01 protocol change (engineering, before production) | Engineering | Production |

## J. Final decision

**NOT COMPLETE — BLOCKERS REMAIN.**

The engineering scope that can be done without CI, devices, an HSM and the bank is done and tested where this environment allows. ENGINEERING COMPLETE — EXTERNAL VALIDATION REQUIRED would require at least a green CI with both SDK builds, the HTTP suites and the SoftHSM suites; that needs the branch pushed, which has not been authorised.
