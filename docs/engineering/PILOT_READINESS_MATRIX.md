# Pilot readiness matrix

The 20 conditions for READY FOR CONTROLLED BANK PILOT (section 22 of the readiness directive), as of the fourth cycle. A condition is met only by a real result: PASS (a real test passed), FAIL, PARTIAL (part of it shown), NOT RUN, BLOCKED (infrastructure or access missing). CI runs and jobs: [CI validation](CI_VALIDATION.md).

| # | Condition | Status | Evidence | What is missing |
|---|---|---|---|---|
| 1 | All 49 functions have a documented status | PASS | [Functional completeness matrix](FUNCTIONAL_COMPLETENESS_MATRIX.md): 44 software functions and 5 non-software items | — |
| 2 | All mandatory pilot functions implemented | PASS, one exception | 43 of 44 implemented; F17 (Verification of Payee) is the bank's function | The bank's Verification of Payee |
| 3 | No open Critical or High defects | PASS | [Security findings](SECURITY_FINDINGS.md): Critical 0, High 5 found, 5 fixed | External test may find more (18) |
| 4 | All mandatory server tests passed | PASS | CI: unit 144/144 (Node 22 and 24), integration 370/370 (59 suites), end-to-end 80/80 checks, WebRTC media 6/6, sandbox 74, demo bank 7 | — |
| 5 | iOS SDK built | PASS | Built and tested for the first time in this cycle: `swift test` 49/49 with warnings as errors on `macos-15`, demo app for `iphoneos`, call module against pinned WebRTC (run `44019252340`) | — |
| 6 | Android SDK built | PASS | CI `android-sdk`: `testDebugUnitTest lintRelease assembleRelease` (real Gradle and Android SDK build, minSdk 28 checked by Lint); `android-sdk-calls` release build against the pinned WebRTC artifact; demo APK built; call conformance against a running Auth Core | — |
| 7 | Both SDKs checked on real devices | BLOCKED | No devices | B1, B2 in [release blockers](RELEASE_BLOCKERS.md) |
| 8 | D-01 and D-02 closed with evidence | PARTIAL | Both fixed in code and tested in CI: D-02 vectors in TypeScript, Kotlin, Python and Swift; D-01 by offline v3 (`offline-per-authorization`, `offline_v3` vectors) | Both on a device (the demo apps show the prompt and the offline code) |
| 9 | All eight HSM suites executed | PASS (SoftHSM 2.7.0) | 8/8 suites, 106 tests ([HSM validation](HSM_VALIDATION.md)) | SoftHSM is not the bank's HSM (10) |
| 10 | Bank HSM check done | BLOCKED | Procedure: [HSM acceptance](../operations/hsm-acceptance.md) | B3 |
| 11 | All 22 HTTP suites executed | PASS | All 22 suites that start Auth Core over HTTP passed in the integration job (list in [CI validation](CI_VALIDATION.md#http-and-hsm-suites)) | — |
| 12 | Migrations checked from an empty database | PASS | `database migrations with a ledger` 7 (empty database, re-run, checksums), `backup and restore` 4, in CI | — |
| 13 | OpenAPI passes full structural validation | PASS | `validate-openapi.py` and the route check in the CI unit job | — |
| 14 | All four technical documents prepared | PASS | [Functional specification](FUNCTIONAL_SPECIFICATION.md), [cryptographic architecture](CRYPTOGRAPHIC_ARCHITECTURE.md), [security architecture](SECURITY_ARCHITECTURE.md), [security testing guide](SECURITY_TESTING_GUIDE.md) | — |
| 15 | Audio, video and push checked in the bank scenarios | PARTIAL | Real WebRTC calls (AUDIO, VIDEO, customer call, console) between Chromium and Auth Core: 6/6; Android call state machine against Auth Core; verification-call 16, customer-calls 4, secure-push vectors | Phones, the bank's TURN and push contour (B5, B6) |
| 16 | Recurring payments checked end to end | PARTIAL | Server and bank database: `payment mandates` 9, `bank database: debits under a payment mandate` 5; mandate vectors in TypeScript, Kotlin and Swift | Signing a mandate on a device (B1, B2) |
| 17 | Bank execution layer checked on a real integration | BLOCKED | The reference boundary passes 45 tests on SoftHSM and PostgreSQL in CI (`bank-execution-boundary` 25, `bank-execution-processes` 20) | The bank's core banking adapter and infrastructure (B4, B8) |
| 18 | External penetration test done | BLOCKED | Internal review only | B7 |
| 19 | Critical and High remarks of the external audit closed | BLOCKED | No external audit yet | B7 |
| 20 | CI reproducibly builds release artifacts | PARTIAL | The CI jobs build every artifact on every push (container image, Android AAR and APK, iOS package, SBOM); `release.yml` builds release artifacts only from a tag equal to `VERSION` whose commit passed CI, and no tag was created (forbidden in this cycle) | A release run from a tag |

**Met (PASS): 11 of 20.** PARTIAL: 4 (8, 15, 16, 20). BLOCKED: 5 (7, 10, 17, 18, 19). FAIL: 0. READY FOR CONTROLLED BANK PILOT requires all 20; the remaining ones need devices, the bank's HSM and environment, and an external test.
