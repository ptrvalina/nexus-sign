# NEXUS-SIGN — Engineering readiness (fourth cycle)

Directive: *Master Execution Directive, Cycle 4: Engineering Validation, Technical Debt Elimination & Production Readiness*. Repository `ptrvalina/nexus-sign`, branch `engineering/production-readiness`, base `2.0.0-rc.2`, draft pull request #22. Date of the results: 2026-11-16.

What this cycle changed in kind: for the first time every check ran for real. CI had never run on the branch; the HSM suites had never run anywhere; the iOS SDK had never been compiled. Running them found and closed ten defects, among them an iOS SDK that did not compile, a gap in the iOS mandate checks, two high dependency advisories and a call-closure race. Everything that can be shown without phones, the bank's HSM, the bank's systems and an external tester now passes in CI. Final run: run `44019252340` (CI) / `44019252337` (Security), commit `d950036`, every job of both workflows green (after the package, 16 more Low findings were fixed with tests on the same branch; the earlier reference run was `43954659319` on `20de8c0`).

**Final decision: READY FOR EXTERNAL VALIDATION.** Not ready for a controlled bank pilot: that needs the external validation listed in section K, which has not happened.

---

## A. Fixes

| # | Fix | Commit | Test that shows it (CI) |
|---|---|---|---|
| 1 | HSM suites run on SoftHSM 2.7.0 built from the pinned upstream tag (Ubuntu's 2.6.1 lacks `CKM_ECDSA_SHA256`) | `52b5036` | 8/8 HSM suites, 106 tests |
| 2 | iOS jobs on `macos-15` (the `macos-14` image is retired) | `52b5036` | iOS jobs run |
| 3 | End-to-end script follows the device-replacement hold (A2-01) | `8d91168` | 80/80 end-to-end checks |
| 4 | Verification call: the closing side sends the only `bye` (race with the server's closure) | `ece80fa` | `verification-call-closure` 4/4; media 6/6 |
| 5 | Four integration tests fixed for the real `pg` driver; stale evidence assertion after migration 025 | `6620564` | Integration 349/349 |
| 6 | zod 4.6.7 (GHSA-mrhx-c7xc-m3w5) and body-parser 1.20.9 (GHSA-27r3-jxmh-p828 / CVE-2026-111181), after making the validation code valid in both zod versions | `6bcd0cb`, `497f6cc` | `npm audit` 0, Trivy pass, all suites |
| 7 | Secret-scan allowlist covers the mandate vectors | `454e542` | gitleaks 0 leaks |
| 8 | Android Lint on the core SDK (API calls against `minSdk 28`) | `b0ae83b` | `android-sdk` job |
| 9 | iOS SDK compiles (`operator` keyword) | `78a5280` | `ios-sdk` job; `AccountModelsTests` |
| 10 | iOS mandate terms checked like Android (canonical bytes, exact fields, values): finding N-13 | `f8cbc11` | `MandateTermsVectorsTests` (3 valid, 17 invalid), 3/3 |
| 11 | Repository check refuses broken relative links in Markdown | documentation commit | `check-repository.sh` (negative-tested) |
| 12 | GitHub Actions on their Node 24 releases, pinned by SHA (TD-12) | `4b3e84d` | every job |
| 13 | iOS tests free of Swift 6 concurrency diagnostics; `swift test` with warnings as errors (TD-14) | `670dbf7` | `ios-sdk` 42/42, 0 warnings |
| 14 | Android Lint on the call module, via the core SDK from Maven Local; the call module's POM names the core SDK version (TD-13) | `62523b3` | `android-sdk-calls` `lintRelease` |
| 15 | Low findings A1-08, A2-04, A2-05, A2-07, B-07, B-12, C-11 (migration 031), D-05, D-10 | `adfe7e3`, `6226128`, `f37216a`, `b65b37b`, `2d705f6`, `a864ca7`, `cb77ab6`, `3be0953` | one test each, failing without the fix ([triage](SECURITY_FINDINGS.md#triage-of-the-low-findings)) |
| 16 | After the package: Low findings A2-06, A2-08 (redelivery, secret overlap, migration 034), A2-10, A1-05/B-06, A1-07, B-08, B-09/C-08 (migration 033), B-10, B-11, C-07 (migration 032), C-13, D-08, D-12, D-15; D-14 in part | `8b0e845` … `d950036` | one test or suite each ([triage](SECURITY_FINDINGS.md#triage-of-the-low-findings)); run `44019252340` |

## B. Technical debt removed

[Technical debt](TECHNICAL_DEBT.md): TD-01 to TD-14 removed (SoftHSM in CI, iOS compile, shim-only tests, stale tests, stale e2e, call race, advisories, secret-scan gap, retired runner, missing Android Lint, overlapping status documents). Checked clean: no temporary files, no TODO/FIXME, no AI-tool text, no always-passing or skipped tests (CI: 0 skipped of 134 unit and 349 integration tests), no mocks or stubs in product code. Remaining: TD-R3 (Android toolchain versions), TD-R4–R7 (local environment, historical release table, open review findings, macOS runner availability).

## C. 22 HTTP test suites

**22/22 PASS**, job `133824854081` of the final run `44019252340` (commit `d950036`); first passed at `f8cbc11` (job `133541411998`). List with test counts: [CI validation](CI_VALIDATION.md#http-and-hsm-suites). They cover the API endpoints, registration and enrolment, authentication, credential lifecycle, NEXUS ID issuance, transaction binding, signature verification, replay protection, idempotency, expiry, cancellation, revocation, multi-device policy, bank isolation (`security invariants`, `bank certificate binding`), webhooks, evidence sealing, offline verification, error responses and authorization boundaries. Rate limiting is not in Auth Core by design (finding A1-10, the bank's gateway).

## D. 8 HSM test suites

**8/8 PASS on SoftHSM 2.7.0**, 106 tests, same jobs. [HSM validation](HSM_VALIDATION.md). SoftHSM is not the bank's HSM; the bank HSM check is BLOCKED.

## E. Android SDK build

**PASS**: real Gradle builds with the Android SDK — `android-sdk` (`testDebugUnitTest lintRelease assembleRelease`, `minSdk 28`, `compileSdk 34`), `android-sdk-calls` (release build against pinned WebRTC, Android Lint), demo APK, call state machine against a running Auth Core. Not run on a device or emulator (BLOCKED). [SDK validation](SDK_VALIDATION.md).

## F. iOS SDK build

**PASS.** The iOS SDK was compiled for the first time in this cycle and failed (`operator` keyword, N-07, job `133528489071`); after the fix every iOS job passed. Final run `44019252340`: `swift test -Xswiftc -warnings-as-errors` on `macos-15`, 49 tests, 0 failures, 0 warnings, including the 20 mandate vectors of N-13 and the new tests of D-08, D-12 and D-14 (job `133824525142`); the demo app built for `iphoneos` against the SDK (job `133824865051`); the WebRTC call module built (job `133824865002`). At `f8cbc11` the iOS jobs got no macOS runner and were cancelled twice; nothing was simulated, they ran in the next run. Not run on an iPhone (BLOCKED). [SDK validation](SDK_VALIDATION.md).

## G. CI

Final run: `CI` `44019252340` and `Security` `44019252337` on `d950036`: every job of both workflows passed. GitHub sometimes assigns no macOS runner (iOS jobs cancelled after 15 minutes at `f8cbc11`, `1f5f81b`, `3be0953`); each time the next run passed, and nothing was simulated. Directive items 1–16 with job IDs and results: [CI validation](CI_VALIDATION.md). Ten failures found by CI in this cycle, each with root cause, fix and regression test: same document.

## H. Security audit

[Security findings](SECURITY_FINDINGS.md). Critical 0; High 5 found, 5 fixed (new this cycle: N-09 dependencies); Medium 19 found, 18 fixed, 1 open (D-01, accepted for a pilot with offline confirmation off, not for production); new this cycle N-07 to N-13. Low: all 44 rechecked; 6 found already fixed, 9 fixed in this cycle with tests, then 16 more fixed after the package (A2-06, A2-08, A2-10, A1-05/B-06, A1-07, B-08, B-09/C-08, B-10, B-11, C-07, C-13, D-08, D-12, D-15) and D-14 in part, each with a test that ran in CI; 13 remain with a decision each (10 accepted by design, 3 planned before production: D-06, D-11, the rest of D-14). Re-audit of injection, XSS, CSRF, SSRF, randomness, secret comparison and logging, `SECURITY DEFINER`, Redis TTLs: no new finding beyond those listed. Threat model of the ten scenarios with residual risk: same document. Highest residual risks: the customer approving a genuine fraudulent payee (business, bank's Verification of Payee), a compromised HSM (high impact, low likelihood; cannot cause an execution), insider with database ownership (detected by the bank's chain checkpoints). This is an internal review; **no external penetration test has been done.**

## I. The 49 functions

[Functional completeness matrix](FUNCTIONAL_COMPLETENESS_MATRIX.md): of 44 software functions, VERIFIED IN CI 10, VERIFIED IN CI — DEVICE/BANK PENDING 33, PARTIAL 1 (F17, the bank's Verification of Payee), NOT IMPLEMENTED 0; 5 non-software items. The eight earlier partial functions were rechecked: seven complete, F17 stays the bank's.

## J. The 20 pilot conditions

[Pilot readiness matrix](PILOT_READINESS_MATRIX.md): PASS 11, PARTIAL 4, BLOCKED 5, FAIL 0. Not met: real devices (7), D-01/D-02 on a device (8), bank HSM (10), bank scenarios for audio, video and push (15), mandates on a device (16), real bank integration (17), external penetration test and its findings (18, 19), a release run from a tag (20).

## K. Remaining blockers

[Release blockers](RELEASE_BLOCKERS.md), each with its test protocol and PASS criterion: real iPhones (B1), real Android phones (B2), the bank's HSM (B3), the bank's test environment (B4), push through the bank's contour (B5), real audio/video scenarios (B6), external penetration test (B7), bank integration acceptance (B8); D-01 before production (B9); Verification of Payee is the bank's (B10).

## L. Changed files

Code and tests: `.github/workflows/ci.yml`, `.gitleaks.toml`, `auth-core/package.json`, `auth-core/package-lock.json`, `auth-core/src/config/env.ts`, `auth-core/src/routes/{admin,mobileV1,nexusV1,recovery}.ts`, `auth-core/src/services/verificationCall.ts`, `auth-core/scripts/e2e-smoke.mjs`, `auth-core/scripts/check-repository.sh`, `auth-core/test/support/resp-redis.mjs`, `auth-core/test/integration/{verification-call-closure (new),authorization-insert-state,mandates,multiple-devices,offline-deferred-signature}.test.mjs`, `ios-sdk/Package.swift`, `ios-sdk/Sources/NEXUSSign/{MandateTerms.swift (new),NEXUSSignSDK.swift,SignedTransaction.swift,NEXUSSignAccountModels.swift}`, `ios-sdk/Tests/NEXUSSignTests/{AccountModelsTests,MandateTermsVectorsTests}.swift` (new).

Documents: new `docs/engineering/{ENGINEERING_READINESS,CI_VALIDATION,SDK_VALIDATION,HSM_VALIDATION,TECHNICAL_DEBT,PILOT_READINESS_MATRIX,RELEASE_BLOCKERS}.md`; renamed `SECURITY_FINDINGS_REGISTER.md` → `SECURITY_FINDINGS.md` and `PRODUCT_FEATURE_COMPLIANCE_MATRIX.md` → `FUNCTIONAL_COMPLETENESS_MATRIX.md` (both updated); removed `PRODUCTION_READINESS_REPORT.md` (duplicate summary; links redirected); updated `KNOWN_LIMITATIONS.md`, `FINAL_READINESS_PACKAGE.md`, `FINAL_ENGINEERING_REPORT.md` (superseded notes), `docs/README.md`, `docs/operations/hsm-acceptance.md`, `docs/operations/release.md`, and link targets in five other documents.

## M. Commits and CI runs

| Commit | Change | CI run (workflow `CI` / `Security`) | Result |
|---|---|---|---|
| `e40fc9f` | Third-cycle state, first push | `43929146935` / `43929147218` | Failures listed in CI validation |
| `52b5036` | SoftHSM 2.7.0, `macos-15` | (pushed together with the next five) | |
| `8d91168` | e2e and the replacement hold | | |
| `ece80fa` | Call closure race | | |
| `6620564` | Four integration tests | | |
| `6bcd0cb` | zod calls valid in v3 and v4 | | |
| `8e3d2bd` | Temporary lockfile job (removed in `497f6cc`) | `43931861252` / `43931861271`, lockfile job `43931861517` | Lockfile resolved; superseded by the next push |
| `497f6cc` | zod 4.6.7, body-parser 1.20.9 | `43932099484` / `43932099625` | Audit and Trivy pass; gitleaks finding |
| `454e542` | gitleaks allowlist | | |
| `b0ae83b` | Android Lint | `43932489275` / `43932489291` | Integration 349/349, HSM 8/8, e2e, media pass; iOS compile error; Lint fails on the calls module |
| `78a5280` | iOS compiles | | |
| `8de9d41` | No Lint on the calls module | `43934636812` / `43934636743` | iOS (38 tests, demo, call module), Android, e2e, media and Security pass; integration cancelled by the next push |
| `f8cbc11` | iOS mandate parser (also carried the two document renames) | `43936067310` / `43936067272` | All jobs pass except iOS (no macOS runner, cancelled twice) |
| `689c876` | Documents of this cycle, Markdown link check, changelog | `43941741958` / `43941742021` | All jobs pass, iOS included (41/41) |
| `1f5f81b` | Documents: decision | `43943541948` / `43943541775` | All pass except two iOS jobs (no runner) |
| `4b3e84d` | Actions on Node 24 releases | (pushed with the next) | |
| `670dbf7` | iOS warnings as errors | `43950832164` / `43950832199` | Linux jobs pass; superseded by the next push |
| `62523b3` … `3be0953` | Lint on the call module; Low findings A2-05, A1-08, C-11, A2-07, D-05, D-10 | `43951724813` / `43951724930` | All pass except iOS (no runner); integration 353/353, call-module Lint pass |
| `6226128`, `a864ca7`, `2d705f6`, `20de8c0` | A2-04, B-12, B-07; Low triage and documents | `43954659319` / `43954659184` | **All jobs pass** — reference run of the package (unit 136, integration 354 in 54 suites, iOS 42) |
| `8b0e845` … `d950036` | Low findings after the package (A2-06, A2-10, B-10, A1-05/B-06, C-07, A1-07, B-11, B-09/C-08, B-08, D-08, A2-08, D-15, D-12, D-14 part, C-13) | `44015361246`, `44016351029`, `44017238945`, `44018225807` (two failures, see CI validation), `44019252340` / `44019252337` | **All jobs pass** — final run (unit 144, integration 370 in 59 suites, iOS 49) |
| later | Final updates of these documents | runs of those commits on pull request #22 | Same code |

## N. Reproduction

| Check | Command |
|---|---|
| Unit, vectors, OpenAPI routes, repository | `cd auth-core && npm ci && npm run typecheck && npm run build && npm run check:all` |
| OpenAPI structure | `python3 auth-core/scripts/validate-openapi.py auth-core/openapi.yaml` |
| Integration incl. 22 HTTP and 8 HSM suites | [HSM validation, how to reproduce](HSM_VALIDATION.md#how-to-reproduce) (PostgreSQL 16, Redis 7, SoftHSM 2.7.0) |
| End-to-end | start Auth Core against PostgreSQL and Redis, then `node auth-core/scripts/e2e-smoke.mjs` (see the `auth-core-e2e` job in `ci.yml`) |
| Browser media | `cd auth-core && npm run test:media` (Chromium via Playwright) |
| iOS, Android | [SDK validation, how to reproduce](SDK_VALIDATION.md#how-to-reproduce) |
| Security scans | `npm audit --omit=dev --audit-level=high`; gitleaks 8.21.2 `detect --source . --redact`; Trivy; CodeQL (`.github/workflows/security.yml`) |
| All of the above | push the branch of a pull request: `.github/workflows/ci.yml` and `security.yml` |

## O. Objective assessment

What is shown: the server (Auth Core), the bank database rules and the reference bank execution boundary behave as designed under every test the repository has — 144 unit tests, 370 integration tests in 59 suites against real PostgreSQL 16, Redis 7 and SoftHSM 2.7.0, 80 end-to-end checks, 6 real WebRTC calls in Chromium — and the central security property holds in those tests: a fully compromised Auth Core cannot make the bank execute a payment. Both SDKs compile for their platforms and pass their unit and shared-vector tests; dependency, secret, container and code scans are clean. No Critical or High finding is open.

What is not shown: anything on a real iPhone or Android phone (hardware keys, biometrics, prompts, push, calls), anything on the bank's HSM or in the bank's infrastructure (failover, load, the core banking adapter), and any external assessment. These are not engineering gaps that this team can close; they are the external validation the product now needs. One Medium finding (D-01) stays open by decision and must be closed before production.

Decision: **READY FOR EXTERNAL VALIDATION.** It is not READY FOR CONTROLLED BANK PILOT: conditions 7, 10, 17, 18 and 19 require external validation that has not happened, and this report does not claim a bank HSM test or a penetration test.
