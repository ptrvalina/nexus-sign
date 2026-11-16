# NEXUS-SIGN — Engineering readiness (fourth cycle)

Directive: *Master Execution Directive, Cycle 4: Engineering Validation, Technical Debt Elimination & Production Readiness*. Repository `ptrvalina/nexus-sign`, branch `engineering/production-readiness`, base `2.0.0-rc.2`, draft pull request #22. Date of the results: 2026-11-16.

What this cycle changed in kind: for the first time every check ran for real. CI had never run on the branch; the HSM suites had never run anywhere; the iOS SDK had never been compiled. Running them found and closed ten defects, among them an iOS SDK that did not compile, a gap in the iOS mandate checks, two high dependency advisories and a call-closure race. Everything that can be shown without phones, the bank's HSM, the bank's systems and an external tester now passes in CI, except the iOS build of the very last change, which is waiting for a macOS runner.

**Final decision: NOT READY — REMAINING BLOCKERS.** One engineering item is open: the iOS build of the last Swift change (`f8cbc11`) has not run, because GitHub assigned no macOS runner. When that job passes, the state matches READY FOR EXTERNAL VALIDATION; a controlled bank pilot additionally needs the external validation in section K.

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
| 10 | iOS mandate terms checked like Android (canonical bytes, exact fields, values): finding N-13 | `f8cbc11` | `MandateTermsVectorsTests` (3 valid, 17 invalid): **not yet run**, no macOS runner |
| 11 | Repository check refuses broken relative links in Markdown | documentation commit | `check-repository.sh` (negative-tested) |

## B. Technical debt removed

[Technical debt](TECHNICAL_DEBT.md): TD-01 to TD-11 removed (SoftHSM in CI, iOS compile, shim-only tests, stale tests, stale e2e, call race, advisories, secret-scan gap, retired runner, missing Android Lint, overlapping status documents). Checked clean: no temporary files, no TODO/FIXME, no AI-tool text, no always-passing or skipped tests (CI: 0 skipped of 134 unit and 349 integration tests), no mocks or stubs in product code. Remaining: TD-R1 (Actions pinned to Node 20 releases), TD-R2 (no Lint on `android-sdk-calls`), TD-R3 (Android toolchain versions), TD-R4–R6.

## C. 22 HTTP test suites

**22/22 PASS**, job `133541411998` of run `43936067310` (commit `f8cbc11`). List with test counts: [CI validation](CI_VALIDATION.md#http-and-hsm-suites). They cover the API endpoints, registration and enrolment, authentication, credential lifecycle, NEXUS ID issuance, transaction binding, signature verification, replay protection, idempotency, expiry, cancellation, revocation, multi-device policy, bank isolation (`security invariants`, `bank certificate binding`), webhooks, evidence sealing, offline verification, error responses and authorization boundaries. Rate limiting is not in Auth Core by design (finding A1-10, the bank's gateway).

## D. 8 HSM test suites

**8/8 PASS on SoftHSM 2.7.0**, 106 tests, same job. [HSM validation](HSM_VALIDATION.md). SoftHSM is not the bank's HSM; the bank HSM check is BLOCKED.

## E. Android SDK build

**PASS**: real Gradle builds with the Android SDK — `android-sdk` (`testDebugUnitTest lintRelease assembleRelease`, `minSdk 28`, `compileSdk 34`), `android-sdk-calls` (release build against pinned WebRTC), demo APK, call state machine against a running Auth Core. Not run on a device or emulator (BLOCKED). [SDK validation](SDK_VALIDATION.md).

## F. iOS SDK build

**PARTIAL.** The iOS SDK was compiled for the first time in this cycle and failed (`operator` keyword, N-07); after the fix every iOS job passed at `8de9d41` (run `43934636812`): `swift test` on `macos-15`, 38 tests in 9 suites, 0 failures (job `133535913952`); the demo app built for `iphoneos` against the SDK (job `133539501894`); the WebRTC call module built (job `133539501764`). The last change (`f8cbc11`, the Swift mandate parser of N-13 and its 20-vector test) is **NOT RUN**: its `ios-sdk` job was queued twice and cancelled after 15 minutes without a macOS runner (jobs `133541033907`, `133550486553`). Nothing was simulated: the iOS status of `f8cbc11` stays NOT RUN until that job runs. Not run on an iPhone (BLOCKED). [SDK validation](SDK_VALIDATION.md).

## G. CI

Reference run: `CI` `43936067310` and `Security` `43936067272` on `f8cbc11`; every job of both workflows passed except the iOS jobs, which got no macOS runner (section F). Directive items 1–16 with job IDs and results: [CI validation](CI_VALIDATION.md). Ten failures found by CI in this cycle, each with root cause, fix and regression test: same document.

## H. Security audit

[Security findings](SECURITY_FINDINGS.md). Critical 0; High 5 found, 5 fixed (new this cycle: N-09 dependencies); Medium 19 found, 18 fixed (N-13 in code, its iOS test pending a runner), 1 open (D-01, accepted for a pilot with offline confirmation off, not for production); new this cycle N-07 to N-13. Re-audit of injection, XSS, CSRF, SSRF, randomness, secret comparison and logging, `SECURITY DEFINER`, Redis TTLs: no new finding beyond those listed. Threat model of the ten scenarios with residual risk: same document. Highest residual risks: the customer approving a genuine fraudulent payee (business, bank's Verification of Payee), a compromised HSM (high impact, low likelihood; cannot cause an execution), insider with database ownership (detected by the bank's chain checkpoints). This is an internal review; **no external penetration test has been done.**

## I. The 49 functions

[Functional completeness matrix](FUNCTIONAL_COMPLETENESS_MATRIX.md): of 44 software functions, VERIFIED IN CI 10, VERIFIED IN CI — DEVICE/BANK PENDING 33, PARTIAL 1 (F17, the bank's Verification of Payee), NOT IMPLEMENTED 0; 5 non-software items. The eight earlier partial functions were rechecked: seven complete, F17 stays the bank's.

## J. The 20 pilot conditions

[Pilot readiness matrix](PILOT_READINESS_MATRIX.md): PASS 10, PARTIAL 5, BLOCKED 5, FAIL 0. Not met: the iOS build of the last change (5), real devices (7), D-01/D-02 on a device (8), bank HSM (10), bank scenarios for audio, video and push (15), mandates on a device (16), real bank integration (17), external penetration test and its findings (18, 19), a release run from a tag (20).

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
| `8de9d41` | No Lint on the calls module | `43934636812` / `43934636743` | All jobs pass, among them `ios-sdk` (38 tests), iOS demo and calls builds |
| `f8cbc11` | iOS mandate parser (also carried the two document renames) | `43936067310` / `43936067272` | Reference run: all jobs pass except iOS (no runner, cancelled twice) |
| after `f8cbc11` | Documents of this cycle and the Markdown link check (`git log f8cbc11..`) | the runs of those commits on pull request #22 | Same code; they re-run every job |

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

What is shown: the server (Auth Core), the bank database rules and the reference bank execution boundary behave as designed under every test the repository has — 134 unit tests, 349 integration tests in 53 suites against real PostgreSQL 16, Redis 7 and SoftHSM 2.7.0, 80 end-to-end checks, 6 real WebRTC calls in Chromium — and the central security property holds in those tests: a fully compromised Auth Core cannot make the bank execute a payment. Both SDKs compile for their platforms and pass their unit and shared-vector tests (iOS as of `8de9d41`; the last Swift change awaits a macOS runner); dependency, secret, container and code scans are clean. No Critical or High finding is open.

What is not shown: anything on a real iPhone or Android phone (hardware keys, biometrics, prompts, push, calls), anything on the bank's HSM or in the bank's infrastructure (failover, load, the core banking adapter), and any external assessment. These are not engineering gaps that this team can close; they are the external validation the product now needs. One Medium finding (D-01) stays open by decision and must be closed before production.

Decision: **NOT READY — REMAINING BLOCKERS.** The only engineering blocker is the pending iOS CI run of `f8cbc11`; after it passes, the product is READY FOR EXTERNAL VALIDATION. It is not READY FOR CONTROLLED BANK PILOT: conditions 7, 10, 17, 18 and 19 require external validation that has not happened, and this report does not claim a bank HSM test or a penetration test.
