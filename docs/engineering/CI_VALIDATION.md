# CI validation

Every check run by GitHub Actions on branch `engineering/production-readiness` (draft pull request #22 of `ptrvalina/nexus-sign`), with the run and job that show it. The branch was pushed to run CI only: nothing was merged into `main`, no tag, release, SDK publication or deployment was made, and no push was forced.

Statuses: PASS (passed in CI), FAIL, PARTIAL, NOT RUN, BLOCKED.

## Reference run

Final run: commit `20de8c0`, 2026-11-16, workflows `CI` (run `43954659319`) and `Security` (run `43954659184`): **every job of both workflows passed**. Job IDs: unit `133605905126` (Node 22, 136/136) and `133605905642` (Node 24), integration `133606360953` (54 suites, 354/354), end-to-end `133606361050` (80/80), media `133606360917` (6/6), `ios-sdk` `133605905133` (42/42, warnings as errors), `ios demo app` `133612505638`, `ios-sdk-calls` `133612505551`, `android-sdk` `133605905128`, `android-sdk-calls` `133607831105` (with Lint), demo APK `133607831049`, conformance `133606360921`, containers `133605905113`, sandbox `133605904535`, demo bank `133605905014`, CodeQL `133605904202`, Trivy `133605903752`, audit and secret scan `133605904120`, SBOM `133605904313`. Logs: `https://github.com/ptrvalina/nexus-sign/actions/runs/<run id>`.

The table below was first filled from the code commit `f8cbc11` (runs `43936067310` / `43936067272`, iOS from the next run `43941741958`); the results of the final run are the same or larger (two unit tests, one integration suite and five integration tests, four iOS tests added with the Low-finding fixes; Lint added on the call module; iOS with warnings as errors).

| # | Directive item | CI job (workflow) | Command | Job ID | Status | Result |
|---|---|---|---|---|---|---|
| 1 | TypeScript | `auth-core / build and unit tests (Node 22)` and `(Node 24)` (CI) | `npm run build` (tsc, strict) | `133541034614`, `133541034563` | PASS | Compiles on Node 22 and 24 |
| 2 | Lint | same jobs; `android-sdk` | `npm run typecheck`, `npm run check:all` (includes `check-repository.sh`: secrets, build output, versions, schema version, error codes, Markdown links); `./gradlew lintRelease` | as above; `133541034382` | PASS | There is no ESLint configuration in the repository (TypeScript `strict` and the repository checks are the gate); Android Lint on the core SDK |
| 3 | Unit tests | `auth-core / build and unit tests` (CI) | `npm run check:all` (unit tests, protocol vectors, OpenAPI routes, repository hygiene) | as above | PASS | 134/134, 0 skipped, on Node 22 and on Node 24 |
| 4 | Integration tests | `auth-core / integration (PostgreSQL, Redis, SoftHSM)` (CI) | `REQUIRE_ALL_INTEGRATION_SUITES=1 npm run test:integration` | `133541411998` | PASS | 53 suites, 349 tests, 0 failed, 0 skipped |
| 5 | PostgreSQL 16 | same job, service `postgres:16-alpine` | — | as above | PASS | Every suite creates its own database |
| 6 | Redis 7 | same job, service `redis:7-alpine` | — | as above | PASS | |
| 7 | OpenAPI validation | `auth-core / build and unit tests` | route check in `check:all`; `validate-openapi.py` on the Auth Core and sandbox documents | as above | PASS | Routes match the routers; document structurally valid |
| 8 | Security checks | `CodeQL (JavaScript/TypeScript)`, `Trivy (dependencies and container image)`, `Dependency audit and secret scan` (Security) | CodeQL; `trivy fs` and image scan; `npm audit --omit=dev --audit-level=high`; gitleaks 8.21.2 over the full history | `133540853012`, `133540853020`, `133540852939` | PASS | No CodeQL alert failing the job; Trivy: no fixable HIGH/CRITICAL; `npm audit`: 0 vulnerabilities; gitleaks: 0 leaks |
| 9 | Migration validation | integration job, suite `database migrations with a ledger` | as 4 | as 4 | PASS | 7 tests: empty database, re-run, checksums, adoption; schema version check in `check-repository.sh` |
| 10 | Dependency audit | `Dependency audit and secret scan`, `SBOM (CycloneDX)` (Security) | `npm audit`; CycloneDX | `133540852939`, `133540852358` | PASS | Two high advisories fixed in this cycle (zod, body-parser) |
| 11 | Docker builds | `containers / build and health check` (CI) | `docker build` of the Auth Core and sandbox images; the sandbox container answers its health check | `133541034533` | PASS | Both images build; the Auth Core image is also scanned by Trivy (8) |
| 12 | iOS SDK build | `ios-sdk / build and unit tests`, `ios demo app / build`, `ios-sdk-calls / WebRTC module build` (CI) | `swift test`; `xcodebuild … -sdk iphoneos`; `xcodebuild -scheme NEXUSSignCalls` | `133560765523`, `133561361078`, `133561359963` (final run) | PASS | `swift test` on `macos-15`: 41 tests in 10 suites, 0 failures, among them the 20 mandate vectors (N-13); demo app built for `iphoneos` against the SDK; call module built against `stasel/WebRTC`. At `f8cbc11` the iOS jobs got no runner and were cancelled (`133541033907`, `133550486553`); at `8de9d41` they passed with 38 tests |
| 13 | Android SDK build | `android-sdk / build and unit tests`, `android-sdk-calls / WebRTC module build`, `android demo app / debug APK`, `android-sdk call state machine against Auth Core` (CI) | `./gradlew testDebugUnitTest lintRelease assembleRelease`; `assembleRelease`; `assembleDebug`; conformance test | `133541034382`, `133542889739`, `133542889596`, `133541412070` | PASS | Real Gradle and Android SDK builds (not JVM stubs); details in [SDK validation](SDK_VALIDATION.md) |
| 14 | E2E | `auth-core / end-to-end (PostgreSQL, Redis)` (CI) | `node scripts/e2e-smoke.mjs` against a running Auth Core | `133541411973` | PASS | 80/80 checks: enrolment, signing, replay, revocation, replacement hold, recovery, evidence chain verified |
| 15 | Offline verification | integration job (5 offline suites), unit (offline verifier), `sandbox` | as 4; `npm test` | `133541411998`, `133541034776` | PASS | `offline confirmation v2: deferred device signature` 15, `restart, v1 deployments, production posture` 4, `enforcement` 5 + 2, `v1 forgery resistance` 6, `limits` 3; evidence verified offline in `backup and restore` |
| 16 | HSM integration | integration job, SoftHSM 2.7.0 built from the pinned tag | as 4 | `133541411998` | PASS (SoftHSM) | 8/8 suites, 106 tests ([HSM validation](HSM_VALIDATION.md)). Not a bank HSM |
| — | Real WebRTC calls | `auth-core / real WebRTC call (PostgreSQL, Redis, Chromium)` (CI) | `npm run test:media` | `133541412093` | PASS | 6/6: AUDIO and VIDEO verification calls, customer call, console screen, with real media between Chromium peers |
| — | Sandbox and demo bank | `sandbox / protocol and API tests`, `demo bank / access control` (CI) | `python -m unittest`; `node --test` | `133541034776`, `133541034407` | PASS | 74 and 7 tests |

## HTTP and HSM suites

The 22 suites that start Auth Core and test it over HTTP, and the 8 HSM suites, all from job `133541411998` (tests per suite in parentheses):

HTTP (22): `audit log`, `admin console`, `bank certificate binding` (one file, 3 + 6 + 4), `attestation requirement for existing credentials` (1), `database roles` (2), `device replacement` (5), `beneficiary display rules` (10), `evidence chain checkpoints held by the bank` (3), `evidence and credential integrity against a database writer` (5), `authorization expiry` (4), `security invariants` (10), `master key rotation interrupted mid-run` (1), `master key rotation of stored secrets` (5), `metrics access` (1), `device request nonce store` (3), `offline confirmation v2: deferred device signature` and `restart, v1 deployments, production posture` (15 + 4), `enforcement` (5 + 2), `offline confirmation v1: forgery resistance` (6), `offline confirmation limits` (3), `production startup posture` (3), `recovery protocol 2` (10), `database state machines` (9), `verification calls` (16), `verification results` (8). Result: **22/22 PASS**.

HSM (8): see [HSM validation](HSM_VALIDATION.md). Result: **8/8 PASS on SoftHSM 2.7.0**.

The remaining 23 suites test the services and the bank database directly on PostgreSQL and Redis (bank database authorization 17, bank mandates 5, ECDSA verifier 3, mandates 9, multiple devices 6, customer section 7, conversations 4, customer calls 4, call closure 4, and others). All passed.

## Failures found by CI in this cycle and how each was closed

| Run (commit) | Failure | Root cause | Fix | Regression test |
|---|---|---|---|---|
| `43929146935` (`e40fc9f`) | iOS jobs cancelled | `macos-14` image retired | `macos-15` (`52b5036`) | The iOS jobs themselves |
| `43929146935` | 8 HSM suites "cannot run" | Ubuntu SoftHSM 2.6.1 lacks `CKM_ECDSA_SHA256` | SoftHSM 2.7.0 from source (`52b5036`) | `REQUIRE_ALL_INTEGRATION_SUITES=1` fails the job if a suite cannot run |
| `43929146935` | 4 PostgreSQL tests | Tests reused a parameter for UUID and VARCHAR (only the local shim accepted it); a stale evidence count | `6620564` | The corrected tests |
| `43929146935` | `e2e-smoke` | Script predated the replacement hold | `8d91168` | 80 checks, now including the hold |
| `43929146935` | WebRTC AUDIO test (intermittent) | Race between the operator's decision and the server's closure | `ece80fa` | `verification-call-closure` 4 |
| `43929147218` (Security) | `npm audit`, Trivy | zod, body-parser advisories | `6bcd0cb`, `497f6cc` | The audit and Trivy jobs |
| `43932099625` (`497f6cc`) | gitleaks: 7 findings | Allowlist missed the mandate vectors (credential UUID) | `454e542` | The secret-scan job |
| `43932489275` (`b0ae83b`) | `ios-sdk`: does not compile | Property named `operator` | `78a5280` | `AccountModelsTests` |
| `43932489275` | `android-sdk-calls`: Lint | AGP cannot build the lint model in a composite build | Lint kept on the core SDK only (`8de9d41`); later run against the core SDK from Maven Local (`62523b3`, TD-13) | `lintRelease` in the calls job, passed (job `133597470092`) |
| review after `43934636812` | iOS mandate terms weaker than Android | Parser not ported; vectors not a resource | `f8cbc11` | `MandateTermsVectorsTests` 3/3 (final run) |
| `43936067310` (`f8cbc11`) | iOS jobs cancelled | No macOS runner within 15 minutes, twice (GitHub capacity or minutes) | None needed in the code | Passed in the next run (`43941741958`) |

## Not run in CI

| Check | Status | Why |
|---|---|---|
| Release workflow (`release.yml`) | NOT RUN | Runs only on a tag; creating a tag or release is forbidden in this cycle |
| iOS tests on a simulator or device | NOT RUN / BLOCKED | `swift test` runs on the macOS host; simulator UI tests do not exist; devices: BLOCKED |
| Android instrumented tests | BLOCKED | Need an emulator with hardware-backed keystore or a device |
| Load, failover, bank HSM, bank push, penetration test | BLOCKED | [Release blockers](RELEASE_BLOCKERS.md) |

## How to reproduce

Push to the branch of a pull request (CI runs on `pull_request`), or run locally: [security testing guide](SECURITY_TESTING_GUIDE.md) (levels L0–L8), [HSM validation](HSM_VALIDATION.md#how-to-reproduce), [SDK validation](SDK_VALIDATION.md#how-to-reproduce).
