# Technical debt

Technical debt found and removed in the fourth engineering cycle (Engineering Validation, Technical Debt Elimination & Production Readiness), and what remains. Every removed item names the commit and the run that shows the result. Earlier cycles: [engineering quality review](ENGINEERING_QUALITY_REVIEW.md).

Most of the debt this cycle found was of one kind: **checks that had never really run**. CI had not run on the branch, the local review environment substituted a `psql`-based shim for the `pg` driver, and the CI image installed a SoftHSM that could not run the HSM suites. Running everything for real found one compile error, four broken tests, a stale end-to-end script, a race in the call closure, two high dependency advisories and a secret-scan configuration gap.

## Removed in this cycle

| ID | Debt | Effect before | Fix | Commit | Shown by |
|---|---|---|---|---|---|
| TD-01 | CI installed Ubuntu's SoftHSM 2.6.1, which lacks `CKM_ECDSA_SHA256` | The 8 HSM suites could not run (run `43929146935`); earlier documents claimed they ran on 2.7 | Build SoftHSM 2.7.0 from the pinned upstream tag in the integration job | `52b5036` | Run `43932489275`: 8/8 HSM suites, 106 tests |
| TD-02 | The iOS SDK had never been compiled; `NexusCustomerCall` used the keyword `operator` as a property name | `swift test` failed at module emission (job `133528489071`) | Escaped identifier; wire name unchanged; decoding test added | `78a5280` | `ios-sdk` job `133535913952`: 38/38; final run 41/41 |
| TD-03 | Four integration tests reused one query parameter for a `UUID` and a `VARCHAR` column; they passed only against the local `psql` shim | 42P08 "inconsistent types deduced" with the real driver | Explicit casts | `6620564` | Run `43932489275`: 349/349 |
| TD-04 | An offline test counted every evidence record; since migration 025 an `OFFLINE_UNSIGNED` outcome is itself sealed | Test failed although the product was right | Counts signed confirmations and asserts the recorded outcome | `6620564` | Same run |
| TD-05 | The end-to-end script predated the device-replacement hold (A2-01) | `e2e-smoke` failed on the 201 it expected | Checks the 202 hold, the device approval and the token afterwards | `8d91168` | `auth-core / end-to-end`: 80 checks passed |
| TD-06 | Operator decision changed the call state before sending its `bye`; the server watcher could close the call first | Flaky AUDIO media test | `closeAs` claims the closure in Redis before the change, withdraws on failure | `ece80fa` | `verification-call-closure` 4/4; media job 6/6 |
| TD-07 | zod 3.25.76 (GHSA-mrhx-c7xc-m3w5, high, no 3.x fix) and body-parser 1.20.8 (GHSA-27r3-jxmh-p828 / CVE-2026-111181, high) | `npm audit` and Trivy failed | Validation code moved to calls valid in zod 3 and 4 (`6bcd0cb`), then zod 4.6.7 and body-parser 1.20.9; lockfile resolved in CI, three entries changed | `6bcd0cb`, `497f6cc` | `npm audit`: 0 vulnerabilities; Trivy passed (run `43932489291`) |
| TD-08 | The secret-scan allowlist did not include the `mandate-terms-v1` vectors added in an earlier cycle | gitleaks: 7 findings, all a public credential UUID | Allowlisted by path, like the other published vectors | `454e542` | `Dependency audit and secret scan` passed |
| TD-09 | The `macos-14` runner image is no longer offered | The three iOS jobs were cancelled before starting | `macos-15` | `52b5036` | iOS jobs start and run |
| TD-10 | No Android Lint in CI: nothing checked platform API calls against `minSdk 28` | An API above 28 without a version check would compile and crash on Android 9–11 | `lintRelease` in the `android-sdk` job | `b0ae83b` | `android-sdk` job: lint passed |
| TD-11 | Three overlapping status documents (`PRODUCTION_READINESS_REPORT.md`, `FINAL_READINESS_PACKAGE.md`, `FINAL_ENGINEERING_REPORT.md`) and two names for one register | Contradicting numbers between documents | One current report ([engineering readiness](ENGINEERING_READINESS.md)); the summary report removed and its links redirected; the two earlier reports kept as dated cycle records with a superseded note; register and matrix renamed to the names in the directive | this cycle | Relative Markdown links checked by `auth-core/scripts/check-repository.sh` (new check, negative-tested) |


Checked and found clean: no temporary or backup files in the tree (`git ls-files` for `*.tmp`, `*.bak`, `*.orig`, `*.rej`, `*.swp`, `*.log`, `.DS_Store`); no `TODO`/`FIXME`/`HACK` markers in code (the only matches are the BIC `COBADEFFXXX` in vectors); no text from AI tools in code or documents; no test that asserts a constant (`assert.ok(true)`, `XCTAssertTrue(true)`, `assertTrue(true)`), no skipped or `@Ignore`d test; in CI the unit run reports 134 tests, 0 skipped, and the integration run 349, 0 skipped (skipping is forbidden there by `REQUIRE_ALL_INTEGRATION_SUITES=1`).

## Compatibility analysis of the dependency changes

| Change | What changes in behaviour | Checked |
|---|---|---|
| zod 3.25.76 → 4.6.7 | `z.record` needs a key schema (changed in code); `message` replaces `required_error`/`errorMap` (same texts); `z.string().uuid()` now enforces the RFC 9562 version and variant | Every UUID the system issues is a version-4 UUID (`randomUUID`, `gen_random_uuid`); every UUID literal in tests and vectors is version 4. The error-response format (`details[].path`, `.message`) is produced by the error handler from `issues` and is unchanged; message wording of built-in checks changed, no client parses it. Unit 134/134, integration 349/349, e2e 80/80 on zod 4.6.7 |
| body-parser 1.20.8 → 1.20.9 | Patch release within express 4.22.3's range `~1.20.5` | Same runs |

## Remaining

| ID | Debt | Risk | Plan |
|---|---|---|---|
| TD-R1 | Five pinned GitHub Actions run on Node 20, which GitHub now forces to Node 24 (`actions/checkout@11d5960`, `actions/setup-node@49933ea`, `actions/setup-java@cf277c6`, `actions/setup-python@a26af69`, `gradle/actions/setup-gradle@748248d`) | Low: works today; will fail when GitHub removes Node 20 | Update the pins to the Node 24 releases, by SHA, after checking their changelogs |
| TD-R2 | Android Lint cannot run on `android-sdk-calls`: AGP 8.5 fails to build the lint model when the core SDK comes from an included build ("unable to find project exploded aar") | Low: 589 lines; the one call above API 28 (`setCommunicationDevice`, API 31) is behind `SDK_INT >= S` (reviewed by hand) | Retry with a newer AGP, or lint the module against a published core AAR |
| TD-R3 | Android toolchain: AGP 8.5.2, Kotlin 1.9.24, `compileSdk 34` | Low for a library (the bank app sets `targetSdk`); new platform APIs and Kotlin 2 features unavailable | Upgrade together with the bank app's toolchain; not changed without that compatibility check |
| TD-R4 | The review environment has no npm registry; local runs use a `psql` shim for `pg` | Cost: TD-03 hid behind it | Treat CI as the only authoritative run (done in all documents of this cycle) |
| TD-R5 | `docs/operations/release.md` keeps the verification table of the `2.0.0-rc.2` release (68 integration tests) | Info: historical; current numbers are in [CI validation](CI_VALIDATION.md) | Replace at the next release |
| TD-R6 | 38 Low and 19 Info review findings open | See [security findings](SECURITY_FINDINGS.md) | Triaged there |
