# Engineering quality review

Review of the whole repository on branch `engineering/production-readiness`, November 2026, applied as a quality gate to every change on that branch. Security findings are in the [security assessment](SECURITY_ASSESSMENT_REPORT.md); this page covers how the code, tests and documents are built and kept consistent.

## Rules applied to every change on the branch

- A fix comes with a test that fails without it, run where the environment allows; where it does not, the commit message and changelog say what was not run.
- No protective check was removed or weakened to make a test pass. Where a test had to change (the migration 018 test recreating a pre-018 database, the duplicate-customer regression test), it was changed to describe the new, stricter behaviour.
- Behaviour visible to a bank is listed in the changelog with its integration impact.
- Documentation states what was verified and how; statements that something was "verified on devices" or "released" were corrected where it was not so.
- Commits are small and named after the finding they close. Nothing was pushed or published.

## Code

| Area | Observation | Action |
|---|---|---|
| Auth Core services | Clear split by concern (`services/`, `crypto/`, `routes/`, `middleware/`); database rules enforced by triggers as well as in code | New services follow the same pattern (`deviceReplacementService.ts`, `authorizationDecline.ts`) |
| Transactions and locking | Identity row lock used to serialize identity-wide operations | Device replacement and identity creation use the same lock order |
| Error model | Named errors mapped to HTTP status in one place (`errorHandler.ts`) | The conflict code reference had fallen behind the code: 11 codes raised by Auth Core, including the ones added on this branch, were not listed. All are now in the [error reference](../reference/error-responses.md#conflict-codes); a check that every `ConflictError` code is documented would keep it so |
| PKCS#11 adapter | Header comment claimed the event loop is never blocked; it was not true | Comment and runbook corrected; deadline now covers synchronous calls |
| Rule duplication across languages | Display text rules exist in TypeScript, Swift, Kotlin and Python | Kept as fixed code point ranges, not platform script tables, so all four agree; checked by a cross-language comparison |
| Bank database | PL/pgSQL ECDSA verifier is long and mathematical | Isolated in `bank-integration/p256Sql.mjs`, tested differentially against OpenSSL |
| Test helpers | A test helper embeds a script in a template literal; a nested template broke three suites | Fixed; the embedded script is syntax-checked separately |

## Tests

| Observation | Status |
|---|---|
| Most integration suites need the full HTTP stack and could not run here | Fixes were additionally covered by service-level PostgreSQL tests that run with the database alone |
| The SoftHSM suites skip silently when SoftHSM is missing | Open: CI should fail when a required suite skips (documentation review, item 5) |
| No tests for App Attest and Play Integrity token parsing | Open |
| Property and fuzz tests for canonical bytes and display rules | Present; oracle updated with the new rules |

## Documentation

| Observation | Action |
|---|---|
| Claims stronger than the evidence (devices, offline, tokens, operator) | Corrected (commit "Correct unsupported and stale documentation claims") |
| Unreleased features labelled as released 2.0.0, and a non-existent rc.3 | Labelled unreleased |
| 14 documents not linked from the index | Linked |
| Internal process jargon ("phase N", "G4") in deliverables | Removed from deliverables; kept in the decision log, which is a history |
| Terminology: "credential", "device key" and "signing key" for one concept; "approval" for the customer's act and for admin four-eyes approval | Not changed in bulk. A glossary-driven pass across code identifiers, API fields and documents is a breaking, high-churn change and is left for a dedicated release |
| Five UPPER_SNAKE file names in `docs/engineering/` against kebab-case elsewhere | Not renamed: they are referenced from build files, source comments and the changelog (see the rename impact table in the [documentation review](security-review/E_docs_ci_tests_hygiene.md)). New reports in this folder follow the folder's existing convention |

## Release engineering

Open items from the documentation and CI review: health check of the Auth Core image in CI, digest-pinned base images, Gradle `distributionSha256Sum` and dependency verification, a committed `Package.resolved`, licence checks, CodeQL for Kotlin, Swift and Python, a Trivy scan of the sandbox image, `release.yml` gated on green CI with a tag-equals-`VERSION` check. None of these could be exercised without CI access.

## Authorship

The changes on this branch were written with an AI assistant and are attributed in each commit (`Co-Authored-By`). No attempt was made to hide that.
