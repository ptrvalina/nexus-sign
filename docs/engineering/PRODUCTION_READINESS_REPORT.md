# Production readiness report

Status of NEXUS-SIGN on branch `engineering/production-readiness` (base: `2.0.0-rc.2`, commit `5999984`), November 2026. Each status below is backed by a result that was actually produced, or says that none was.

## Status

| Gate | Status | Why |
|---|---|---|
| Engineering complete | **No** | Functions shown in the product presentation are missing (chat, bot, mandates, the customer's devices, history and settings, several devices per customer); 4 Medium and 55 Low/Info review findings are open ([feature matrix](PRODUCT_FEATURE_COMPLIANCE_MATRIX.md), [security assessment](SECURITY_ASSESSMENT_REPORT.md)) |
| Ready for external security audit | **Not yet** | The core (authorization, evidence, bank execution boundary) is in a state worth auditing, but the SDK and HTTP-level changes on this branch have not been compiled or run; CI must be green on the branch first |
| Ready for controlled bank pilot | **No** | Nothing has run on a physical phone; no production HSM has been used; no penetration test |
| Production approved | **No** | Requires all of the above and the bank's own acceptance |

## What changed on this branch

17 commits on top of the base (`git log 5999984..HEAD`). All four High and 12 of 16 Medium findings of the internal review are fixed or partly fixed; details and commits in the [security assessment](SECURITY_ASSESSMENT_REPORT.md). Changes that affect a bank's integration (also in the [changelog](../../CHANGELOG.md)):

- Device replacement answers 202 `REPLACEMENT_PENDING` until the customer's enrolled device approves or the hold passes.
- `POST /v1/nexus-identities` returns an existing identity with 200 and `replayed: true` instead of 409.
- New calls: customer decline, bank cancel, device replacement list, approve and cancel.
- Displayed text that breaks the display rules (mixed scripts, compatibility characters, invalid IBAN check digits and others) is refused when the authorization is created.
- The bank database needs the bank's trust key installed and verifies signatures itself; payments have an execution window.
- Migration 024 must be applied; the HSM evidence key must have been generated in the HSM.

## What was run

Final run on the branch head, Node.js 22, PostgreSQL 16.15, Redis, Python 3; the `pg` module was replaced by a test-only shim that runs queries through `psql` (not part of the repository).

| Check | Result |
|---|---|
| Auth Core unit tests (`node --test test/*.test.mjs`) | 100 tests: 91 passed, 8 failed, 1 skipped. All 8 failures are environment failures, the same as on the unchanged base: `prom-client` is not installed (5) and the `pg` shim does not support pool options (3) |
| Signed payload vectors and iOS copies (`npm run test:vectors`) | Passed: 8 valid and 54 invalid vectors, 5 shared vector files |
| Routes against `openapi.yaml` (`npm run check:openapi`) | Passed, 49 routes |
| Repository hygiene (`scripts/check-repository.sh`) | Passed |
| Sandbox (`python -m unittest discover`) | 74 passed |
| Demo bank backend tests | 7 passed |
| PKCS#11 adapter against a module double (deadline, pool, key provenance) | 3 passed |
| Integration suites runnable here (PostgreSQL only): `authorization-decline`, `authorization-insert-state`, `bank-db-authorization`, `bank-p256`, `device-replacement-hold`, `identity-create-retry`, `recovery-phrase-once` | 38 passed, 0 failed |
| Integration suites that need `ioredis`/`express` (21) | Not run |
| Integration suites that need SoftHSM (8) | Skipped |
| iOS and Android SDK builds and tests | Not run (no Swift or Gradle toolchain) |
| Display rules across languages (generated cases, JavaScript vs Python vs Java) | No disagreement; run during the work, not repeated at the end (the rules did not change afterwards) |
| TypeScript type check | Only errors from missing type packages (`express`, `pg`, Node types) in this environment; no other error kinds than on the base |

For A1-04, A2-02, B-01 and B-02 the new tests were also run against the code before the fix and failed there; the other new tests were not run against the old code.

## Before a controlled pilot

1. CI green on the branch: all `ci.yml` and `security.yml` jobs, including both SDK builds and the SoftHSM integration suite.
2. The [device acceptance checklist](DEVICE_ACCEPTANCE_CHECKLIST.md) on real iPhones and Android phones.
3. Validation on the bank's HSM model.
4. External penetration test of Auth Core, the SDKs and the bank execution boundary.
5. Decision on the open Medium findings (B-04, C-06, D-01, D-02) and on the missing functions the pilot needs.
6. The bank's own acceptance items in the [pilot execution pack](../integration/pilot-execution-pack.md).

Nothing on this branch has been pushed, published or deployed.
