# Production readiness report

Status of NEXUS-SIGN on branch `engineering/production-readiness` (base `2.0.0-rc.2`, commit `5999984`). The full basis is the [final readiness package](FINAL_READINESS_PACKAGE.md) (sections A–J).

## Decision

**NOT COMPLETE — BLOCKERS REMAIN.**

| Gate | Status | Why |
|---|---|---|
| Engineering complete — external validation required | **Not yet** | CI has not run on the branch (not pushed): the iOS SDK has never been compiled, the Android build, the 22 HTTP suites and the 8 SoftHSM suites have not run |
| Ready for controlled banking pilot | **No** | 6 of the 20 acceptance criteria are met; no devices, no bank HSM, no external penetration test |
| Ready for production | **No** | Additionally needs the D-01 protocol change, load and resilience tests and the bank's acceptance |

## Evidence in short

- 44 software functions: 7 verified locally, 36 implemented but not verified, 1 partial (payee check, the bank's), 0 not implemented.
- 18 PostgreSQL/Redis suites: 95 tests passed, 0 failed. Unit tests 113 of 122 (8 failures for missing packages, as in the base). Kotlin core on the JVM: 39 passed. Sandbox 74, demo bank 7, vectors, OpenAPI (92 routes, structural validation), manifests, hygiene: passed.
- Not run: 22 HTTP suites, 8 SoftHSM suites, browser media tests, iOS and Android builds, anything on a device or a bank system.
- Findings: Critical 0, High 0 open, Medium 1 open (D-01, decided).

Nothing on this branch has been pushed, published or deployed.
