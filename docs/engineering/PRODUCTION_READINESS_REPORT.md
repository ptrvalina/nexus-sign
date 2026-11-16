# Production readiness report

Status of NEXUS-SIGN on branch `engineering/production-readiness` (base `2.0.0-rc.2`, commit `5999984`). The detailed basis, commands and results are in the [final engineering report](FINAL_ENGINEERING_REPORT.md).

## Status

| Gate | Status | Why |
|---|---|---|
| Engineering complete | **No** | 8 of 49 presentation functions are partial; Medium findings D-01 and D-02 are open; SDK changes are not compiled; four required documents are missing |
| Ready for external security audit | **Not yet** | The server, the bank database and the evidence chain are in a state worth auditing; CI must first be green on the branch, including both SDK builds and the SoftHSM suites |
| Ready for controlled bank pilot | **No** | Nothing has run on a physical phone; no production HSM; no penetration test |
| Production approved | **No** | Requires all of the above and the bank's acceptance |

## Evidence in short

- 14 PostgreSQL integration suites: 79 tests passed, 0 failed.
- Unit tests: 97 of 106 passed; the 8 failures are missing packages of this environment, identical to the unchanged base.
- Protocol vectors, OpenAPI contract (85 routes), repository hygiene, sandbox (74), demo bank (7): passed.
- Not run: 22 HTTP integration suites (`ioredis` missing), 8 SoftHSM suites, iOS and Android builds, anything on a device, CI.

Nothing on this branch has been pushed, published or deployed.
