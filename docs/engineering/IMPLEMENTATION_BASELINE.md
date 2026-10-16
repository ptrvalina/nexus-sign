# Implementation baseline (2026-10-16)

Baseline for the 2.0.0 remediation work. The forensic inventory in `docs/audit/forensic-inventory/2026-10-16/` stays unchanged; corrections to it are recorded here and in `DECISION_LOG.md`.

## Source snapshot

| Item | Value |
|---|---|
| Tree | Local working copy of NEXUS-SIGN `2.0.0-rc.2` (the tree the owner's archives were built from), plus the forensic inventory |
| Git | The copy had no `.git`. A local repository was created for traceability: branch `baseline/2026-10-16`, commit `885d053` (363 files), remediation on branch `remediation/2.0.0`. This commit is **not** a GitHub commit; correspondence with `ptrvalina/nexus-sign` is unverified (no GitHub access from this environment) |
| Version declarations | `2.0.0-rc.2` in `VERSION`, `auth-core/package.json`, both `openapi.yaml`, `NEXUSSignVersion.swift`, `NEXUSSignVersion.kt` |
| Lockfile | `auth-core/package-lock.json` is absent (FI-009). It cannot be generated here: the npm registry is blocked (HTTP 403 from the egress proxy). A lockfile built from the locally assembled dependency set would not be a reviewed npm lockfile and is not created |

## Toolchain

| Tool | Version | Source |
|---|---|---|
| Node.js | 22.22.2 | `/opt/node22` |
| TypeScript | 5.9.3 | assembled dependency set |
| Auth Core runtime dependencies | express 4.22.3, pg 8.23.1, ioredis 5.11.1, zod 3.25.76, helmet 7.2.0, pino 9.14.0, pino-http 10.5.0, cbor 9.0.2, pkcs11js 2.1.7, prom-client 15.1.3 | Built from their GitHub sources at release tags (not from the npm registry); `@types/*` are local stubs |
| PostgreSQL | 16.13 | Ubuntu package, local cluster on 127.0.0.1:55432 |
| Redis | 7.0.15 | Ubuntu package, 127.0.0.1:56379 |
| SoftHSM | 2.7.0 | Built from source in this environment (`scratchpad/rc/softhsm/install`) |
| Python | 3.11.15 | sandbox tests |
| Kotlin compiler | standalone `kotlinc` | Android SDK compiled against hand-written Android API stubs (not AGP) |
| Swift / Xcode | not available | iOS: BLOCKED |
| Android SDK / AGP | not available | Android native build: BLOCKED |
| Docker daemon | not running | container builds: BLOCKED |
| Chromium | Playwright build in `/opt/pw-browsers` | available for browser-based WebRTC tests |

## Baseline regression (run `baseline-212512`)

| Suite | Command | Result |
|---|---|---|
| Typecheck | `tsc --noEmit` | pass |
| Build | `tsc -p tsconfig.json` | pass |
| Unit | `node --test "test/*.test.mjs"` | 88 / 88 |
| Vectors | `npm run test:vectors` | pass (valid 5, invalid 22) |
| OpenAPI routes | `npm run check:openapi` | 39 routes match |
| Repository hygiene | `scripts/check-repository.sh` | pass |
| Integration incl. SoftHSM | `node --test --test-concurrency=1 "test/integration/*.test.mjs"` with `SOFTHSM2_MODULE`/`SOFTHSM2_UTIL` | **68 / 68** |
| End to end | `scripts/e2e-smoke.mjs` against a server running as `nexus_app` | 71 / 71 |
| Sandbox | `python -m unittest discover -s tests` | 74 / 74 |
| Android JVM (stubs) | `kotlinc` + JUnit | 34 run, 30 pass, 4 fail in the `kotlinx.serialization` stub (harness limitation) |

Correction to the forensic inventory: FI-010 states that the SoftHSM suite could not run. A SoftHSM 2.7.0 build already existed in this environment; with it the HSM suite passes 10/10. FI-010 remains open for a vendor HSM.

## Simulations and test doubles in the repository

| Component | Real or simulated | Where |
|---|---|---|
| Device in e2e | Simulated (Node, software P-256 keys) | `auth-core/scripts/e2e-smoke.mjs` |
| HSM | Software adapter in development; PKCS#11 tested on SoftHSM | `softwareHsmAdapter.ts`, `test/integration/hsm.test.mjs` |
| Attestation | Disabled in e2e; Android chains verified against real fixture chains | `test/android-key-attestation.test.mjs` |
| Audio / video providers | Simulated in sandbox; arbitrary assertion string in e2e | `sandbox/server`, `e2e-smoke.mjs` |
| Push providers | Not exercised (no APNs/FCM credentials) | `pushProviders.ts` |
| Demo bank | Demo only | `demo/bank-backend` |

## Security-critical paths without meaningful tests at baseline

- Signature or JWS verification of audio/video results (does not exist: FI-002).
- Expiry visible to read paths (FI-013).
- Display limits of signed fields (FI-003).
- Master-key rotation (FI-005).
- Device behaviour of Secure Enclave, Keystore and BiometricPrompt (FI-011, FI-012).
