# Implementation progress

Branch `remediation/2.0.0` of the local repository (not GitHub; see IMPLEMENTATION_BASELINE.md). Per-finding detail: [REMEDIATION_HISTORY.md](REMEDIATION_HISTORY.md). Decisions: [DECISION_LOG.md](DECISION_LOG.md). Open items: [REMAINING_RISKS.md](REMAINING_RISKS.md), [RELEASE_GATES.md](RELEASE_GATES.md).

## Batches

| Batch | Local commit | Findings | Summary |
|---|---|---|---|
| Baseline | `885d053` | — | Snapshot of the audited 2.0.0-rc.2 tree |
| 1 | `de6a2bc` | FI-013, FI-014, FI-015, FI-016, FI-019 (part) | Expiry reporting and sweep, outcome webhooks, drained shutdown, NEXUS ID retry, demo pairing code |
| 2 | `3d1d595` | FI-002, FI-017 | Verified audio/video results (ES256 provider tokens), operator decisions, verifier-backed channels |
| 3 | `e212be5` | FI-001 (server, console) | In-app calls: signalling relay, TURN credentials, operator console, real WebRTC tests |
| 4 | `fa72341` | FI-003, FI-006 | Display rules (140 characters, account first), optional TLS pinning |
| 5 | `7c1c0a8` | FI-001 (SDKs) | Signalling rules, call state machine in both core SDKs, WebRTC modules, demo integration, CI jobs |
| 6 | this commit | FI-004, FI-005, FI-008, FI-019, FI-023, FI-030, FI-032 | Master key ring and rotation tool, offline caps, PostgreSQL nonce store, sealed chain heads to the bank, metrics token |

## Latest full regression (run `batch6-104748`, 2026-10-18)

Command: `scratchpad/audit/regress.sh batch6` (copies the working tree, starts PostgreSQL 16, Redis 7 and SoftHSM 2.7.0 locally).

| Suite | Command (in `auth-core/` unless noted) | Result |
|---|---|---|
| Typecheck, build | `tsc --noEmit`, `tsc` | ok |
| Unit | `node --test "test/*.test.mjs"` | 99/99 |
| Vectors | `npm run test:vectors` | ok (valid 6, invalid 28) |
| OpenAPI | `npm run check:openapi` | 43 routes match |
| Repository hygiene | `scripts/check-repository.sh` | ok |
| Integration (incl. HSM on SoftHSM) | `node --test --test-concurrency=1 "test/integration/*.test.mjs"` | 118/118 |
| Media (real Chromium WebRTC) | `node --test "test/media/*.test.mjs"` (PLAYWRIGHT_MODULE) | 3/3 (VIDEO, AUDIO, ICE restart + operator hang-up); the conformance suite skips here |
| End to end | `scripts/e2e-smoke.mjs` against a running server | 74/74 |
| Demo bank | `node --test demo/bank-backend/test/pairing.test.mjs` | 5/5 |
| Sandbox | `python3 -m unittest discover -s tests` (in `sandbox/`) | OK |
| Android SDK, JVM | `kotlinc` against Android API stubs + real kotlinx-serialization 1.6.2, JUnit 4 | 52/52 |
| Android call module | type check against org.webrtc signature stubs (no View) | ok, 17 classes |
| SDK call conformance | `test/media/sdk-call-conformance.test.mjs` driving `CallConformanceTest` (JVM) | 1/1 |

Not run, because the tools are not available here: Swift build and XCTest, Gradle/AGP builds, the real libwebrtc binaries, Docker image build, npm audit, Trivy, gitleaks, CodeQL, physical devices.

## Implemented versus simulated

| Area | Real in tests | Simulated or stubbed |
|---|---|---|
| Server signalling, session control, results, evidence | Real Auth Core, PostgreSQL, Redis, SoftHSM | — |
| Media | Two Chromium instances with Chromium's synthetic camera and microphone; real DTLS-SRTP, ICE, ICE restart | Phone side in the browser test is a web page standing in for the SDK |
| SDK call logic | Kotlin controller and wire format against a real Auth Core | Media engine scripted (no WebRTC on the JVM); operator scripted through the admin API |
| Native WebRTC adapters | Source using native org.webrtc / WebRTC.framework APIs | Android: type-checked against stubs written from the API, not the AAR; iOS: not compiled |
| Android SDK | Kotlin compiler, JUnit, real serialization and coroutines | Keystore, BiometricPrompt, OkHttp, Play Integrity are stubs |
