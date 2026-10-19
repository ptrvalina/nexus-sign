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
| 6 | `9dee0af` | FI-004, FI-005, FI-008, FI-019, FI-023, FI-030, FI-032 | Master key ring and rotation tool, offline caps, PostgreSQL nonce store, sealed chain heads to the bank, metrics token |
| Report | `1bbd12e` | — | Milestone report (Russian) |
| 11 | `9b8c2a5`…`4a1935f` (tests `9b8c2a5`, `6122192`, `07579e0`, `ed34add`, `e644ea0`, `4a1935f`; fixes `8969a2b`, `165f259`) | FI-004 (evidence row metadata) | Evidence row columns bound to the sealed payload at commit, in `confirmed`, in the enrolment check and in the verifier; enrolment cache limited to the ECDSA result; no second pool connection under the commit row lock |
| 10 | `588a0a6`, `8635a04`, `b7e6cb6` | FI-004 (evidence trust), FI-005 (rotation interrupted) | Commit check covers chain position; `confirmed` from verified evidence; forged-seal suite on SoftHSM; parser format checks and vectors; rotation tool killed mid-run |
| 9 | `75736c8`, `0582f54` | FI-004 (enforcement), FI-005 (in-HSM check) | Bank commit re-verifies sealed evidence; `confirmed` flag; v1 behind the insecure flag; enforcement suite; demo bank status; SoftHSM capability check |
| 8 | `88d9a0d`, `d06a378`, `e068c40` | FI-004 (deferred device signature), FI-005 (KEK attributes) | Offline confirmation v2 in Auth Core and the SDKs, migration 022, verifier `--reject-offline-code`; KEK must be generated in the HSM |
| 7 | `e8e90e7` | FI-005 (HSM wrapping), FI-004 (threat model, daily limit) | Master keys wrapped by an HSM KEK, `masterKeys.js`, offline forgery tests, native build guide, baseline script, WebRTC provenance update |

## Latest full regression (run `phase11-122631`, 2026-10-19, code at `4a1935f`)

Same tools as below. Typecheck and build ok; unit 101/101; vectors ok (valid 8, invalid 37); OpenAPI 44 routes; repository hygiene ok; integration 191/191, 0 skipped (new: `evidence-metadata-binding` 13 on SoftHSM); media 3/3; E2E 77/77; demo bank 7/7; sandbox OK (74 tests); Android JVM (stubs) 57/57; Android call module type check ok (17 classes). **SDK call conformance: exit code 1 in the full run** (JVM `CallConformanceTest`, `engine.released` expected 1, was 0, asserted right after the call ended); three separate runs of the same suite afterwards: exit code 0 each. Not changed in this phase (SDK call code is outside its scope); recorded as an intermittent failure, not as a pass.

Mutation run (code at `165f259`; suites `offline-deferred-signature`, `offline-enforcement`, `evidence-forgery-hsm`, `evidence-metadata-binding`, `invariants` with SoftHSM): 39 mutations, 36 caught; M16 and M30 refused by another check (shown by tests that still refuse with the mutation applied); M37 and M38 survived that run and were caught after the parallel tests were strengthened (`4a1935f`, 40 requests). Phase 11 mutations M25–M39: 14 of 15 caught, M30 redundant.

## Phase 10 full regression (run `phase10-194621`, 2026-10-18, code at `b7e6cb6`)

Same tools as below. Every line exit code 0: typecheck and build ok; unit 101/101; vectors ok (valid 8, invalid 37); OpenAPI 44 routes; repository hygiene ok; integration 178/178 (new: `evidence-forgery-hsm` 13, `key-rotation-interrupted` 1); media 3/3; E2E 77/77; demo bank 7/7; sandbox OK (74 tests); Android JVM (stubs) 57/57; Android call module type check ok (17 classes); SDK call conformance 1/1.

Mutation run (separate, code at `8635a04`, the same code as `b7e6cb6`; suites `offline-deferred-signature`, `offline-enforcement`, `evidence-forgery-hsm` with SoftHSM, a run with skipped tests counts as invalid): 25 mutations, 23 caught by a failing check, 2 refused by another layer (M16 binding, M22 device-key comparison: the commit is still refused by the byte or signature check).

## Phase 9 full regression (run `phase9-185423`, 2026-10-18, code at `0582f54`)

Tools: Node 22.22.2, PostgreSQL 16.13, Redis 7.0.15, SoftHSM 2.7.0, OpenJDK 21.0.10, kotlinc 2.0.21, Playwright 1.56.1 with Chromium build 1194, Python 3.11.15. Every line exit code 0.

| Suite | Result |
|---|---|
| Typecheck, build | ok |
| Unit | 101/101 |
| Vectors, OpenAPI | ok, 44 routes |
| Repository hygiene | ok |
| Integration (incl. SoftHSM) | 164/164 (new: `offline-enforcement` 7, `hsm-in-place-decryption` 3) |
| Media (Chromium WebRTC) | 3/3 |
| End to end | 77/77 |
| Demo bank | 7/7 (new: `status.test.mjs` 2) |
| Sandbox | OK |
| Android SDK, JVM (stubs) | 57/57 |
| Android call module type check | ok, 17 classes |
| SDK call conformance | 1/1 |

Mutation runs (separate from the regression): 20 mutations against `offline-deferred-signature` and `offline-enforcement`; 19 caught, 1 survived (a binding check duplicated by the byte and signature checks; removing all three is caught).

## Previous full regression (run `phase8-173638`, 2026-10-18)

Same command as below, on the phase 8 working tree before the commits (the commits contain exactly that tree's code). Baseline run on `760d066` before any change: `phase8-baseline-115010`, identical to `batch7-112422`.

| Suite | Result |
|---|---|
| Typecheck, build | ok |
| Unit | 100/100 |
| Vectors | ok |
| OpenAPI | 44 routes match |
| Repository hygiene | ok |
| Integration (incl. SoftHSM) | 154/154 (new: `offline-deferred-signature` 19, `master-key-hsm` +1) |
| Media (Chromium WebRTC) | 3/3 |
| End to end | 77/77 (offline section now runs v2) |
| Demo bank | 5/5 |
| Sandbox | OK (simulates offline v1 only) |
| Android SDK, JVM (stubs) | 57/57 |
| Android call module type check | ok, 17 classes |
| SDK call conformance | 1/1 |

Mutation check of the v2 suite: 13 mutations, 12 caught; the surviving one (service-level check that the uploading device is the bound credential) is also enforced by the route's scope check.

## Earlier full regression (run `batch7-112422`, 2026-10-18)

New in this run compared with `batch6-104748`: unit 99 → 100, integration 118 → 134 (`master-key-hsm` 10, `offline-forgery` 6). Commits after `e8e90e7` changed documentation only.

## Previous full regression (run `batch6-104748`, 2026-10-18)

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
