# Release gates (re-assessed 2026-10-19, after phase 11)

Gates as defined in the forensic inventory (`docs/audit/forensic-inventory/2026-10-16/13_RELEASE_GATE_MATRIX.csv`), re-assessed after remediation batches 1–11. Status values: PASS, PARTIAL, FAIL, BLOCKED. A gate passes only on evidence that was executed and recorded; source code alone does not move a gate to PASS.

| Gate | Name | Audit (2026-10-16) | Now | Evidence now | What is still missing |
|---|---|---|---|---|---|
| G0 | Repository integrity and reproducible baseline | PARTIAL | PARTIAL (FI-009 BLOCKED) | Local git history with baseline `885d053` and the remediation commits up to `4a1935f`; `verify-baseline.sh` prepared; `check-repository.sh` ok; full regression reproducible with `regress.sh` | Lockfile (FI-009); GitHub head unavailable; dependency scans not run (R-09, R-20) |
| G1 | Functional completeness | PARTIAL | PARTIAL | Expiry fixed; verified A/V results; in-app calls end to end in browsers; SDK call logic; demo flows | Native media unbuilt; sandbox still simulates A/V (R-13); per-operation attestation absent (R-08) |
| G2 | Protocol and cryptographic correctness | PARTIAL | PARTIAL | Vectors valid 6 / invalid 28 incl. display rules; verification result v1 with 20 refusal cases; signalling rules; offline caps and daily limit; **offline confirmation v2: 19 tests incl. concurrency and a killed process; enforcement suite 7 (service-level device check without HTTP, no alternative endpoint, bank commit re-verifies sealed evidence, DB-written VERIFIED and copied evidence not committable, v1 record refused on v2); 20 mutations, 19 caught; phase 10: records with a genuine SoftHSM evidence seal but a wrong device signature, other key, altered terms, stale enrolment, missing field, code-only method, unknown seal key or wrong chain position refused by the commit check and the verifier (13 tests); device parsers check ID and nonce formats (37 invalid / 8 valid vectors); 25 mutations, 23 caught, 2 refused by another layer; phase 11: evidence row columns bound to the sealed payload at commit, in `confirmed`, in the enrolment check and in the verifier, parallel refused and genuine commits answered 409/202 without HTTP 500 (`evidence-metadata-binding` 13 on SoftHSM, 9 of them fail on `2df8754`); 15 new mutations, 14 caught, 1 redundant shown by test**; offline threat model before/after | Swift parser, prompt and v2 flow unexecuted; v2 on devices (F3–F8); FI-007 open; a controlled Auth Core can still forge enrolments (bank reconciliation not implemented); no formal analysis |
| G3 | Backend and database reliability | PARTIAL | PARTIAL | Integration suites on PostgreSQL 16 / Redis 7 incl. key rotation across restarts, nonce durability after Redis loss, drained shutdown; 40 parallel commit requests on one authorization without pool exhaustion (phase 11, D-040) | Load, soak and two-instance tests (FI-024); BOOTSTRAP tokens in Redis (R-06) |
| G4 | iOS and Android release builds | BLOCKED | BLOCKED | CI jobs defined, now including `ios-sdk-calls`, `android-sdk-calls`, `sdk-call-conformance` | No toolchain here (re-checked phase 9: no Android SDK, Swift, Xcode, Docker daemon; Maven/Google Maven refused); CI not run for this work; build inputs not hash-pinned (R-21); no SDK release pipeline (FI-022) |
| G5 | Real-device verification | FAIL | BLOCKED | Checklist with 22 call items ([DEVICE_ACCEPTANCE_CHECKLIST.md](DEVICE_ACCEPTANCE_CHECKLIST.md)) | No devices or TURN over a mobile network in this environment; no run recorded |
| G6 | Real HSM integration and key management | FAIL | PARTIAL | PKCS#11 suite 10/10 on SoftHSM 2.7.0; master keys wrapped by an HSM KEK, 11/11 local SoftHSM tests incl. failure modes, rotations and an imported KEK refused; in-HSM decryption of the stored format shown on SoftHSM (3 tests), migration path not available on SoftHSM ([KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)) | Vendor HSM: BLOCKED (none available); key ceremony; keys still in process memory (R-05) |
| G7 | Audio/video end-to-end implementation and security | FAIL | PARTIAL | Server session control, authenticated results, signalling relay with enforced order, TURN credentials, operator console; real DTLS-SRTP media between browsers incl. ICE restart; SDK state machine tested against Auth Core | Native modules not built or run on devices; WebRTC binary provenance and licences open (R-04); operator procedure and legal meaning of a call (R-17) |
| G8 | Independent security assessment | FAIL | FAIL | — | External assessment (R-18) |
| G9 | Deployment, monitoring, backup and DR | PARTIAL | PARTIAL | Runbooks updated (key rotation, calls, upgrade to 2.0.0); metrics token; coturn reference configuration | Restore and rollback drills (R-12); staging deployment |
| G10 | Privacy, legal, compliance | BLOCKED | BLOCKED | — | Counsel and bank acceptance criteria (R-19) |

## Readiness by level

| Level | Ready | Why |
|---|---|---|
| 1. Local development | Yes | Full regression green locally (see IMPLEMENTATION_PROGRESS.md) |
| 2. Internal demo (simulator / browser) | Partly | Server, console and browser calls work; native demo apps not yet built after these changes |
| 3. Controlled technical pilot | No | Needs G0 (lockfile), G4 (CI builds), G5 (device checklist), TPM items or calls disabled |
| 4. Limited production pilot | No | Additionally G6 (vendor HSM), G8, G9 drills, G10 |
| 5. General production | No | All gates |
| 6. Security-critical production (high-value payments) | No | All gates, plus per-operation attestation (R-08) and a decision on offline codes (R-07) |
| 7. Production with in-app calls | No | G7 complete: native builds, device tests, WebRTC provenance and licences, operator procedures |

## Release assessment (2026-10-18)

| Category | Items |
|---|---|
| Verified complete (locally, by executed tests) | Expiry reporting and sweep; verified A/V results; channels only with verifiers; signalling relay rules, closure and operator release; browser-to-browser media incl. ICE restart; display rules on the server and Android JVM; master key rotation; nonce durability; sealed chain heads; metrics token; demo pairing code |
| Implemented, not fully verified | Offline confirmation v2 in the SDKs (Android JVM only, iOS uncompiled); native call modules (Android type-checked against stubs, iOS uncompiled); Swift parsing, pinning and call state machine; HSM master key wrapping (SoftHSM only); Android SDK on Android itself |
| Still vulnerable or partially mitigated | FI-004 residual cases after v2 (provisional acted upon by a bank, forged v1/enrolment records by a controlled Auth Core); FI-007 device integrity after enrolment; FI-008 BOOTSTRAP tokens in Redis; master keys in process memory; confusable payee names (FI-034) |
| Blocked by environment or access | FI-009 lockfile and source baseline; dependency, secret, CodeQL and container scans; WebRTC artifact download, checksums, licence files; native builds (G4) |
| Requires real-device testing | Prompt layout (FI-003), pinning vs MITM (FI-006), all call items E1–E22, enrolment and keys (B), recovery (G) |
| Requires a real HSM | AES-GCM wrapping and attribute policy on the vendor HSM; evidence sealing on the vendor HSM; key ceremony and backup |
| Requires independent security or legal assessment | G8 external assessment; G10 evidential value of signatures, offline codes and operator decisions; privacy of call metadata; WebRTC licence and codec patent position |
