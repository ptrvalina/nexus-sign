# Release gates (re-assessed 2026-10-18)

Gates as defined in the forensic inventory (`docs/audit/forensic-inventory/2026-10-16/13_RELEASE_GATE_MATRIX.csv`), re-assessed after remediation batches 1–6. Status values: PASS, PARTIAL, FAIL, BLOCKED. A gate passes only on evidence that was executed and recorded; source code alone does not move a gate to PASS.

| Gate | Name | Audit (2026-10-16) | Now | Evidence now | What is still missing |
|---|---|---|---|---|---|
| G0 | Repository integrity and reproducible baseline | PARTIAL | PARTIAL | Local git history with baseline `885d053` and six remediation commits; `check-repository.sh` ok; full regression reproducible with `regress.sh` | Lockfile (FI-009); GitHub head unavailable; dependency scans not run (R-09, R-20) |
| G1 | Functional completeness | PARTIAL | PARTIAL | Expiry fixed; verified A/V results; in-app calls end to end in browsers; SDK call logic; demo flows | Native media unbuilt; sandbox still simulates A/V (R-13); per-operation attestation absent (R-08) |
| G2 | Protocol and cryptographic correctness | PARTIAL | PARTIAL | Vectors valid 6 / invalid 28 incl. display rules; verification result v1 with 20 refusal cases; signalling rules; offline caps | Swift parser and prompt unexecuted; FI-004 inherent; FI-007 open; no formal analysis |
| G3 | Backend and database reliability | PARTIAL | PARTIAL | Integration suites on PostgreSQL 16 / Redis 7 incl. key rotation across restarts, nonce durability after Redis loss, drained shutdown | Load, soak and two-instance tests (FI-024); BOOTSTRAP tokens in Redis (R-06) |
| G4 | iOS and Android release builds | BLOCKED | BLOCKED | CI jobs defined, now including `ios-sdk-calls`, `android-sdk-calls`, `sdk-call-conformance` | No toolchain here; CI not run for this work; no SDK release pipeline (FI-022) |
| G5 | Real-device verification | FAIL | FAIL | Checklist written ([DEVICE_ACCEPTANCE_CHECKLIST.md](DEVICE_ACCEPTANCE_CHECKLIST.md)) | No device run |
| G6 | Real HSM integration and key management | FAIL | PARTIAL | PKCS#11 suite 10/10 on SoftHSM 2.7.0 (correction of the audit); master key rotation implemented and tested | Vendor HSM; master keys not HSM-wrapped (R-05); key ceremony |
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
