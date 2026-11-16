# Final engineering report

NEXUS-SIGN, branch `engineering/production-readiness`, base `2.0.0-rc.2` (commit `5999984`), November 2026. Written for the bank's CTO, information security, bank architects and external auditors. Every statement of readiness below names the test, file or commit behind it; where a check could not run, the report says so.

**Final status: NOT COMPLETE — REMAINING BLOCKERS LISTED** ([section 17](#17-what-still-blocks-the-pilot-and-production)).

## 1. Initial state

At `2.0.0-rc.2`: Auth Core (TypeScript, PostgreSQL, Redis, PKCS#11), iOS and Android SDKs, the bank execution boundary reference (`bank-integration/`), a sandbox and a demo bank. The internal review found 4 High, 16 Medium, 41 Low and 16 Info findings ([security assessment](SECURITY_ASSESSMENT_REPORT.md)). Of the 49 functions the product presentation shows, 11 had no code and 10 were partial ([feature matrix](PRODUCT_FEATURE_COMPLIANCE_MATRIX.md), earlier statuses in its summary).

## 2. Changes

27 commits and 172 changed files before this report (`git log 5999984..HEAD`). In order:

| Commit | Change |
|---|---|
| `56e4fad` | Deferred offline signature reachable behind gateway mTLS (A1-01) |
| `4eef752`, `67443c6` | Display text rules against look-alikes and layout tricks (A1-02) |
| `8f33d81`, `a770b4c` | Customer signature, bank-approved key, execution window and restore checks inside the bank database (C-01–C-04) |
| `d4817d2` | Device replacement hold, approved or cancelled on the enrolled device (A2-01) |
| `f93c939` | Verifier refuses truncated and empty chains; no throw-away evidence keys (B-05, B-03) |
| `5c78c61` | Single-use recovery phrase, notice to the old device, bank-only call operators (A2-02, A2-03) |
| `c18b0f9` | Customer decline, bank cancel (A1-03) |
| `d4e60a9` | Retry-safe NEXUS ID creation (A1-04) |
| `5ba29ec` | Authorization inserts checked by the database (C-05) |
| `f7ad5ba`, `8ee386a` | PKCS#11 in a worker thread: bounded calls, queue limit, circuit breaker, fail-closed (B-01) |
| `4a2760b` | Evidence key must be generated in the HSM (B-02) |
| `0768ce3` | Evidence for every outcome and every revocation (B-04) |
| `e4d269c` | Migration ledger with checksums; fresh install and upgrade tested (C-06) |
| `ba3231d` | Customer section: devices, history, evidence, security log, feed, settings and limits, suspension; bank suspend and reactivate |
| `3e8343a` | Several active devices per NEXUS ID under a bank limit |
| `3e988aa`, `2882a8b` | Payment mandates, checked by Auth Core and independently by the bank database |
| `67caf19` | Conversations with the bank: chat, the bank's bot, handover to an operator, console queue |
| `0052940` | SDK methods for the above (not compiled) |
| `5fbe09a` | CI fails when a required suite cannot run; release gated on CI and `VERSION` |
| `a38b7ee`, `b86877a`, `d560aa0`, `6bc2c61` | Documentation corrections, reports, a test-helper fix |

## 3. Architecture and changed components

The chain NEXUS ID → credential → transaction binding → device signature → independent verification → HSM → evidence is unchanged. What changed around it:

- **Auth Core** gained `deviceReplacementService` (replacement and addition requests), `customerAccountService`, `mandateService`, `conversationService`, the PKCS#11 worker (`pkcs11Worker.ts`, `HsmWorkerHost`) and outcome sealing in `evidenceService`. Migrations 023–029.
- **Bank database** (`bank-integration/schema.mjs`) verifies the customer's ECDSA signature itself (`p256Sql.mjs`), the bank's trust statements, the execution window, restore marks and mandate debits. The gateway is no longer the only source of trust.
- **SDKs** gained the account, mandate and conversation API surface and the stricter display rules.
- **Evidence** record types: `AUTHORIZATION`, `CREDENTIAL_ENROLLED`, `RECOVERY_CONFIGURED`, `AUTHORIZATION_OUTCOME`, `CREDENTIAL_REVOKED`, `MANDATE`.
- **Communication** stays inside the bank's app and the bank's systems: the bot runs at the bank, push is the bank's, attachments are stored by the bank.

## 4. Functions

49 functions of the presentation: 7 implemented and verified, 29 implemented with external verification required, 8 partial, 5 not applicable, none missing. Per row: [feature matrix](PRODUCT_FEATURE_COMPLIANCE_MATRIX.md).

## 5. Closed security findings

All 4 High; 14 of 16 Medium (A1-02, A1-03, A1-04, A2-02, A2-03, B-01, B-02, B-03, B-04, B-05, C-03, C-04, C-05, C-06); Low D-03 and D-04. Details and commits: [security assessment](SECURITY_ASSESSMENT_REPORT.md).

## 6. Residual risks

Open Medium: D-01 (iOS offline secret available to the app process), D-02 (prompt layout). Also open: D-07 (biometric change), App Attest and Play Integrity tests, 39 Low and 16 Info findings, master-key unwrap on the main thread at startup, conversation bodies stored in clear text in the database, forward-only migrations. Full list: [known limitations](KNOWN_LIMITATIONS.md).

## 7. Test results

Run on the branch head, Node.js 22, PostgreSQL 16.15, Redis 7, Python 3; the `pg` driver replaced by a test-only shim that runs queries through `psql` (not in the repository), because the npm registry is not reachable from this environment.

| Command (in `auth-core/` unless noted) | Result |
|---|---|
| `node --test "test/*.test.mjs"` | 106 tests: 97 passed, 8 failed, 1 skipped. The 8 failures are the same set as on the unchanged base: `prom-client` not installed (5), shim limits (3) |
| `node test-vectors/check-signed-payload-vectors.mjs && node test-vectors/check-vector-copies.mjs` | Passed (8 valid, 54 invalid vectors; 5 shared files) |
| `node scripts/check-openapi-routes.mjs` | Passed, 85 routes; `openapi.yaml` parses and every `$ref` resolves (checked separately with PyYAML) |
| `bash scripts/check-repository.sh` | Passed (includes the new rule: every conflict code is documented) |
| `python3 -m unittest discover -s tests` (in `sandbox/`) | 74 passed |
| `node --test test/*.mjs` (in `demo/bank-backend/`) | 7 passed |
| `node --test test/integration/<suite>.test.mjs` with `INTEGRATION_DATABASE_URL`, `INTEGRATION_REDIS_URL`, for the 14 suites that need only PostgreSQL | 79 passed, 0 failed: `authorization-decline` 3, `authorization-insert-state` 4, `bank-db-authorization` 17, `bank-db-mandates` 5, `bank-p256` 3, `conversations` 4, `customer-account` 7, `device-replacement-hold` 6, `evidence-outcomes` 4, `identity-create-retry` 3, `mandates` 8, `migrations` 7, `multiple-devices` 6, `recovery-phrase-once` 2 |
| The other 22 integration suites | Not run: they load `ioredis`, which is not installed here |
| The 8 SoftHSM suites | Skipped: no SoftHSM here. In CI they now fail instead of skipping when SoftHSM is missing |

Fixes for A1-04, A2-02, B-01 and B-02 were also run against the code before the fix and their tests failed there.

## 8. iOS and Android builds

Not run. This environment has no Xcode, Swift or Gradle. The SDK changes of this branch have not been compiled. CI jobs `ios-sdk / build and tests` and `android-sdk / build and unit tests` must pass first.

## 9. HSM and PKCS#11

Worker-thread host tested with a PKCS#11 double that stalls synchronously (`hsm-worker-host`, 6 tests: bounded calls, event loop stays responsive, breaker, probe, queue limit, crash, close) and the adapter's deadline and key-provenance checks (`pkcs11-adapter-deadline`, 3). SoftHSM suites not run here. No production HSM has been validated; no compatibility with a specific vendor is claimed.

## 10. Migrations and bank integration

Migrations: fresh install from an empty database equals `schema.sql`; upgrade from the rc.2 schema; changed, removed or missing migrations stop the run; a failing migration leaves nothing; parallel runs apply each migration once (`migrations`, 7). Bank database: signature verification in SQL against OpenSSL, privilege matrix, revocation cut-off, execution window, restore, mandate debits (`bank-p256`, `bank-db-authorization`, `bank-db-mandates`: 25 tests).

## 11. Evidence chain

Every authorization outcome and credential revocation is recorded in the transaction that makes it and sealed; concurrent sealers seal each outcome once in a valid chain; a changed or removed outcome is refused by the verifier (`evidence-outcomes`, 4). Mandate events are sealed and verified, including the device signature over the terms and the key sealed at enrolment; a removed revocation is detected (`mandates`). The unit suite `evidence.test.mjs` did not run here (needs `prom-client`).

## 12. CI

Workflows changed: the integration job sets `REQUIRE_ALL_INTEGRATION_SUITES=1`; the release workflow checks the tag against `VERSION` and requires successful `ci.yml` and `security.yml` runs for the commit. No workflow has run on this branch: nothing was pushed. Open: Gradle `distributionSha256Sum`, digest-pinned images, a YAML parse step for `openapi.yaml`, CodeQL for Swift and Kotlin, licence checks.

## 13. The 49 functions

See [section 4](#4-functions) and the [feature matrix](PRODUCT_FEATURE_COMPLIANCE_MATRIX.md).

## 14. Needs real devices

Key generation and protection in Secure Enclave and StrongBox, biometric binding and change (D-07), the confirmation and mandate screens (D-02, display on small screens, fonts, accessibility, localization), offline confirmation (D-01), push handling, calls on the phone, recovery. Package: [device acceptance checklist](DEVICE_ACCEPTANCE_CHECKLIST.md), [native build guide](NATIVE_BUILD_GUIDE.md).

## 15. Needs the bank's infrastructure

The bank's HSM model; its push contour (APNs/FCM through the bank); its gateway with mTLS; its core banking and payment provider behind the execution boundary; its bot (webhooks and bot API); its attachment storage; its SIEM and anti-fraud; load tests in its infrastructure. Package: [pilot execution pack](../integration/pilot-execution-pack.md), [bank backend guide](../integration/bank-backend-guide.md).

## 16. Needs an independent audit

Penetration test of Auth Core, both SDKs and the bank execution boundary; review of the PL/pgSQL ECDSA verifier; cryptographic review of the protocols (authorization v1, mandates v1, recovery v2, offline v2, evidence schema 3).

## 17. What still blocks the pilot and production

1. SDK changes not compiled; CI not run on the branch (requires the owner's permission to push).
2. Nothing run on physical iPhones or Android phones.
3. No SoftHSM run in this cycle; no production HSM.
4. The 22 HTTP integration suites not run here.
5. Open Medium findings D-01 and D-02; D-07 and attestation tests.
6. Eight partial functions ([remaining gaps](PRODUCT_FEATURE_COMPLIANCE_MATRIX.md#remaining-gaps)).
7. Missing documents of the required set: Product Functional Specification, Cryptographic Architecture, Security Architecture (as single documents), Security Testing Guide.
8. No penetration test, load test or bank acceptance.

## 18. Gates

| Gate | Status | Basis |
|---|---|---|
| Functional completeness | Not passed | 8 partial rows |
| Security | Not passed | D-01, D-02 open |
| Backend | Passed where runnable | Unit (environment failures only), 14 PostgreSQL suites, contract; HTTP suites not run |
| Database | Passed | Fresh install, upgrade, ledger, restore handling, bank execution protection tested |
| iOS | Not run | No toolchain |
| Android | Not run | No toolchain |
| HSM | Not run | Worker host tested with a double; SoftHSM suites not run |
| Bank integration | Passed (database level) | Signature, key, terms, window, restore and mandate checks in the bank database, independent of the gateway |
| Audio/Video | Not run | Needs the HTTP stack, a browser and phones |
| Evidence | Passed | All outcomes sealed and verified |
| CI/CD | Not run | Workflows changed, not executed |
| Documentation | Partly | Four required documents missing |
| Presentation | Passed for claims | No function is claimed as verified without a test; the matrix marks the rest |

External gates (physical iPhone, physical Android, target HSM, bank push contour, load test, penetration test, bank acceptance): none performed.

## Changes for the bank

| Item | Content |
|---|---|
| Breaking changes | Device replacement answers 202 until approved or matured; retried identity creation returns 200 with the existing ID instead of 409; text that breaks the display rules is refused at authorization creation; the bank database needs the bank's trust key, migration 024+ and the evidence key generated in the HSM; authorizations above the customer's own limits are refused (`CUSTOMER_LIMIT_EXCEEDED`) |
| New APIs | Decline and cancel; device replacement and addition; customer section; bank suspend, reactivate, device list; mandates and debits; conversations (bank, device, console) — all in `openapi.yaml` |
| Migration requirements | Apply migrations 023–029 with `npm run migrate` (`src/cli/migrate.ts`, ledger and checksums); install the bank trust key in the bank database; rehearse the upgrade on a restored copy |
| Bank infrastructure | Gateway with mTLS, PostgreSQL 16, Redis, a PKCS#11 HSM, push through the bank, webhook receiver, attachment storage, the bank's bot if used |
| External dependencies | Apple App Attest, Google Play Integrity and key attestation roots, APNs/FCM, TURN servers for calls |
| Needs the bank's participation | Re-identification for replacements and reactivation, the bot, operators, limits policy, device limit per customer, mandate conditions, anti-fraud and SIEM integration, acceptance testing |
