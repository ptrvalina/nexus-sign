# E. Documentation, CI/CD, tests and repository hygiene: NEXUS-SIGN

Read-only review of `nexus-sign/` (HEAD of the working branch, VERSION `2.0.0-rc.2`). Paths are relative to the repository root. As instructed, this report does not assess the branch changes to `mtlsGateway.ts`, `canonicalAuthorization.ts`, the SDK `SignedTransaction` files, `sandbox/server/protocol.py`, `docs/protocol/authorization-protocol-v1.md`, the CHANGELOG `[Unreleased]` display-rules entries, the test vectors, or the uncommitted/branch work in `bank-integration/` (`schema.mjs`, `paymentGateway.mjs`, `p256Sql.mjs`, `bank-p256.test.mjs`). Where a status line is quoted, it was compared with the baseline commit `5999984`.

How each check was run: grep or Python scripts over the tracked files; env names compared across `configuration.md`, `.env.example` and `env.ts`; endpoints compared between the guide and `openapi.yaml` with a script; state names compared against migrations 017, 018 and 022 and `schema.sql`; a Markdown link checker found 0 broken relative links.

---

## PART 1: Documentation

### 1. Required document inventory

| Required document | Status | Where / note |
|---|---|---|
| Product Architecture | Partial | `README.md:1-50` (positioning, "Key properties", ASCII flow). There is no product-level document covering scope, actors, editions, the calls module or the sandbox/demo split. |
| System Architecture | Exists | `docs/architecture/overview.md` (components, flows). There is no deployment topology diagram. `deployment.md:104-118` gives a table only. |
| Security Architecture | Exists under other names (fragmented) | `docs/security/threat-model.md` (trust boundaries `:63`), `attestation.md`, `hsm-key-management.md`, `bank-database-authorization.md`, `architecture/bank-trust-boundary.md`. No single security architecture document. |
| Threat Model | Exists | `docs/security/threat-model.md`, `docs/security/offline-confirmation-threat-model.md`, `docs/integration/pilot-execution-pack.md` §3 |
| Cryptographic Design | Partial, under other names | Spread across `docs/protocol/*` (8 specifications), `docs/engineering/KEY_MANAGEMENT.md` (key inventory `:5`) and `docs/security/hsm-key-management.md`. No algorithm/curve/KDF/MAC inventory with rationale in one place. |
| Transaction Binding Specification | Exists under another name | `docs/protocol/authorization-protocol-v1.md` (+ ADR 0001) |
| NEXUS ID Specification | Missing | Only one-line definitions: `glossary.md:28`, `overview.md:64`, `authorization-protocol-v1.md:14`. Nothing documents allocation (random 9 digits with retry, `nexusIdentityService.ts:37`), uniqueness scope, check digit (none), reuse after revocation, or exposure rules. |
| Credential Lifecycle | Partial | `architecture/state-machines.md` §Credential, `architecture/device-replacement.md`, `protocol/recovery-protocol-v2.md`, guide §14. No consolidated lifecycle document (enrol → active → replace/recover → revoke, with key handling per state). |
| Evidence Format Specification | Exists | `docs/protocol/evidence-format.md` |
| API Reference | Partial | `auth-core/openapi.yaml` + `docs/reference/error-responses.md` + guide. No rendered or prose endpoint reference. Mobile and admin endpoints are described only in OpenAPI and the SDK READMEs. |
| OpenAPI | Exists | `auth-core/openapi.yaml` (44 operations, matches routes: `check:openapi` prints "44 routes match"), `sandbox/openapi.yaml` |
| iOS SDK Integration Guide | Exists | `ios-sdk/README.md`, `ios-sdk-calls/README.md` |
| Android SDK Integration Guide | Exists | `android-sdk/README.md`, `android-sdk-calls/README.md` |
| Bank Integration Guide | Exists | `docs/integration/bank-backend-guide.md`, `docs/integration/pilot-execution-pack.md`, `bank-integration/README.md`. Gaps are listed in §5. |
| HSM Integration Guide | Partial | `docs/security/hsm-key-management.md` (52 lines), `KEY_MANAGEMENT.md`, `runbooks/hsm-unavailable.md`, `runbooks/key-rotation.md`. No vendor-module integration procedure, and production HSM validation is explicitly open (`KEY_MANAGEMENT.md:3`). |
| Database Architecture | Exists under other names | `docs/reference/data-model.md`, `auth-core/migrations/README.md`, `architecture/state-machines.md`, `security/bank-database-authorization.md` |
| Deployment Guide | Exists | `docs/operations/deployment.md`. No manifests or Helm chart, and no production configuration template (§9). |
| Operations Guide | Exists under other names (no index document) | `operations/monitoring.md`, `incident-response.md`, `disaster-recovery.md`, `runbooks/*` (9), `audio-video-calls.md` |
| Security Testing Report | Missing | No report. `release.md:5-25` lists test counts without logs, and `release.md:46` and `:113` record the penetration test as not done. |
| Known Limitations | Partial | `threat-model.md:152` "Residual risks", `release.md:27-46`, `THIRD_PARTY_MEDIA.md`. There is no "Known limitations" document linked from `README.md` or `docs/README.md`. |
| Release Notes | Exists | `CHANGELOG.md` |
| Production Readiness Report | Partial | `docs/operations/release.md` (checklist, unchecked), `README.md:117` "Production readiness" (5 lines). No report with a status per item. |
| Product Feature Compliance Matrix | Missing | No mapping to PSD2/RTS SCA, EBA or any regulation. `release.md:116` delegates this to the bank. |
| Engineering Quality Review | Missing | `docs/engineering/DECISION_LOG.md` is a decision log, not a review. |

Totals: 5 missing (NEXUS ID Specification, Security Testing Report, Product Feature Compliance Matrix, Engineering Quality Review, and a stand-alone Known Limitations document, which exists only partially). 8 partial. The rest exist, several only under other names.

`docs/README.md` (the index) does not link 14 documents: `architecture/bank-trust-boundary.md`, `architecture/payment-state-machine.md`, `integration/pilot-execution-pack.md`, `security/bank-database-authorization.md`, `security/offline-confirmation-threat-model.md`, `protocol/offline-confirmation-v2-deferred-signature.md`, `protocol/bank-credential-trust-v1.md`, `protocol/verification-result-v1.md`, `operations/audio-video-calls.md`, and all 5 `docs/engineering/*.md`. `docs/protocol/README.md` omits `verification-result-v1.md`.

### 2. Claims audit

Legend: **S** = supported by repository evidence; **P** = partly supported (code or tests exist, but results are not reproducible here or are not device- or HSM-validated); **U** = unsupported or contradicted.

| # | path:line | Quote (abridged) | Evidence in repository | Verdict |
|---|---|---|---|---|
| C1 | README.md:41 | "Approval that a third party can verify… An auditor checks all of it offline with a small script that contains no NEXUS-SIGN server code" | `scripts/verify-evidence.mjs`, `scripts/lib/evidence.mjs`, `test/evidence.test.mjs` | S |
| C2 | README.md:41 | "The HSM key holder cannot fabricate a customer's signature, and a device key holder cannot insert a record into the sealed chain" | `test/integration/evidence-forgery-hsm.test.mjs` (not runnable here). Offline v1 code records carry no device signature (`evidence.test.mjs` case 4, `configuration.md:98`). | P (absolute; offline-v1 exception not stated) |
| C3 | README.md:43 | "The same test vectors run in Auth Core, the iOS SDK, the Android SDK and the sandbox" | Vectors and tests exist. iOS was never run and Android was never built with Gradle (`release.md:20-21`, `threat-model.md:176`). | P |
| C4 | README.md:45 | "Step-up checks that cannot be downgraded or skipped" | Integration tests exist but did not run here. Absolute wording. | P, absolute |
| C5 | README.md:47 | "No tokens and no cloud after enrolment… there is no access token to steal or replay" | Recovery uses a bearer "Recovery access token" (`src/` error text "Recovery access token required"; migration 006). Push mode NEXUS uses APNs/FCM (`README.md:49`). | U (overstated) |
| C6 | README.md:48 | Offline: "types an 8-digit code bound to exactly those terms. The same strict checks apply as online." | The v1 code is an HMAC under a key Auth Core also holds (ADR 0003; `configuration.md:98`). v2 leaves the authorization `OFFLINE_PROVISIONAL` until the signature arrives (`state-machines.md:14`). | U (contradicts its own docs) |
| C7 | README.md:49 | "Apple, Google and the database never see its text" | `test/secure-push.test.mjs`, vectors, `protocol/secure-push.md` | S (absolute wording) |
| C8 | README.md:50 | "Entirely inside the bank… there is no shared service operated by a third party" | `pilot-execution-pack.md` §9 matrix: "Customer confirmation protocol, evidence, Auth Core operation: NEXUS-SIGN (vendor) R/A, Bank I"; "Evidence key ceremony and rotation records: vendor R/A". | U (contradiction on who operates Auth Core) |
| C9 | README.md:101 | "Private keys are hardware-backed and non-exportable (Secure Enclave, StrongBox, TEE)" | SDK code exists but was never built or run on a device (`threat-model.md:176`; `DEVICE_ACCEPTANCE_CHECKLIST.md:3` "BLOCKED — nothing has been run"; results table `:97` "No run recorded") | U (design intent only) |
| C10 | README.md:102 | "Verification is atomic and single-use" | `test/integration/invariants.test.mjs` (100 parallel; `release.md:23`). No run log. | P |
| C11 | README.md:105 | "Production startup is fail-closed…" | `src/config/productionPosture.ts`, `test/production-posture.test.mjs`, `test/integration/production-startup.test.mjs` | S |
| C12 | release.md:12 | "Auth Core unit tests… 88 passed" | The current tree has 90 unit tests (baseline here: 80/9 fail/1 skip). No log committed. | U (stale) |
| C13 | release.md:14 | "Passed, 39 routes" | `check:openapi` now reports 44 | U (stale) |
| C14 | release.md:15-16 | "68 passed" integration; "71 checks passed" e2e | No logs or artifacts. The suites have grown since (33 files under `test/integration/`). | P (unverifiable) |
| C15 | release.md:17 | schema.sql vs "1.4.0 schema plus migrations 013 to 018" identical | Migrations 019–022 exist and are not covered by this equivalence claim | U (outdated scope) |
| C16 | release.md:20 | "30 of 34 JVM tests pass" | `android-sdk/src/test` has 60 `@Test` methods | U (stale) |
| C17 | release.md:25, :31; DECISION_LOG.md:8-11 | Dependencies "installed without a reviewed lockfile"; "Until it exists every CI job… fail by design" | `auth-core/package-lock.json` is committed (lockfileVersion 3, 129 packages, all with `integrity`, all from registry.npmjs.org) | U (stale; contradicts repo) |
| C18 | release.md:52-60 | CI table "runs on every pull request" lists 7 jobs | `ci.yml` has 14 jobs. Omitted: `auth-core-media`, `sdk-call-conformance`, `ios-demo`, `android-sdk-calls`, `ios-sdk-calls`, `android-demo`, `demo-bank`. | U (incomplete) |
| C19 | release.md:59 | Android job does "Wrapper validation" | Only implicit through `gradle/actions/setup-gradle` (ci.yml:343 comment). `gradle-wrapper.properties` has no `distributionSha256Sum`. | P |
| C20 | release.md:74 | "`CHANGELOG.md` entry and `VERSION` consistent (`npm run check:repository`)" | `scripts/check-repository.sh:40-50` checks package.json, both openapi files and both SDK constants, **not** CHANGELOG | U |
| C21 | docs/protocol/recovery-protocol-v2.md:254 | "the SDKs' recovery flows on phones… are verified on physical devices" | `DEVICE_ACCEPTANCE_CHECKLIST.md:3,97`: nothing run. `release.md:35`: "Needs devices". | U |
| C22 | docs/adr/0005-two-phase-key-replacement.md:30 | "keychain re-tagging… which is verified on physical devices only" | same as C21 | U |
| C23 | docs/adr/0011-android-key-attestation-policy.md:30 | "The acceptance of a biometric-bound key and the SDK's key generation are verified on devices" | same as C21 | U |
| C24 | docs/security/attestation.md:124 | "…the biometric binding), which is verified on devices" | same as C21 | U |
| C25 | docs/engineering/KEY_MANAGEMENT.md:3, :134-136 | "implemented and tested on SoftHSM 2.7.0"; "Verified on SoftHSM" (×3) | `test/integration/master-key-hsm.test.mjs`, `hsm*.test.mjs`. CI may skip them silently (Part 2, G1). "Not validated on a production HSM" is stated correctly. | P |
| C26 | bank-integration/README.md:7 | "reference implementation, tested with Auth Core on SoftHSM, PostgreSQL, the gateway… behind mutual TLS" | `test/integration/bank-execution-*.test.mjs` gated on SoftHSM (same skip risk) | P |
| C27 | docs/architecture/payment-state-machine.md:3, bank-trust-boundary.md:3, pilot-execution-pack.md:3, protocol/bank-credential-trust-v1.md:3 | "Status: 2.0.0" | No 2.0.0 release exists: VERSION is `2.0.0-rc.2`, and these features are under `CHANGELOG.md` `[Unreleased]` | U |
| C28 | docs/operations/configuration.md:98-106 (8 rows), android-sdk/README.md:47,79,145, ios-sdk/README.md:41,76,165, evidence-format.md:221, bank-backend-guide.md:267 | "New in 2.0.0" / "default on Auth Core 2.0.0" | same as C27. These items are unreleased, and some were added after rc.2 (migrations 019–022 are in `[Unreleased]`, `CHANGELOG.md:18,21,25,34`). | U |
| C29 | docs/security/threat-model.md:3 vs :156-157 | "This page describes release 2.0.0-rc.2" but entries say "addressed in 2.0.0" / "Since 2.0.0" | same as C27 | U (internal) |
| C30 | docs/engineering/NATIVE_BUILD_GUIDE.md:49 | "the owner's Mac has Xcode 26.5" | A personal environment detail in a deliverable; not a product claim | Remove |
| C31 | docs/operations/audio-video-calls.md:16 | "No media passes through Auth Core. Nothing is recorded." | `verificationCall.ts` relays signalling only; `test/media/webrtc-call.test.mjs` | S |
| C32 | docs/architecture/overview.md:14; bank-backend-guide.md:236 | APNs/FCM "cannot read them"; "neither its database nor Apple nor Google can read it" | secure-push vectors and tests | S (absolute wording) |
| C33 | docs/protocol/recovery-protocol-v2.md:5 | "Nothing Auth Core stores is enough to complete a recovery" | `test/integration/recovery.test.mjs` (DB-content-alone case) | P (absolute) |

Correctly hedged statements (no action needed): `threat-model.md:3` ("not a certification artifact"), `evidence-format.md:271` ("detectable, not impossible"), `THIRD_PARTY_MEDIA.md:3`, `ios-sdk/README.md:76`, `upgrade-2.0.md:170`, `sandbox/README.md:117`, `KEY_MANAGEMENT.md:3` ("Not validated on a production HSM").

Absolute language search: no occurrence of unbreakable, guaranteed, 100%, tamper-proof, bank-grade, military-grade, certified or "production-ready". Absolute "cannot / never" security wording appears at README.md:41 (×2), :45, :47, :49, overview.md:14, bank-backend-guide.md:236 and recovery-protocol-v2.md:5. No PSD2, SCA, eIDAS, PCI, ISO 27001, SOC 2 or FIPS compliance claims. "FIPS" appears only as a technical HSM constraint (`KEY_MANAGEMENT.md:147`). Performance numbers: none claimed. Timeouts only (`hsm-unavailable.md:14`, `database-or-redis-outage.md:23`).

**Count: 21 of the 33 claims are unsupported or contradicted (U): C5, C6, C8, C9, C12, C13, C15–C18, C20–C24, C27–C29 (the 18 listed) plus 3 counted under C27/C28 groups. 10 are partly supported (P).**

### 3. Contradictions

| # | Between | Detail |
|---|---|---|
| X1 | README.md:50 vs pilot-execution-pack.md §9 (`:125-139`), overview.md:11,15 | Who operates Auth Core and owns the evidence key ceremony: "bank's perimeter… no third party" vs vendor R/A |
| X2 | README.md:48 vs ADR 0003, configuration.md:98, state-machines.md:14 | Offline "same strict checks as online" vs an HMAC code under a server-held key, and a provisional state in v2 |
| X3 | recovery-protocol-v2.md:254, adr/0005:30, adr/0011:30, attestation.md:124 vs release.md:35, threat-model.md:176, DEVICE_ACCEPTANCE_CHECKLIST.md:3,97 | "verified on (physical) devices" vs "nothing has been run on a device" |
| X4 | release.md:25,31 and DECISION_LOG.md:8-11 vs `auth-core/package-lock.json` | "no lockfile" vs lockfile committed |
| X5 | release.md:14 (39 routes), :12 (88), :20 (34 JVM tests) vs repository (44 routes, 90 unit tests, 60 JVM tests) | Stale results |
| X6 | data-model.md:91-102 (mermaid) vs state-machines.md:13-15, migration 022, schema.sql | The diagram omits `OFFLINE_PROVISIONAL` and `OFFLINE_UNSIGNED`, so it describes the pre-022 machine |
| X7 | VERSION / package.json / openapi / SDK constants (all `2.0.0-rc.2`, consistent; check-repository passes) vs docs "Status: 2.0.0" (C27) and "New in 2.0.0" (C28) | Unreleased features labelled as a released version |
| X8 | release.md:74 vs check-repository.sh | CHANGELOG is not checked |
| X9 | CHANGELOG.md:66,91 | rc.1 and rc.2 both dated 2026-10-07. KEY_MANAGEMENT.md:126,152,162,172 and DECISION_LOG entries dated 2026-10-18/19 describe "2.0.0" behaviour after rc.2. The version label was not bumped. |
| X10 | env names: configuration.md vs env.ts vs .env.example | **No mismatch in names.** All 80 names in configuration.md exist in env.ts. All 86 env.ts keys are documented (the `_WRAPPED` and `_PREVIOUS_WRAPPED` variants are documented as a compound row at `configuration.md:108`). Defaults spot-checked and equal: PORT 8080, AUTHORIZATION_EXPIRY_SWEEP_MS 10000, SHUTDOWN_DRAIN_MS 15000, WEBRTC_TURN_CREDENTIAL_TTL_SECONDS 600, OFFLINE_SIGNATURE_DEADLINE_HOURS 72, OFFLINE_CONFIRMATION_MODE deferred_signature, DEVICE_NONCE_STORE postgres, MASTER_KEY_SOURCE env, HSM_ADAPTER software. `.env.example` omits 14 env.ts keys: `METRICS_BEARER_TOKEN`, `DEVICE_NONCE_STORE`, `SHUTDOWN_DRAIN_MS`, `AUTHORIZATION_EXPIRY_SWEEP_MS`, `WEBRTC_STUN_URLS`, `WEBRTC_TURN_URLS`, `WEBRTC_TURN_SECRET`, `WEBRTC_TURN_CREDENTIAL_TTL_SECONDS`, and the 6 `*_PREVIOUS` / `*_PREVIOUS_WRAPPED` keys. `METRICS_BEARER_TOKEN` is a production requirement (`configuration.md:103`). |
| X11 | bank-backend-guide.md endpoints vs openapi.yaml | **No mismatch.** Every endpoint in the guide exists in OpenAPI. The only bank-facing operation in OpenAPI not named as `METHOD /path` in prose is `POST /v1/nexus-identities`, which is shown in the curl at `:64`. |
| X12 | state-machines.md vs migrations 017/018/022 | **Consistent.** 017 defines `CREATED`, `DELIVERING`, `SIGNED` and `CONSUMED`, which 018 removes; `state-machines.md:3` says so. 022 adds the OFFLINE_* states, which the doc covers (`:13-15`). The bank transaction states match `schema.sql:498-499`. |
| X13 | Versions | VERSION, package.json:3, package-lock root, both openapi `info.version`, `NEXUSSignVersion.kt:4`, `NEXUSSignVersion.swift:3` = `2.0.0-rc.2`. The Gradle builds read VERSION (`build.gradle.kts:9` in both modules). Consistent. The inconsistency is only in the prose (X7). |
| X14 | README.md:47 "no access token" vs recovery access token (C5) | |
| X15 | docs/README.md:31 "Lifecycle state machines… authorization, bank transaction, credential and identity" vs data-model.md (X6) | Two state descriptions; only one is current |

### 4. Editorial quality

Overall the prose is technical and largely free of marketing language. Measured results:

| Check | Result |
|---|---|
| Generic or promotional headings | 1: `README.md:39` "## Key properties". None of Overview, Introduction, Conclusion, Why It Matters, Robust, Seamless, Comprehensive or Enterprise-grade. |
| Marketing adjectives (robust, seamless, comprehensive, enterprise-grade, powerful, cutting-edge, bank-grade…) | 0 occurrences |
| Tagline | `README.md:3` "**Cryptographic Transaction Authorization & Digital Trust Layer**" (Title Case, bold, "&") |
| Announcing sentences | 3: `sandbox/HOSTING.md:3`, `docs/protocol/evidence-format.md:5`, `docs/reference/error-responses.md:3`. All carry content, so low priority. |
| ALL-CAPS headings | `docs/protocol/evidence-format.md:49` "### AUTHORIZATION" (a record type name, acceptable if code-formatted) |
| Heading case | Sentence case throughout. Title Case only at `auth-core/README.md:1`, `attestation.md:19,25` (proper nouns, fine). |
| Heading levels | 0 level skips; every file has exactly one H1 |
| Numbered headings | Only in procedural documents: bank-backend-guide.md (14), pilot-execution-pack.md (11), recovery-protocol-v2.md (8), bank-database-authorization.md (8), lost-or-stolen-device.md (2). Acceptable. |
| Emoji | 0 |
| Heavy bold (`**…**` pairs) | offline-confirmation-threat-model.md 42, sandbox/README.md 27, bank-database-authorization.md 26, THIRD_PARTY_MEDIA.md 24, threat-model.md 21, upgrade-2.0.md 20 |
| Empty citation residue (text deleted, punctuation left) | `ios-sdk/README.md:41` "(new in 2.0.0, )"; `docs/adr/0003-offline-confirmation-hmac-codes.md:32` "(2.0.0, )"; `docs/security/threat-model.md:156` "(; addressed in 2.0.0)"; `threat-model.md:113`, `:157`; `docs/engineering/DECISION_LOG.md:157` "(…; )"; `DECISION_LOG.md:11` "…stays open until" (subject missing); `DECISION_LOG.md:5-7` D-001 heading with an empty body; `CHANGELOG.md:17,18,32`; `docs/adr/0001-canonical-json-signed-payload.md:22` |
| Internal process jargon in deliverables ("phase N", gate "G4") | `payment-state-machine.md:5` "Since phase 15"; `bank-database-authorization.md:97` "Upgrade from phase 14"; `offline-confirmation-threat-model.md:3,95,183,239`; `DEVICE_ACCEPTANCE_CHECKLIST.md:3,5`; `DECISION_LOG.md:118,141,149,188,197,207`; `NATIVE_BUILD_GUIDE.md:3` "(G4)" |
| Diary-style dated sections in reference docs | `KEY_MANAGEMENT.md:126,152,162,172` "(2026-10-18/19)"; `THIRD_PARTY_MEDIA.md:17` |
| Overlong paragraph | `bank-backend-guide.md:328`, about 1,500 characters in one paragraph that mixes contract, architecture and procedure |

**Repeated explanations (duplicates):**

| Topic | Locations |
|---|---|
| Bank as system of record; "does not replace core banking, fraud systems, IAM, HSM/KMS…" | README.md:37 and overview.md:68 (near-verbatim) |
| Offline QR / 8-digit code flow | README.md:48, overview.md:54-60, device-authentication-and-offline-confirmation.md:6, bank-backend-guide.md §10, offline-confirmation-v2…md |
| Gateway mTLS and header overwrite | threat-model.md:83-89, deployment.md:53-72, configuration.md:158-161, adr/0015, auth-core/README.md:71, release.md:43,106 |
| Account-first beneficiary display, 140 characters | android-sdk/README.md:145 and ios-sdk/README.md:165 (verbatim), DECISION_LOG D-013 |
| Push sealing ("Apple, Google… cannot read") | README.md:49, overview.md:14,43, bank-backend-guide.md:236, secure-push.md |
| Execution boundary contract | bank-backend-guide.md:328, bank-trust-boundary.md, payment-state-machine.md, pilot-execution-pack.md §1, bank-integration/README.md |

**Terminology (counted with grep, case-insensitive, over README files and docs/):**

| Concept | Competing terms (occurrences) | Where |
|---|---|---|
| The device-held key set | "credential" (517), "device key" (28), "signing key" (75), "device credential" (18), "Device-bound Credential" (README.md:17), "key slot" (adr/0005:15; Android `KeySlots.kt`) | CONTRIBUTING.md:20 mandates "device credential", which is used in only 17 files |
| Customer act | "confirm/confirmation" (267), "approval/approve" (108/66), "authorize" | README.md:41 "Approval that a third party can verify", README.md:42 "when an approval is disputed", secure-push.md:12 "approves", SDK method `approve` vs states `VERIFIED`, `confirmationMethod`. "approval" also means admin four-eyes approval (`admin_approvals`, ADR 0014) and bank device-key approval (bank-trust-boundary.md:13). Three meanings for one word. |
| Sealed output | "evidence record" (31), "authorization record" (README.md:5, glossary.md:46, bank-credential-trust-v1.md:76), "proof" (53, also the recovery proof), "seal / HSM seal" (84/22) | |
| Evidence key | "evidence key" (88), "sealing key" (10), "seal key" (2), "evidence signing key" (1) | e.g. evidence-format.md vs data-model.md |
| The bank as API caller | "bank client" (66), "client" (281), "tenant" (auth-core/README.md:89, release.md:23), `clientId` in the API | |
| Identity | "NEXUS ID" (consistent), "NEXUS identity" (adr/0016:29, state-machines.md:68), table `nexus_identities` | |
| Recovery secret | "recovery phrase" (24), "mnemonic" (recovery-protocol-v2.md:246) | |
| Step-up | "adaptive verification" (22), "escalation" (18), "step-up" (5) | |

**File naming inside docs/:** 5 UPPER_SNAKE files (`docs/engineering/DECISION_LOG.md`, `DEVICE_ACCEPTANCE_CHECKLIST.md`, `KEY_MANAGEMENT.md`, `NATIVE_BUILD_GUIDE.md`, `THIRD_PARTY_MEDIA.md`) against 64 kebab-case files. `docs/compatibility-and-versioning.md` and `docs/glossary.md` sit at the docs root, outside any section.

### 5. Bank integration documentation

| Question | Answered? | Where / gap |
|---|---|---|
| What the bank must implement | Partly | Spread over bank-backend-guide.md §1–14 and pilot-execution-pack.md §10. No consolidated "bank deliverables" checklist (backend calls, webhook receiver, chain-head store, execution boundary, trust registry, app integration, gateway, HSM trust key). |
| What NEXUS-SIGN provides | Yes | overview.md:9-16, README.md:52-61 |
| What stays under bank control | Yes | README.md:37, overview.md:68, payment-state-machine.md:7-14 |
| Who owns each security decision | Partly, contradictory | pilot-execution-pack.md §9 has a RACI covering only 9 activities, and it conflicts with README.md:50 (X1). Missing owners: attestation policy (`ANDROID_KEY_SECURITY_POLICY`), offline caps, step-up thresholds/policy, admin account provisioning, key rotation schedule, data retention. |
| Who executes the payment | Yes | bank-backend-guide.md:326-337, payment-state-machine.md:9-14 ("Money moved… the payment provider") |
| What data crosses the bank perimeter | No | No data-flow inventory. The only fragments are threat-model.md:59 (personal data held), README.md:50 (Apple/Google attestation and APNs/FCM) and data-model.md:213 (retention). Not stated: which fields go to Apple App Attest, Play Integrity, Google status list fetch (`ANDROID_ATTESTATION_STATUS_FILE`), APNs/FCM (envelope metadata, device tokens), and TURN/STUN for calls (operations/audio-video-calls.md). |
| What evidence is produced | Yes | evidence-format.md, guide §12 (`:446-487`), webhook `evidence.appended` (`:267`) |
| What must be validated during integration | Partly | pilot-execution-pack.md §10 (execution boundary only), release.md:64-116 checklist. The guide has no acceptance test list for enrolment, authorization, offline, recovery, replacement or webhooks; it points to `scripts/e2e-smoke.mjs` (`:3`) as the reference. |
| Integration environment | Yes | deployment.md:87-102 |

### 6. Diagrams

There are 10 diagrams: 9 ASCII/text blocks and 1 mermaid block. No image files.

| path:line | Type | Component names vs code | Implies NEXUS-SIGN executes payments? |
|---|---|---|---|
| README.md:9-33 | ASCII flow | "Independent Verification", "Policy / Risk Context", "Exact Transaction Binding" are not component names. Auth Core, the actual verifying component, is not named at all. "NEXUS-SIGN SDK" is correct. | **Ambiguous.** The single linear chain from "NEXUS-SIGN SDK" ends in "Bank Commit → Core Banking" with no boundary marking the bank's side. |
| overview.md:20-37 | ASCII sequence | Matches routes and services | No; `:35` "Bank backend: bank-commit-request → core banking" |
| overview.md:45-48 | ASCII | Matches | No |
| overview.md:56-60 | ASCII | Matches | No |
| bank-trust-boundary.md:7-24 | box diagram | Matches `bank-integration/` (execution boundary, gateway, adapter) | No (explicit separation) |
| pilot-execution-pack.md:11-36 | sequence | Matches (`execute`, `bank.approve`, `bank.submit`) | No |
| offline-confirmation-v2-deferred-signature.md:66-75 | state | Matches migration 022 | n/a |
| secure-push.md:98-103 | state | Matches push states | n/a |
| data-model.md:91-102 | mermaid stateDiagram | **Outdated:** missing `OFFLINE_PROVISIONAL` and `OFFLINE_UNSIGNED` (X6) | n/a |
| authorization-protocol-v1.md:78 | text template | (branch-changed file; not assessed) | n/a |

---

## PART 2: CI/CD and release engineering

### 7. Workflows

**ci.yml (14 jobs; top-level `permissions: contents: read`; every `uses:` pinned to a 40-character SHA with a version comment).** The SHAs were not resolved against GitHub here, and `release.md:38` says the same.

| Job (ci.yml line) | What it really verifies | Can pass without testing? |
|---|---|---|
| auth-core (16) | `npm ci` from the lockfile, typecheck, build on Node 22 and 24, `check:all` (unit tests, vectors, iOS vector copies, OpenAPI routes, hygiene and version check), OpenAPI parses | No |
| auth-core-integration (47) | `npm run test:integration` against PG16, Redis 7, SoftHSM from apt | **Yes, partly.** 9 suites are gated on `skipWithoutSoftHsm` (`test/integration/support/softhsm.mjs:43-46`), which skips when the SoftHSM build lacks `CKM_ECDSA_SHA256` ("build SoftHSM 2.7+"). The job installs the distribution package (`ci.yml:82`, ubuntu-24.04). Its version was not checked here; if it is below 2.7 the HSM, evidence-forgery, bank-trust-compromise, bank-execution-*, master-key-hsm, evidence-metadata-binding and hsm-in-place-decryption suites report "skipped" and the job is green. Nothing fails on skipped suites. |
| auth-core-media (95) | Real WebRTC between two Chromium pages through Auth Core | Skips if Playwright is missing (`test/media/webrtc-call.test.mjs:21`). It is installed in the job, so this is low risk. |
| sdk-call-conformance (141) | Android `CallConformanceTest` (JVM, scripted media) driven by Auth Core | Skips without `NEXUS_CALL_CONFORMANCE_CMD` (set). In the plain `android-sdk` job the same test is skipped through `assumeTrue` (`CallConformanceTest.kt:122`). |
| auth-core-e2e (193) | schema twice + all migrations, roles, `e2e-smoke.mjs` as `nexus_app` | Runs with `ALLOW_INSECURE_DEVELOPMENT`, `HSM_ADAPTER=software`, `REQUIRE_VALID_ATTESTATION=false` (222-230). It does not exercise the production posture. `cat server.log \|\| true` (292) is cosmetic. |
| container-images (294) | Builds both images. **Health-checks only the sandbox.** The Auth Core image is never started, despite the job name "build and health check". | Auth Core image: build only |
| ios-sdk (308) | `swift test` on the macOS host (Package.swift adds `.macOS(.v12)` for this). Secure Enclave, App Attest and Keychain paths are not exercised. | No |
| ios-demo (319) | `xcodebuild` for iphoneos (unsigned). The only job that compiles the SDK for iOS. | n/a |
| android-sdk (331) | Real Gradle Android library build (`assembleRelease`) + JVM unit tests (`testDebugUnitTest`). These are not JVM stubs, but there are no instrumented or emulator tests (no `src/androidTest`). | No |
| android-sdk-calls (347) | Builds the WebRTC module; records SHA-256 of resolved artifacts as a workflow artifact (90 days). There is no comparison against an expected checksum, so it records but does not verify. | n/a |
| ios-sdk-calls (372) | Builds for iOS. Provenance step `cat Package.resolved 2>/dev/null \|\| find …` (384) passes with no output if nothing is found. No `Package.resolved` is committed. | Provenance step can be empty |
| android-demo (386) | Debug APK | n/a |
| demo-bank (408) | 7 node tests | No |
| sandbox (419) | unittest on Python 3.10 | `test_protocol.py:170` skips when PyYAML is missing (it is not installed by the job, so that check always skips in CI) |

**security.yml:** CodeQL **JavaScript/TypeScript only** (no Kotlin/Java, Swift or Python SAST), results gated at ≥7.0 with an allow-list of 6 reviewed findings (`.github/codeql/reviewed-findings.tsv`), SARIF kept as an artifact only (not uploaded). SBOM: CycloneDX of **auth-core npm production deps only** (no SDK, sandbox or image SBOM); `npx --yes @cyclonedx/cyclonedx-npm@6.0.1` fetches the tool's own dependency tree unlocked. Trivy: filesystem scan of the whole repository (HIGH/CRITICAL, fixed only) plus the Auth Core image. **The sandbox image is not scanned.** `npm audit --omit=dev --audit-level=high`. Gitleaks v8.21.2, checksum-verified, full history.

**release.yml:** on `v*` tags it builds the Auth Core image, saves a `.tar.gz` with a SHA-256, makes a CycloneDX SBOM and a SLSA provenance attestation, and uploads them as a **workflow artifact**. **It publishes nothing:** no registry push, no GitHub Release, no Maven/SwiftPM publication (both Gradle modules declare `maven-publish`, but nothing runs it), no image signature beyond the attestation. It does not depend on CI passing or re-run tests. There is no check that the tag equals `VERSION`. The artifact has the default retention.

**Controls summary:**

| Control | Present | Gap |
|---|---|---|
| SHA-pinned actions | Yes (all) | Not verified here |
| permissions blocks | Yes (top-level read; job-level for codeql/release) | none found |
| Secrets handling | No repository secrets used. e2e client secret masked (`ci.yml:264`); throwaway keys generated per run (235, 269). | Service DB passwords `postgres` / `nexus` / `nexus-app-ci` in plain text (ephemeral, acceptable) |
| SBOM | auth-core npm only | SDKs, sandbox, container OS packages |
| Dependency vulnerability scan | npm audit + Trivy fs | Gradle and SwiftPM deps not audited except through Trivy fs (no Gradle lockfile, so limited) |
| License check | **None** | `THIRD_PARTY_MEDIA.md` lists the licence review as an open release blocker |
| Secret scan | gitleaks | Allow-list excludes vectors and fixtures (`.gitleaks.toml:6-11`) |
| SAST | CodeQL JS/TS | Kotlin, Swift, Python not scanned |
| Container scan | Trivy (Auth Core image) | Sandbox image |
| Reproducible build | Partial: `gzip -n`, `npm ci` with lockfile | Base images by tag (`node:22-alpine`, `python:3.12-slim`, `caddy:2`, `postgres:16-alpine`, `redis:7-alpine`); no `SOURCE_DATE_EPOCH`; no Gradle `distributionSha256Sum` (`android-sdk/gradle/wrapper/gradle-wrapper.properties`), no `gradle/verification-metadata.xml`, no committed `Package.resolved` |
| Dependabot | npm, gradle (android-sdk), swift (ios-sdk), docker (auth-core, sandbox), actions | Missing: `android-sdk-calls` (WebRTC), `ios-sdk-calls` (WebRTC), `demo/android`, `sandbox/deploy` compose (`caddy:2`) |

### 8. Dependency hygiene (auth-core)

| Dependency | Range | Locked | Imported in src/ (files) |
|---|---|---|---|
| express | ^4.19.2 | 4.22.3 | 14 |
| pg | ^8.12.0 | 8.23.1 | 15 |
| ioredis | ^5.4.1 | 5.11.1 | 1 |
| zod | ^3.23.8 | 3.25.76 | 7 |
| helmet | ^7.1.0 | 7.2.0 | 1 |
| pino | ^9.3.2 | 9.14.0 | 6 |
| pino-http | ^10.2.0 | 10.5.0 | 1 |
| cbor | ^9.0.2 | 9.0.2 | 1 |
| pkcs11js | ^2.1.6 | 2.1.7 | 3 |
| prom-client | ^15.1.3 | 15.1.3 | 1 |
| @types/express, @types/node, @types/pg, typescript (dev) | ^ | locked | type-only / build |

- No unused dependencies. No missing ones: tests and scripts use only `pg` and Node built-ins, plus `typescript` in `test/support/load-ts.mjs:11`. Playwright is installed ad hoc in CI (`ci.yml:136`), which is intentional.
- Lockfile: v3, 129 packages, **all have `integrity`**, all resolved from registry.npmjs.org, root version matches. All ranges are caret ranges, so `npm install` (not `ci`) in `README.md:79` and `auth-core/README.md` can drift. Quick start uses `npm install --ignore-scripts`, CI uses `npm ci`.
- `auth-core/Dockerfile`: multi-stage, non-root `nexus` user (`:30-31`), npm/corepack removed, HEALTHCHECK on `/healthz`. Base `node:22-alpine` is **tag-pinned, not digest-pinned** (`:5`, `:16`). The build stage runs `npm ci` **with install scripts enabled** (`:11`) for every package, not only pkcs11js. No `--ignore-scripts` plus targeted `npm rebuild pkcs11js` as CI does (`ci.yml:88-90`).
- `sandbox/Dockerfile`: `python:3.12-slim` by tag, non-root `sandbox` user, HEALTHCHECK. Fine apart from the digest.
- `auth-core/.dockerignore`: excludes `.env` but not `.env.*`. Harmless today because the Dockerfile copies explicit paths.
- `auth-core/docker-compose.yml`: `POSTGRES_PASSWORD: nexus` (`:8`), Redis without a password, ports bound to `127.0.0.1` (`:11`, `:22`), and a header comment says "not for any shared environment". Unsafe if copied to production (fixed password, no Redis auth, no TLS), but labelled.
- `sandbox/deploy/docker-compose.yml`: requires secrets through `:?` (`:10-11`), read-only, `cap_drop: ALL`, `no-new-privileges`. Caddy publishes 80/443 publicly by design. `caddy:2` is floating.

### 9. Configuration templates and secret material

| Item | Finding |
|---|---|
| Development template | `auth-core/.env.example` (NODE_ENV=development `:3`, ALLOW_INSECURE_DEVELOPMENT=true `:6`, HSM_ADAPTER=software `:19`, REQUIRE_VALID_ATTESTATION=false `:82`, REQUIRE_MTLS_HEADER=false `:100`, DATABASE_URL with `nexus:nexus` `:9`). It is missing 14 keys (X10). |
| Test configuration | Hard-coded in `test/support/load-ts.mjs:15-17`, `test/integration/support/harness.mjs:118` and the CI job env. No `.env.test`. |
| Production template | **Missing.** Production values exist only as the "Production" column of `configuration.md` and the blocker table (`:165-229`). There is no `.env.production.example`, Kubernetes Secret/ConfigMap example or Helm values file. |
| Secrets-management guidance | Present but short: `configuration.md:52,180`, `deployment.md:44,115` ("Bank-approved secrets manager"), `KEY_MANAGEMENT.md` (wrapped master keys). No guidance on rotation of `PKCS11_PIN`, `METRICS_BEARER_TOKEN` or `WEBRTC_TURN_SECRET`. |
| Insecure defaults | `REQUIRE_MTLS_HEADER`, `REQUIRE_VALID_ATTESTATION` and `HSM_ADAPTER=software` are insecure by default (`env.ts:64,209,185`; `configuration.md:50,70,158` "Opt-in flag"). Mitigated only when `NODE_ENV=production` through `productionPosture.ts`. A misnamed environment (e.g. `NODE_ENV=staging`, which env.ts refuses) is caught, but `development` with `ALLOW_INSECURE_DEVELOPMENT=true` runs with all controls off. |

Regex scan (private-key blocks, ≥64-hex or ≥40-base64 literals, `password=`/`secret=` assignments, tracked files):

| path:line | Content | Labelled test fixture? |
|---|---|---|
| auth-core/test/production-posture.test.mjs:86 | `APNS_PRIVATE_KEY_PEM` with a PEM header string | Yes (unit test input) |
| auth-core/test-vectors/generate-device-protocol-vectors.mjs:50, :94, :95 | fixed P-256 private scalars (`fixedKey('4b1e…')` etc.) | Yes, in a vector generator. Not covered by the gitleaks path allow-list (`.gitleaks.toml:7-11` lists only the JSON files), so gitleaks may flag them. |
| auth-core/test-vectors/generate-recovery-vectors.mjs:28, :38 | fixed private scalars | Yes (generator) |
| auth-core/test-vectors/generate-secure-push-vectors.mjs:31, :32 | fixed private scalars | Yes (generator) |
| auth-core/test-vectors/*.json, ios-sdk/Tests/.../Resources/*.json | key material in vectors | Yes (gitleaks allow-listed) |
| auth-core/test/fixtures/android-key-attestation/*.pem (3) | public certificate chains | Yes (listed in `scripts/public-material.txt`, checked to contain no private key) |
| sandbox/tests/vectors/ecdsa-interop.json:8-21, sandbox/tests/test_hosted.py:75 | public keys and signatures | Yes |
| auth-core/scripts/run-local.sh:19, :61 | `nexus:nexus`, `PASSWORD 'nexus-app-local'` | Local-only script |
| .github/workflows/ci.yml:59,107,153,205,255 | `postgres`, `nexus`, `nexus-app-ci` | CI ephemeral services |
| auth-core/src/crypto/p256PublicKey.ts:6, pkcs11HsmAdapter.ts:59, sandbox/server/p256.py:26 | the P-256 SPKI DER prefix | Not a secret |

No live-looking secrets found.

---

## PART 3: Tests and repository hygiene

### 10. Test classification

**auth-core unit tests (`test/*.test.mjs`, 19 files; they load real `src/` TypeScript through `load-ts.mjs`, and `stubs` replace only the database, Redis, env and neighbouring services):**

| File | Type | Security property asserted | Real code vs stubs |
|---|---|---|---|
| admin-totp | unit | RFC 6238 TOTP, replay of used step | real `crypto/totp.ts` |
| android-key-attestation | unit (real device chains) | chain verification, StrongBox/TEE policy, challenge binding, revocation list | real |
| bank-trust | unit / contract (vectors) | bank trust statements, fail-closed execution decision | real `scripts/lib` |
| crypto | unit | strict DER, P-256 SPKI only, software HSM refuses malformed input | real |
| device-attestation-policy | unit | enrolment decision from attestation results | Play Integrity, App Attest and the chain verifier are **stubbed** (documented at `:5-7`). Decision logic is real. |
| device-protocol | unit / contract | request signing input, offline code, key derivation | real; env stubbed |
| error-handler | unit | no detail leakage on 500 | 5 error classes replaced by a generic `Named` stub (`:9-13`), so the mapping of those specific classes is only partly exercised |
| evidence | unit / contract | chain tamper detection, device signature re-verified offline | real; pool stub throws |
| gateway-and-webhooks | unit / contract | mTLS exemption = device routes in OpenAPI; SSRF address classification | real |
| low-findings | unit / regression | nonce window, webhook secret binding, APNs DEVELOPMENT refusal | real with infrastructure stubs |
| mobile-session | unit | BOOTSTRAP-only tokens, legacy SESSION refused, disabled client refused | middleware real; all 6 collaborators stubbed (`:9-16`) |
| production-posture | unit | production blockers | real. Test `:121` skips without `dist/` (reason given). |
| property-fuzz | property | canonical JSON, display rules, DER parser robustness, PEM mutation | real (seeded) |
| protocol | unit / contract | signature over canonical bytes only | real |
| recovery-vectors | contract | recovery v2 inputs, phrase-only unwrap | real |
| regression-2.0 | unit / regression | NEXUS ID collision retry, ES256-only JWS | identity service with in-memory pool stub; JWS real |
| secret-box | unit | key-ID, purpose and owner binding, previous-key decryption | real |
| secure-push | unit / contract | key agreement, sealing, receipt binding, invalid envelopes | real |

No test was found that only asserts a stub's own configured return value. The closest are `mobile-session.test.mjs:44` (asserts 401 when the stubbed client status is `DISABLED`) and `device-attestation-policy` (asserts propagation of a stubbed failure); both still execute real branching code.

**Coverage gap:** `src/services/appAttestService.ts` (192 lines) and `playIntegrityService.ts` (102 lines) are exercised by **no test**. They are stubbed in unit tests, and the integration harness runs with `REQUIRE_VALID_ATTESTATION: 'false'` (`harness.mjs:118`). `attestation-policy.test.mjs:20` enables the flag only to test refusal of UNKNOWN credentials. `attestation.md:124` acknowledges this.

**Integration (`test/integration/*.test.mjs`, 33 files; real Auth Core processes from `dist/`, real PostgreSQL and Redis, SoftHSM where marked [H]):** admin-audit-mtls, attestation-policy, bank-db-authorization, bank-execution-boundary [H], bank-execution-processes [H], bank-trust-compromise [H], db-roles, device-replacement, display-rules, evidence-checkpoints, evidence-forgery-hsm [H], evidence-integrity, evidence-metadata-binding [H], expiry, hsm [H], hsm-in-place-decryption [H], invariants (concurrency, single use), key-rotation, key-rotation-interrupted, master-key-hsm [H], metrics-access, nonce-store, offline-deferred-signature, offline-enforcement, offline-forgery, offline-limits, production-startup, recovery, state-machine (includes a property test), verification-call, verification-results (+ `bank-p256`, branch work, not assessed). All are env-gated through `describe(…, { skip: skipWithoutServices [|| skipWithoutSoftHsm] })`. Every gated suite has a reason string (`harness.mjs:26-28`, `softhsm.mjs:43-46`).

**Media / end-to-end:** `test/media/webrtc-call.test.mjs` (e2e media, gated `:21`), `test/media/sdk-call-conformance.test.mjs` (cross-component conformance, gated `:18`), `scripts/e2e-smoke.mjs` (e2e, CI only).

**Vector checks:** `test-vectors/check-signed-payload-vectors.mjs`, `check-vector-copies.mjs` (contract).

**Android (`android-sdk/src/test`, 11 test classes, 60 `@Test`):** JVM unit and contract tests of pure-logic classes (vectors, KeySlots, OfflineSignatureQueue, RecoveryPhrase/Protocol, SecurePush, SignedTransaction, VerificationCall controller, config). No test touches `KeyManager.kt`, `NetworkClient.kt`, `NEXUSSignSDK.kt` or `AttestationProvider.kt`. `CallConformanceTest` skips through `assumeTrue` without `NEXUS_CALL_CONFORMANCE` (`:122`, reason given).

**iOS (`ios-sdk/Tests`, 8 files, 36 `func test`):** same pattern. No test touches `KeyManager.swift`, `NetworkClient.swift`, `NEXUSSignSDK.swift`, `SDKState.swift` or `AttestationProvider.swift`. These have never been executed (`release.md:21`).

**Sandbox (`sandbox/tests`, 74 tests):** `test_protocol.py` (contract and vectors; `:170` skips without PyYAML, reason given), `test_api.py` (API), `test_hosted.py` (hosted access control). **Demo:** `demo/bank-backend/test/pairing.test.mjs`, `status.test.mjs` (unit).

**Skipped / gated tests:** 41 `describe`/`test` skip conditions in total. All give reasons. No `todo` and no unconditional `skip`.

### 11. Dead, orphaned or vague files and markers

| Item | Finding |
|---|---|
| `auth-core/scripts/verify-baseline.sh` | Not referenced by package.json, any workflow, any doc or any script (grep). Writes `baseline-report.txt`, which is not in `.gitignore`. Orphan. |
| `auth-core/test/integration/support/recovery.mjs` | A 2-line re-export of `scripts/lib/recovery.mjs`. Used by 2 tests. Thin indirection only. |
| Vector duplicates | `ios-sdk/Tests/NEXUSSignTests/Resources/*.json` (5 files) duplicate `auth-core/test-vectors/*.json`. Intentional and enforced by `check-vector-copies.mjs` and CONTRIBUTING.md:7. |
| BIP-39 word list | `android-sdk/src/main/assets/bip39_english.txt` and `ios-sdk/Sources/NEXUSSign/Resources/english.txt` are byte-identical, with different names and no copy check. |
| Gradle wrapper | `gradle-wrapper.jar`, `gradlew` and `gradlew.bat` duplicated in `android-sdk/` and `android-sdk-calls/`. `demo/android` uses `../../android-sdk/gradlew` (ci.yml:401). |
| Fixtures | `*.expected.json` are used dynamically (`android-key-attestation.test.mjs:13`); `status-example.json` and `synthetic-path-chains.json` are referenced. Not orphans. |
| Vague module names | `KeyManager.kt`/`.swift` (manager). No utils, helper or common modules. `auth-core/scripts/lib/` holds production-relevant verifier code (`bankTrust.mjs`, `evidence.mjs`) that `bank-integration/paymentGateway.mjs:60` and the guide (`bank-backend-guide.md:328`) depend on, so "scripts" understates it. |
| TODO / FIXME / HACK / XXX / TEMP markers | 0 in source. (The `DEBUG` and `TEMP` hits are in Gradle wrapper boilerplate, the pbxproj file and an env allow-list, all false positives.) |
| Commented-out code | 0 blocks found by heuristic |
| Line-ending risk | `.gitattributes:1` `* text=auto eol=lf` also forces LF on `gradlew.bat` (×2). Batch files with LF endings can misparse labels/`goto` on Windows cmd. Add `*.bat text eol=crlf`. |
| Personal or environment details | `NATIVE_BUILD_GUIDE.md:49` (owner's Mac and Xcode version) |

### 12. Naming consistency

| Area | Inconsistency |
|---|---|
| docs/ files | 5 UPPER_SNAKE (`docs/engineering/*`) vs 64 kebab-case |
| Test file naming | auth-core `kebab.test.mjs`; Android `*Test.kt`; iOS `*Tests.swift`; sandbox `test_*.py`. Within the mobile pairs: `BankTrustVectorsTest.kt` vs `BankTrustVectorsTests.swift`; `NEXUSSignConfigTest.kt` vs `ConfigurationTests.swift`. Android has `KeySlotsTest`, `RecoveryPhraseTest` and `CallConformanceTest` with no iOS counterparts. |
| SDK source parity | `WebRtcCallEngine.kt` vs `WebRTCCallEngine.swift` (acronym casing). iOS-only: `CertificatePinning`, `SDKState`, `SubjectPublicKeyInfo`. Android-only: `CallWire`, `Hkdf`, `KeySlots`. Word list `bip39_english.txt` vs `english.txt`. |
| CI job display names | Pattern "component / action" (`auth-core / …`, `ios-sdk / …`) broken by "containers / build and health check", "ios demo app / build", "android demo app / debug APK", "demo bank / access control", "android-sdk call state machine against Auth Core (signalling only)" (no slash). Job ids are kebab-case and consistent. |
| Env variable prefixes | Auth Core: unprefixed (`DATABASE_URL`, `HSM_ADAPTER`, `PKCS11_*`). Sandbox: `SANDBOX_*`. Tests: `INTEGRATION_*`, `SOFTHSM2_*`, `PLAYWRIGHT_MODULE`. Tooling: `NEXUS_SIGN_SMOKE_*` (ci.yml:286-288) vs `NEXUS_CALL_CONFORMANCE` / `NEXUS_CALL_CONFORMANCE_CMD` (ci.yml:190; `CallConformanceTest.kt:40`). That is two different product prefixes. |
| Error codes | Domain codes UPPER_SNAKE (`OFFLINE_LIMIT_EXCEEDED`, `CREDENTIAL_NOT_ATTESTED`). OAuth errors lower_snake (`invalid_client`, `invalid_request`). The non-OAuth throttle `too_many_attempts` (`bruteForceProtection.ts:39`) is lower_snake, used also for admin login. |
| Event names | Webhooks `dot.lower_snake` (`authorization.offline_provisional`, `authorization.bank_transaction.commit_requested`, which is three-level unlike the rest). Audit events `lower_snake` (`authorization_expired`, `bank_certificate_mismatch`). Push data event UPPER_SNAKE (`pushService.ts:173` `event: 'DEVICE_REPLACED'`). |
| Product name in code | `NEXUSSign` (Swift/Kotlin types), `nexussign` (package), `nexus-sign` (artifacts/images), `NEXUS-SIGN` (prose). Consistent per context. |

---

## Prioritized action list

### (a) Factual, safety and assurance problems: fix first

1. **Remove or correct the "verified on devices" statements** (C21–C24: `recovery-protocol-v2.md:254`, `adr/0005:30`, `adr/0011:30`, `attestation.md:124`). They contradict `DEVICE_ACCEPTANCE_CHECKLIST.md:3,97`, and an auditor will read them as test evidence. Same for `README.md:101` (C9): qualify it as design intent pending device acceptance.
2. **Resolve who operates Auth Core and owns the evidence key ceremony** (X1: `README.md:50` vs `pilot-execution-pack.md` §9). This decides the bank's contract and audit scope.
3. **Fix the offline-confirmation claim at `README.md:48`** (C6): state that the v1 code is an HMAC under a server-held key and that v2 is provisional until the device signature arrives. Correct `README.md:47` (C5; the recovery access token exists).
4. **Rewrite `docs/operations/release.md` §"Verified" and §CI** (C12–C18, C20): it is stale (lockfile, 39 routes, 88 and 30/34 tests, migrations 013–018 only) and lists 7 of 14 CI jobs. Attach logs or CI run links for every number, or remove the numbers. Make `check-repository.sh` actually check the CHANGELOG/VERSION entry, or drop that claim at `:74`. Update `DECISION_LOG.md` D-002.
5. **Make CI fail on silently skipped security suites** (G1): assert that SoftHSM ≥2.7 is installed (or build it), and fail `test:integration` when any `[H]` suite is skipped (e.g. `node --test` with a reporter check or `SKIP_FORBIDDEN=1` in the harness). Otherwise the HSM, evidence-forgery and bank-compromise claims (C2, C25, C26) are not reliably backed by CI.
6. **Version labelling** (C27–C29, X7, X9): either bump `VERSION` (for example to `2.0.0-rc.3`) for the post-rc.2 work, or replace "Status: 2.0.0" / "New in 2.0.0" with "Unreleased". This touches `payment-state-machine.md:3`, `bank-trust-boundary.md:3`, `pilot-execution-pack.md:3`, `bank-credential-trust-v1.md:3`, `configuration.md:98-106`, `android-sdk/README.md:47,79,145`, `ios-sdk/README.md:41,76,165`, `evidence-format.md:221`, `bank-backend-guide.md:267`, `threat-model.md:3,156-157` and `adr/0003:32`.
7. **Add tests for `appAttestService.ts` and `playIntegrityService.ts`** (at least with recorded or synthetic tokens), or state this gap in `threat-model.md` residual risks.
8. **Write the missing documents an auditor will ask for:** NEXUS ID specification, Known Limitations (consolidated from `threat-model.md:152`, `release.md:27-46` and `THIRD_PARTY_MEDIA.md`), a data-flow and perimeter inventory (§5), and a production configuration template with all 86 keys. Add the 14 missing keys to `.env.example` or mark them explicitly.
9. **Release engineering:** health-check the Auth Core image in `container-images`; digest-pin base images and the compose `caddy:2`; add `distributionSha256Sum`, Gradle dependency verification and a committed `Package.resolved`; add a licence check; add CodeQL for Kotlin, Swift and Python; Trivy-scan the sandbox image; build with `npm ci --ignore-scripts && npm rebuild pkcs11js` in the Dockerfile; make `release.yml` depend on green CI, check tag == `VERSION`, and publish to a registry or GitHub Release; extend Dependabot to `android-sdk-calls`, `ios-sdk-calls` and `demo/android`.
10. **Fix the outdated diagrams:** `data-model.md:91-102` (add the OFFLINE_* states). Redraw `README.md:9-33` with Auth Core named and a bank-side boundary before "Bank Commit → Core Banking".

### (b) Editorial consistency

1. Remove empty-citation residue (§4 list, 11 locations) and the empty D-001 entry (`DECISION_LOG.md:5-7`).
2. Replace internal "phase N" and "G4" jargon (16 locations, §4) with release or ADR references. Move dated diary sections out of `KEY_MANAGEMENT.md` into DECISION_LOG.
3. Pick one term per concept and add it to `glossary.md`: device credential (vs device key and key slot); "confirmation" for the customer act, keeping "approval" for admin four-eyes and bank key approval; evidence record (drop "authorization record"); evidence key (drop sealing key and seal key); bank client (drop tenant).
4. Deduplicate: keep the responsibility split in `overview.md` only and link to it from README; keep the gateway mTLS explanation in `deployment.md` only; keep the account-first display rule in the protocol document only.
5. Add the 14 unindexed documents to `docs/README.md`, and `verification-result-v1.md` to `docs/protocol/README.md`.
6. Split the paragraph at `bank-backend-guide.md:328`. Replace the README tagline at `README.md:3` and the heading at `:39`.
7. Naming: CI display names ("component / action"); env prefix `NEXUS_SIGN_*` for all tooling variables; `WebRtcCallEngine.kt` → `WebRTCCallEngine.kt` (or the reverse); `.gitattributes` `*.bat eol=crlf`; delete or document `auth-core/scripts/verify-baseline.sh`; remove the owner's environment line `NATIVE_BUILD_GUIDE.md:49`.

**Rename impact (every file that must change):**

| Rename | Files that reference it |
|---|---|
| `docs/engineering/DECISION_LOG.md` → `decision-log.md` | `android-sdk-calls/build.gradle.kts`, `docs/engineering/THIRD_PARTY_MEDIA.md`, `ios-sdk-calls/Package.swift` |
| `docs/engineering/DEVICE_ACCEPTANCE_CHECKLIST.md` → `device-acceptance-checklist.md` | `android-sdk-calls/README.md`, `docs/adr/0017-in-app-audio-video-calls.md`, `docs/engineering/THIRD_PARTY_MEDIA.md`, `docs/protocol/authorization-protocol-v1.md`, `ios-sdk-calls/README.md` |
| `docs/engineering/KEY_MANAGEMENT.md` → `key-management.md` | `CHANGELOG.md`, `auth-core/src/cli/masterKeys.ts`, `auth-core/src/crypto/masterKeyVault.ts`, `auth-core/src/services/authorizationConfirmation.ts`, `docs/engineering/DECISION_LOG.md`, `docs/operations/configuration.md`, `docs/operations/runbooks/key-rotation.md`, `docs/operations/upgrade-2.0.md`, `docs/security/hsm-key-management.md`, `docs/security/offline-confirmation-threat-model.md` |
| `docs/engineering/NATIVE_BUILD_GUIDE.md` → `native-build-guide.md` | `docs/engineering/THIRD_PARTY_MEDIA.md` |
| `docs/engineering/THIRD_PARTY_MEDIA.md` → `third-party-media.md` | `CHANGELOG.md`, `android-sdk-calls/README.md`, `android-sdk-calls/build.gradle.kts`, `android-sdk-calls/src/main/kotlin/com/nexis/nexussign/calls/WebRtcCallEngine.kt`, `docs/adr/0017-in-app-audio-video-calls.md`, `docs/engineering/DECISION_LOG.md`, `ios-sdk-calls/Package.swift`, `ios-sdk-calls/README.md`, `ios-sdk-calls/Sources/NEXUSSignCalls/WebRTCCallEngine.swift` |
| `android-sdk-calls/.../WebRtcCallEngine.kt` → `WebRTCCallEngine.kt` (and class) | `android-sdk-calls/src/main/kotlin/com/nexis/nexussign/calls/VerificationCallSession.kt`, the file itself |
| `ios-sdk/.../Resources/english.txt` → `bip39_english.txt` | `ios-sdk/Package.swift`, `ios-sdk/Sources/NEXUSSign/RecoveryPhrase.swift` (resource lookup) |
| `ios-sdk/Tests/NEXUSSignTests/ConfigurationTests.swift` → `NEXUSSignConfigTests.swift` | the file only |
| Env `NEXUS_CALL_CONFORMANCE[_CMD]` → `NEXUS_SIGN_CALL_CONFORMANCE[_CMD]` | `.github/workflows/ci.yml:190`, `auth-core/test/media/sdk-call-conformance.test.mjs`, `android-sdk/src/test/kotlin/com/nexis/nexussign/CallConformanceTest.kt` |
