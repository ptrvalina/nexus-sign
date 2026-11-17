# Security findings

All findings of the internal security review of branch `engineering/production-readiness`, classified by risk and by the OWASP ASVS 4.0 / MASVS 2.0 control group they belong to, with their status and the release decision. Rule of the readiness directive: an open **Critical** or **High** blocks a release; an open **Medium** needs a documented decision. Details of each finding are in the [area reports](security-review/README.md) and the [assessment report](SECURITY_ASSESSMENT_REPORT.md).

This is an **internal review**, not an external penetration test. No external test has been done.

## Summary

| Severity | Found | Fixed | Open | Release effect |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | — |
| High | 5 | 5 | 0 | None open |
| Medium | 19 | 19 | 0 | D-01 fixed in code (offline v3), device check pending |
| Low | 46 | 36 | 10 (all accepted, each with its reason) | [Triage of the Low findings](#triage-of-the-low-findings); none blocks a pilot alone |
| Info | 20 | 13 | 7 (accepted or by design) | [Info findings](#info-findings) |

The third cycle closed D-02 and D-07 in code and recorded N-01 to N-06. The fourth cycle (this one) ran every check for real in CI for the first time and found N-07 to N-13 (below), and added the [threat model of ten scenarios](#threat-model-ten-scenarios). "Fixed" means fixed in code and covered by a test that passed in CI, unless the row says otherwise. Since the fourth cycle every test named as evidence in this document has passed in GitHub Actions on branch `engineering/production-readiness` (runs and jobs: [CI validation](CI_VALIDATION.md)); tests marked "(CI)" in earlier cycles' rows have now run.

## Critical, High and Medium (and D-07, Low, fixed with them)

| ID | Finding | Sev. | ASVS / MASVS | Status | Evidence of the fix |
|---|---|---|---|---|---|
| A1-01 | Offline deferred signature blocked by gateway mTLS | High | ASVS V1 Architecture, V13 API | Fixed | Device routes derived from `openapi.yaml` and tested (`gateway-and-webhooks`) |
| A2-01 | Bank backend alone could replace a device (account takeover) | High | ASVS V2 Authentication, V4 Access control; MASVS-AUTH | Fixed | `device-replacement-hold` 6 |
| C-01 | Restored bank journal could execute a payment twice | High | ASVS V11 Business logic | Fixed | SoftHSM suite `bank-execution-boundary` (CI) |
| C-02 | Bank database trusted the gateway's signature claim | High | ASVS V1, V6 Cryptography | Fixed | `bank-p256` 3, `bank-db-authorization` 17 |
| A1-02 | Look-alike scripts and layout tricks in displayed text | Medium | MASVS-PLATFORM, ASVS V5 Validation | Fixed | Vectors in TS, Kotlin, Python |
| A1-03 | Customer could not decline; bank could not withdraw | Medium | ASVS V11 | Fixed | `authorization-decline` 3 |
| A1-04 | Retried identity creation lost the NEXUS ID | Medium | ASVS V11 | Fixed | `identity-create-retry` 3 |
| A2-02 | Recovery revoked silently, phrase stayed valid | Medium | ASVS V2, MASVS-AUTH | Fixed | `recovery-phrase-once` 2 |
| A2-03 | Platform operators decided any bank's calls | Medium | ASVS V4 | Fixed | HTTP suite (CI) |
| B-01 | Blocking PKCS#11 calls | Medium | ASVS V1, V6 | Fixed | `hsm-worker-host` 6 |
| B-02 | Imported evidence key accepted | Medium | ASVS V6 | Fixed | SoftHSM suite `hsm` (CI) |
| B-03 | Baseline CLI could seal with a software key | Medium | ASVS V6 | Fixed | Unit |
| B-04 | Evidence only for verified authorizations | Medium | ASVS V7 Logging | Fixed | `evidence-outcomes` 4 |
| B-05 | Verifier accepted truncated chains | Medium | ASVS V7 | Fixed | Unit |
| C-03 | Execution not time-limited at the bank | Medium | ASVS V11 | Fixed | `bank-db-authorization` |
| C-04 | Unsigned registry statements could block credentials | Medium | ASVS V4, V6 | Fixed | `bank-db-authorization` |
| C-05 | Insert could create a verified row | Medium | ASVS V11 | Fixed (authorizations); credentials caught at runtime | `authorization-insert-state` 4 |
| C-06 | Migrations not reproducible | Medium | ASVS V14 Configuration | Fixed | `migrations` 7, `backup-restore` 4 |
| D-02 | Ambiguous prompt layout (payee name read as an account) | Medium | MASVS-PLATFORM, MASVS-AUTH | **Fixed in code (this cycle)**; device check pending | Labelled prompt, separators reserved, IBAN look-alike refused in Auth Core, Kotlin, Swift, sandbox; vectors (5 + 2 new); Kotlin and TypeScript and Python ran, Swift did not, no device |
| D-07 | iOS kept dead keys after a biometric change | Low | MASVS-AUTH, MASVS-STORAGE | **Fixed in code (this cycle)**; device check pending | `KeyManager.forgetInvalidatedCredential`; [procedure](../architecture/biometric-behaviour.md) |
| D-01 | iOS: offline ECDH secret usable by the app process | Medium | MASVS-CRYPTO, MASVS-STORAGE | **Fixed in code** (`5f2ab00`): offline v3, a key of Auth Core's per authorization in the QR code; device check pending | `offline-per-authorization` (6, incl. a secret taken for one authorization computes no code for another), vectors `offline_v3` (TS, Swift), `DeviceProtocolTests` |

## D-01 (Medium): fixed by offline confirmation v3

**Status: fixed in code and in CI (`5f2ab00`, run `44023147512`); to be confirmed on an iPhone.**

- Before: the iOS Secure Enclave returns the ECDH secret to the app process, and with one key agreed at enrolment that secret computed codes for every later transaction. Code inside the bank app that captured it once could confirm any payment offline.
- Now: the iOS SDK enrols with `offlineKeyAgreement: PER_AUTHORIZATION`. Auth Core generates a fresh P-256 key pair for each authorization when the bank asks for the QR code (`NXS3.` carries its public key) and stores the private key encrypted and bound to the authorization (migration 035). The phone runs the ECDH against that key inside the biometric prompt. A captured secret serves only the authorization the customer was confirming. Android keeps the static agreement, because its HMAC key never leaves the Keystore.
- Unchanged: production refuses offline v1, and every offline code still needs the device signature before the authorization is `VERIFIED` (v2/v3).
- Device check: item F3–F6 of the [device acceptance checklist](DEVICE_ACCEPTANCE_CHECKLIST.md) on an iPhone (the demo app fetches the QR code and shows the code without network).

## New items from the third cycle

| ID | Item | Sev. | ASVS / MASVS | Status |
|---|---|---|---|---|
| N-01 | The OpenAPI route check did not parse the document; an invalid YAML passed | Low | ASVS V14 | Fixed: `validate-openapi.py` in CI, negative-tested |
| N-02 | Image user was a name, so Kubernetes could not verify `runAsNonRoot` | Low | ASVS V14 | Fixed: numeric user 10001, checked by `check-manifests.py` |
| N-03 | `CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS` missing from the configuration reference and `.env.example` | Low | ASVS V14 | Fixed |
| N-04 | Confirmation counter increments inside the transaction (a rolled-back transaction is counted) | Info | — | Accepted, documented in monitoring |
| N-05 | Audit export cursor depends on transaction start times; late commits can be skipped without a lag | Info | ASVS V7 | Mitigated: `--lag-seconds`, documented |
| N-06 | Customer calls are not sealed in the evidence chain | Info | ASVS V7 | By design: calls authorize nothing; the call row is immutable once ended |

## New items from the fourth cycle

| ID | Item | Sev. | ASVS / MASVS | Status | Evidence |
|---|---|---|---|---|---|
| N-07 | The iOS SDK did not compile (a property named with the Swift keyword `operator`); no iOS integration was possible | Medium | MASVS-CODE | Fixed (`78a5280`) | `ios-sdk` CI job; decoding test `AccountModelsTests` |
| N-08 | Race between the operator's decision and the server's closure of a verification call: the call could end with the server's reason instead of the operator's | Low | ASVS V11 | Fixed (`ece80fa`) | `verification-call-closure` 4; WebRTC media job 6/6 |
| N-09 | Two dependencies with high advisories: zod <4.6.6 (memory exhaustion on oversized constrained collections, GHSA-mrhx-c7xc-m3w5) and body-parser <1.20.9 (DoS with a compressed body, GHSA-27r3-jxmh-p828 / CVE-2026-111181). Real exposure is reduced by the gateway's body limit, but both are reachable from the bank API | High | ASVS V14 Dependencies | Fixed (`6bcd0cb`, `497f6cc`) | `npm audit` 0 vulnerabilities; Trivy passed |
| N-10 | Secret scanning stopped at a public credential UUID in the mandate vectors (allowlist incomplete); a real secret committed after it would have failed the same job, so no secret could pass, but the job was red | Low | ASVS V14 | Fixed (`454e542`) | `Dependency audit and secret scan` passed |
| N-11 | The security suites that prove the bank does not trust Auth Core alone (HSM, evidence forgery, bank trust compromise, execution boundary) had never run in CI: Ubuntu's SoftHSM 2.6.1 lacks `CKM_ECDSA_SHA256` | Medium (assurance) | ASVS V1, V6 | Fixed (`52b5036`) | 8/8 suites, 106 tests ([HSM validation](HSM_VALIDATION.md)) |
| N-13 | The iOS SDK checked mandate terms less strictly than the Android SDK: it accepted non-canonical bytes, missing or unexpected fields, an unknown frequency, a non-integer limit, a total below the per-payment limit and a validity ending before it starts (7 of the 17 invalid shared vectors). An unexpected field is signed without being shown, the class of D-02. The iOS copy of the vectors was not even a test resource | Medium | MASVS-PLATFORM, ASVS V5 | Fixed (`f8cbc11`): `MandateTermsParser` in Swift mirrors Kotlin | `MandateTermsVectorsTests` (3 valid, 17 invalid) passed, job `133560765523` |
| N-12 | `getRecoveryAttestationBinding` compares token hashes with `timingSafeEqual` without a length guard | Info | ASVS V6 | Not changed: both values are SHA-256 digests and the column is `NOT NULL`; a mismatch can only be a 32-byte digest | — |

Checked in the fourth-cycle re-audit without a new finding: SQL injection (every query parameterised; the dynamic `WHERE` clauses in `adminService.ts` add placeholders only; the two identifier interpolations in CLIs take a fixed table list and a role name checked against `^[a-z_][a-z0-9_]*$`), command injection (no `child_process` in the service), XSS (every `innerHTML` in the console goes through `escapeHtml`, which also escapes quotes; `badge` restricts class names), weak randomness (no `Math.random`), secret comparison (all MAC, token, code and password comparisons use `timingSafeEqual`), SSRF (outbound requests only to fixed Google and Apple hosts and to webhook URLs checked by `webhookUrlPolicy.ts`), secret logging (no logger call carries a token, secret, PIN or key; HSM startup failures are tested to log no key material), `SECURITY DEFINER` (every `SECURITY DEFINER` function of the bank schema uses one definition, `SECURITY DEFINER SET search_path = pg_catalog, pg_temp`, and no function declares it any other way; `EXECUTE` is revoked from `PUBLIC` by default), Redis keys (every key Auth Core writes has a TTL; call state hashes get theirs from the append script). Dependency, container and code scanning: `npm audit`, Trivy and CodeQL passed in CI. Not covered: an external penetration test, fuzzing of every route, mobile reverse engineering.

## Threat model: ten scenarios

Scope: the attacker fully controls the named component; the question is what they obtain, which control stops them, which test shows it, and what remains. Residual risk is rated by real impact and likelihood in a bank deployment that follows the [deployment guide](../operations/deployment.md). The detailed model is in [threat model](../security/threat-model.md).

| # | Scenario | What the attacker obtains | Controls | Shown by (CI) | Residual risk |
|---|---|---|---|---|---|
| 1 | Compromise of the customer's phone | Malware as another app: overlays, notification reading. Code inside the bank app process: use of keys while the customer authenticates | Keys generated and kept in Secure Enclave / StrongBox (TEE fallback), non-exportable, biometric-bound; the confirmation screen is built from the signed bytes; device-signed requests with nonces; platform attestation at enrolment; replacement needs the enrolled device or a hold | Vectors TS/Kotlin/Swift, `nonce-store` 3, `invariants` 10, attestation parsers (unit), `device-replacement-hold` 6 | **Medium**: D-01 (iOS offline secret usable by the app process; production refuses v1, v2 needs the device signature). Code inside the app process or a rooted OS is out of what an SDK can defend. Not tested on a device (BLOCKED) |
| 2 | Compromise of Auth Core | Database, configuration, process memory, use of the HSM through its session | The bank decides by itself: the bank database verifies the device's ECDSA signature over the terms it recorded, against keys it approved with its own trust key, and pins the evidence keys; payments execute once at the bank boundary | `bank-trust-compromise` 11, `bank-execution-boundary` 25, `bank-execution-processes` 20, `bank-p256` 3, `bank-db-authorization` 17 | **Medium**: confidentiality — conversation bodies and payment metadata are readable; availability — Auth Core can refuse service. It cannot cause an execution |
| 3 | Compromise of the bank API client (OAuth credentials) | Calls on behalf of that bank | Token bound to the bank's client certificate at the gateway; tenant isolation in every query; device replacement held until the enrolled device approves or the hold passes, with notification; recovery needs the customer's phrase and the bank's approval of the new key | `bank certificate binding` 4, `invariants` 10, `device-replacement` 5, `device-replacement-hold` 6, `recovery` 10 | **Medium**: with the certificate too, an attacker can create authorizations (the customer still signs) and start a replacement (held, visible). Gateway configuration is the bank's |
| 4 | Compromise of the push channel (provider or bank push contour) | Read, drop, delay, inject notifications | Push content sealed per device; a push only invites the app to fetch the signed request; nothing in a push is shown as payment data | Secure-push vectors (TS, Kotlin, Swift), `customer-account` 7 | **Low**: suppression or delay → the authorization expires (`expiry` 4); a fake push leads only to the app's own screen. The bank's push contour is not tested (BLOCKED) |
| 5 | Compromise of the HSM (or its PIN with HSM access) | Seals with the evidence key; unwrapping the master keys | A seal alone is not enough: the bank checks the device signature and the terms (forged records with a valid seal refused); evidence keys pinned by the bank; KEK non-extractable; startup refused without the HSM | `evidence-forgery-hsm` 13, `evidence-metadata-binding` 13, `master-key-hsm` 11, `hsm` 10 | **High impact, low likelihood**: stored secrets (webhook, offline v1 keys) readable; forged evidence could mislead a dispute review but not cause an execution. HSM access control is the bank's; vendor HSM not tested (BLOCKED) |
| 6 | Replay of a transaction | Re-submitting a signature, request or evidence | Validity window, per-request nonces, single-use authorization, idempotent commit; the bank boundary executes once and refuses old evidence for another payment | `nonce-store` 3, `invariants` 10, `expiry` 4, `state-machine` 9, `bank-execution-boundary` 25 | **Low** |
| 7 | Substitution of payment details | Changing payee, amount, currency or validity between bank, Auth Core and phone | The device signs canonical bytes covering every displayed field; the bank database re-checks terms against its own record; display rules: labelled prompt, look-alike scripts refused, IBAN-like text refused outside the account field | Vectors (8 valid / 59 invalid), `display-rules` 10, `bank-db-authorization` 17, `bank-db-mandates` 5 | **Medium** (business): a customer tricked into approving a genuine but fraudulent payee (APP fraud) is not stopped by cryptography; Verification of Payee is the bank's (F17). Prompt on a device not seen (BLOCKED) |
| 8 | Compromise of a bank staff account in the console | Actions in the console with that account's scope | Password + TOTP (replay refused), bank-scoped accounts, four eyes enforced in the database (the requester cannot approve), cross-origin state changes refused, password reset ends sessions, append-only audit | `admin console` 6, `audit log` 3, `bank-console` 5 | **Low**: a single account cannot revoke or reactivate alone; it can see its bank's data |
| 9 | Abuse by a bank employee (insider, including a DBA) | Changing records, hiding actions | Database roles: the application role cannot change evidence or audit rows; evidence chain with checkpoints held by the bank; four eyes; operators decide only their bank's calls (A2-03); a call never replaces the signature | `db-roles` 2, `evidence-integrity` 5, `evidence-checkpoints` 3, `audit log` 3, `verification-call` 16 | **Medium**: a database owner can disable triggers; the chain checkpoints detect rewritten history but not the reading of data |
| 10 | Infrastructure unavailability (HSM, PostgreSQL, Redis, Auth Core, network) | — | HSM: per-call deadline, breaker, readiness down, startup refused; bank boundary holds payments while Auth Core or the registry is down and executes once afterwards; offline confirmation v2 for the phone; runbooks | `hsm` 10, `master-key-hsm` 11, `bank-execution-boundary` 25, `offline-*` (5 suites), `backup-restore` 4 | **Medium**: no high-availability, failover or load test has run (BLOCKED: bank environment) |

## Triage of the Low findings

Every Low finding of the area reports was rechecked against the code in the fourth cycle. Six had already been fixed in earlier cycles without the register saying so for all of them (D-03: NFKC and digit rules and IBAN check digits 02–98 in Auth Core, Kotlin and Swift; D-04: `operation_type` gets the full display rules on all three; D-07; N-01 to N-03). Nine were fixed in this cycle, each with a test that fails without the fix:

| ID | Fix | Commit | Test |
|---|---|---|---|
| A1-08 | A failed `ROLLBACK` keeps the original error and destroys the connection | `adfe7e3` | `low-findings` (unit) |
| A2-04 | The 10-failures-per-identity recovery limit applies to every attempt, under the identity lock | `6226128` | `recovery-phrase-once` (3 sessions, 10 failures, then the right phrase is locked out) |
| A2-05 | Webhook SSRF filter: 6to4 judged by its IPv4; Teredo, local NAT64, discard, benchmarking, ORCHIDv2 refused | `f37216a` | `gateway-and-webhooks` (unit) |
| A2-07 | `admin_logout` names the account and its bank (the console reads were already audited) | `b65b37b` | `admin console` (HTTP suite) |
| B-07 | The independent verifier refuses device keys other than ECDSA P-256 | `2d705f6` | `evidence` (unit: P-384, RSA, Ed25519) |
| B-12 | ADR 0004 names the real sealing functions; removal of the newest records is detected only against a kept head | `a864ca7` | — (documentation) |
| C-11 | Live device nonces cannot be deleted, by any role (migration 031); `UPDATE` revoked from the application role | `cb77ab6` | `device-nonce-guard` (new suite, real `roles.sql`) |
| D-05 | iOS compares the response with the signed bytes by UTF-16 code units, not canonical equivalence | `3be0953` | `SignedTransactionTests` |
| D-10 | Android splits recovery phrases on Unicode White_Space, like iOS | `3be0953` | `RecoveryPhraseTest`, `RecoveryProtocolTests` |

After the fourth-cycle package, the planned Lows were worked through on the same branch. Nineteen more were fixed, each with a test that ran in CI:

| ID | Fix | Commit | Test |
|---|---|---|---|
| A2-06 | While the account-wide failure limit is hit, the right password **and** a valid TOTP code still sign in; the password alone is refused with 429 and `Retry-After`. A stranger can no longer lock a named admin out | `8b0e845` | `admin console` (HTTP suite): locked account, valid code signs in, password alone refused |
| A2-10 | The three swallowed errors are logged as security events (`recordSecurityEvent`, level 50) when the audit write itself fails; the OAuth and push-receipt throttle counters no longer hide errors | `f0fa92e` | `low-findings` (unit) |
| A1-05 / B-06 | Device signatures are normalised to low S before they are stored and sealed (authorization, deferred signature, mandate); a resent high-S copy is the same signature | `13e9e0f` | `crypto` (unit), `offline-deferred-signature` (integration) |
| C-07 | Migration 032: `consumed_at` set once on `VERIFIED`, `bank_commit_*` only on the commit transition; audit rows take the server time unless written by the table owner | `3ccb253` | `audit-field-immutability` (new suite, 4) |
| A1-07 | Every path that changes a credential or identity first locks the identity's open authorizations in the order confirmation uses. The deadlock (40P01) was reproduced on the old code | `366a951` | `lock-order` (new suite) |
| B-11 | Auth Core refuses to start in production while unbound legacy webhook ciphertext remains, and warns otherwise; upgrade guide step 7 | `f811411` | `low-findings` (unit) |
| B-09 / C-08 | Migration 033: re-wrapping a secret needs the role `nexus_secret_rotator` (created by `roles.sql`, granted to no login by default); the session setting alone no longer suffices | `f2b7a72` | `secret-rewrap-role` (new suite, 3, real `roles.sql`) |
| B-08 | `reinitialize()` stops new calls, waits until every session is back (bounded by the call deadline, else an error and no `C_Finalize`), then finalizes | `e11eddc` | `pkcs11-adapter-deadline` (2 new). Not observed on a vendor HSM |
| D-08 | The iOS push receipt goes through the session with the configured certificate pins | `95be0c4` | `SecurePushTests.testReceiptsUseThePinnedSession` |
| D-12 | iOS: biometric signing, key agreement and PBKDF2 run on a dedicated queue behind `withCheckedThrowingContinuation`, not on the cooperative pool | `a0bd304` | `BlockingWorkTests` (4, incl. more blocked operations than pool threads while another task runs). Not measured on a device |
| D-15 | iOS README: App Attest entitlement, capability and Auth Core settings for integrators | `fa9e837` | — (documentation) |
| A2-08 | Console route `POST /admin/api/webhook-deliveries/:id/redeliver` (operator role, bank-scoped, audited): a `FAILED` delivery returns to `PENDING` with the same event ID. Secret rotation overlap: migration 034 keeps the replaced secret for `--webhook-overlap-hours` (default 24); deliveries carry `v1=<previous>,v1=<new>`; the reference receiver and the guide accept any matching entry | `e44f415`, `06e2d85` | `admin console` (HTTP suite), `webhook-secret-overlap` (new suite, 4), `low-findings` (unit) |
| B-10 | The verifier binds an export to an expected identity, authorization and bank (`--expect-nexus-id`, `--expect-authorization-id`, `--expect-client-id`); every new record seals the bank's `clientId` | `b2bf43f`, `d950036` | `evidence` (unit), `evidence-outcomes` (integration) |
| C-13 | A REVIEW is settled by two operator logins (request, then confirmation with the same outcome; the requester cannot confirm), kept in `bank.review_requests`; `createOperatorTools({ authCore })` reports the result to Auth Core | `24e0568` | `bank-db-authorization` (2), `bank-execution-processes` (Auth Core state after the resolution) |
| D-14 | Both SDKs end a call whose answer has no DTLS fingerprint (`a=fingerprint`, SHA-256/384/512, RFC 8122) and close the session; relay-only ICE as a bank option (`relayOnly`, TURN URLs only, `iceTransportPolicy = relay`, refused without TURN); a Security job verifies the pinned WebRTC binaries on every run (checksums, Maven PGP signature, stasel tag checksum). **Stays a release blocker:** the owner's provenance and licence decision on the binaries (D-015, TPM-1, TPM-4 to TPM-7) | `e3daad1`, `d974ab1`, `c0fae11` | `VerificationCallControllerTests`, `VerificationCallControllerTest` (fingerprint, relay-only); job `WebRTC binaries` ([evidence](THIRD_PARTY_MEDIA.md#verification-in-ci-2026-11-17-finding-d-14)) |
| D-06 | iOS registration state: one atomic file in Application Support, excluded from backups, per bank; state of earlier builds moved out of `UserDefaults` once | `5f2ab00` | `DurableStateTests` (6) |
| D-11 | iOS and Android error model: dedicated cases (`invalidServerResponse`, `invalidRecoverySession`, `randomGenerationFailed`, `configurationInvalid`, `cryptographicOperationFailed`, `invalidArgument`) instead of `serverError(0/200/400)`; the internal error type is gone. **Integration impact:** a host app's exhaustive `switch` over `NEXUSSignError` needs the new cases | `5f2ab00` | `ErrorModelTests` (3), `RecoveryProtocolTest` |

The 10 that remain, all accepted, with the reason for each. **Accepted** means the behaviour is intended or the control belongs to the bank's infrastructure, and it is documented; **Planned** means a fix is needed before production but not before a controlled pilot.

| ID | Finding (short) | Decision | Reason or plan |
|---|---|---|---|
| A1-06 | Idempotent replay ignores `verificationPolicy`, `expiresInSeconds`, `correlationId`, `pushNotification` | Accepted | Documented in the bank backend guide: a replay returns the original plan, so it cannot weaken it |
| A1-09 | Bank tokens carry no scope | Accepted for the pilot | Tokens are bound to the bank's mTLS certificate; per-endpoint scopes when a bank needs separated backends |
| A1-10 | No rate limiting in Auth Core | Accepted | The bank's gateway rate-limits (deployment guide); per-authorization and login counters exist |
| A2-09 | Provider and TURN secrets in plain environment variables | Accepted for the pilot | Kubernetes secrets; HSM wrapping covers the stored secrets; production posture check to be added |
| C-09 | Boundary role can push a kept head to the maximum (denial of service) | Accepted | The boundary role is the bank's own component; the effect is a refusal, never an execution |
| C-10 | No row-level security; tenant isolation in the application | Accepted for the pilot | Every query is scoped by `client_id` (tested by `security invariants` and console suites); RLS is a defence-in-depth step for multi-bank hosting |
| C-12 | Provider outcomes: no distinct "rejected"; reference provider unauthenticated | Accepted | Reference adapter only; the bank's adapter defines outcomes ([pilot execution pack](../integration/pilot-execution-pack.md)) |
| C-14 | Security state only in Redis (lockouts, sessions) | Accepted | Redis persistence is required in production (deployment guide); a flush logs everyone out and resets counters, it does not grant access |
| D-09 | Secure push has no replay or freshness check | Accepted | A push only invites the app to fetch the signed request; a replayed push shows nothing new |
| D-13 | Android key bytes cleared only in the caller's copy | Accepted | `SecretKeySpec` copies by design; keys live in the Keystore, the copy is short-lived |

## Info findings

| ID | Finding (short) | Status | Evidence or reason |
|---|---|---|---|
| A1-11 | A refused signature or code is HTTP 200 with `status: FAILED` | Documented | Bank backend guide states it prominently; unchanged for 1.x compatibility |
| A1-12 | Bank `GET /v1/authorizations/{id}` spread the whole record | **Fixed** (`c0fae11`) | Explicit view of the contract's fields; offline fields added to `openapi.yaml`; key set pinned in `offline-deferred-signature` |
| A1-13 | No bank field in the signed bytes | Accepted; mitigated | Cross-bank replay impossible (IDs scoped per bank); every evidence record now seals the bank (B-10) |
| A1-14 | Dead `REJECTED` branch, orphan doc comments, redundant per-route gateway middleware, integrity reason in the 403 body | **Fixed** (`d974ab1`) | `error-handler` (unit); the app-wide `requireGatewayMtls` stays |
| A2-11 | DTLS-SRTP rests on the signalling: whoever writes signals could swap fingerprints | **Fixed** (`c0fae11`) | Call code from both fingerprints on the phone and in the console; vectors `call-code-v1.json`; both real WebRTC tests compare the codes |
| A2-12 | No contract for the 41 console routes | **Fixed** (`5455f91`) | `admin-openapi.yaml`; `check-openapi-routes.mjs` compares it with `admin.ts`; validated in CI |
| B-13 | Unsealed metadata in exports | Documented | `evidence-format.md` names the unsealed fields; verifiers rely on the sealed payload |
| B-14 | Evidence key has no domain separation from the health probe | Accepted | The probe signs a hash with no canonical-JSON preimage, so it cannot be used as a seal; a domain prefix belongs to the next evidence schema version |
| B-15 | Canonical JSON follows JavaScript's key order | Documented | `evidence-format.md` states the order and that no sealed object has integer-like keys |
| B-16 | Master keys not zeroized; the development HSM key is per process | **Fixed** (log line) / accepted | The development HSM says at start that earlier seals cannot be verified (`select-hsm-adapter`); master keys in memory documented in KEY_MANAGEMENT |
| C-15 | Trigger functions without a fixed `search_path`; `nexus_app` had TEMP | **Fixed** (`d974ab1`) | Migration 036; `roles.sql` revokes TEMPORARY; `schema-hardening` (3) |
| C-16 | Owner could TRUNCATE the history tables | **Fixed** (`d974ab1`) | TRUNCATE refused on the history tables, even for a superuser (`schema-hardening`) |
| C-17 | Signed operation type not compared when the bank omitted it; stale ADR states | **Fixed** (`5455f91`) | The bank requires and compares `operationType` (`bank-db-authorization`, `bank-trust-compromise`); ADR 0013 notes the removed states. Unused columns kept (dropping them is a migration without benefit) |
| C-18 | No backup scripts; disaster-recovery placeholders | Accepted | Backup and restore with `pg_dump`/`pg_restore` is tested (`backup-restore`, 4); the method, RPO and RTO are the bank's decisions |
| D-16 | Android does not refuse software keys on the device | Accepted | Auth Core decides from the attestation chain; `ALLOW_SOFTWARE` is refused in production. Device check: an emulator must get 403 with production attestation settings |
| D-17 | Orphaned and misplaced doc comments | **Fixed** (`d974ab1`) | — |
| N-04, N-05, N-06, N-12 | See above | Accepted / mitigated | Reasons in their rows |

## Control groups covered by the review

| Group | Covered | Not covered |
|---|---|---|
| ASVS V1 Architecture | Trust boundaries, bank-side independent verification, HSM isolation | External architecture review |
| ASVS V2/V3 Authentication, sessions | Device signatures, admin password + TOTP, cookies | Load-based credential stuffing |
| ASVS V4 Access control | Bank, identity and role scope in every service; four eyes | — |
| ASVS V5 Validation | zod schemas, display rules, canonical parsing | Fuzzing of every route (only payload parsing is fuzzed) |
| ASVS V6 Cryptography | Keys, domains, vectors, HSM attributes | External cryptographic review |
| ASVS V7 Logging | Append-only audit, sealed evidence, SIEM export | — |
| ASVS V8 Data protection | Encrypted secrets at rest, no secrets in logs | Database-level encryption is the bank's |
| ASVS V11 Business logic | State machines in code and database, limits, holds | — |
| ASVS V13 API | Contract, mTLS, rate limits at the gateway | No rate limiting in Auth Core (A1-10, Low) |
| ASVS V14 Configuration | Fail-closed posture, manifests, migrations | Image scanning in a registry |
| MASVS-STORAGE / CRYPTO / AUTH | Keys in hardware, biometric binding, D-01/D-02/D-07 | Nothing verified on a device |
| MASVS-NETWORK | Certificate pinning option, device-signed requests | Not tested on a device |
| MASVS-PLATFORM / CODE / RESILIENCE | Display rules, attestation | Reverse engineering and tampering resistance: not assessed |
