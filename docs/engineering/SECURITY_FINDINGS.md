# Security findings

All findings of the internal security review of branch `engineering/production-readiness`, classified by risk and by the OWASP ASVS 4.0 / MASVS 2.0 control group they belong to, with their status and the release decision. Rule of the readiness directive: an open **Critical** or **High** blocks a release; an open **Medium** needs a documented decision. Details of each finding are in the [area reports](security-review/README.md) and the [assessment report](SECURITY_ASSESSMENT_REPORT.md).

This is an **internal review**, not an external penetration test. No external test has been done.

## Summary

| Severity | Found | Fixed | Open | Release effect |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | — |
| High | 5 | 5 | 0 | None open |
| Medium | 19 | 18 (N-13 in code; its iOS test not yet run) | 1 (D-01) | Documented decision below |
| Low | 46 | 8 | 38 | Listed in the area reports; none blocks a pilot alone |
| Info | 20 | 0 | 20 | — |

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
| D-01 | iOS: offline ECDH secret usable by the app process | Medium | MASVS-CRYPTO, MASVS-STORAGE | **Open — decision below** | — |

## Decision on D-01 (Medium, open)

**Decision: accepted for a controlled pilot with conditions; not accepted for production.**

- Why the risk is bounded: production refuses offline v1 (`OFFLINE_CONFIRMATION_MODE=immediate`) at startup; with v2 a code alone leaves an authorization `OFFLINE_PROVISIONAL`, which cannot be committed. Only the device signature with the biometric-bound key makes it `VERIFIED`, and the bank database verifies that signature itself. An attacker needs code execution inside the bank app process first.
- Conditions: the bank never treats `OFFLINE_PROVISIONAL` as paid; offline confirmation stays off (`OFFLINE_CONFIRMATION_ENABLED=false`, as in the Kubernetes ConfigMap) unless the bank needs it; the iOS limitation is stated to the bank ([iOS README](../../ios-sdk/README.md)).
- Closure: per-authorization server ephemeral key in the offline QR (protocol change in Auth Core, both SDKs and the vectors), verified on a device. Owner: engineering; before production.

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
| N-13 | The iOS SDK checked mandate terms less strictly than the Android SDK: it accepted non-canonical bytes, missing or unexpected fields, an unknown frequency, a non-integer limit, a total below the per-payment limit and a validity ending before it starts (7 of the 17 invalid shared vectors). An unexpected field is signed without being shown, the class of D-02. The iOS copy of the vectors was not even a test resource | Medium | MASVS-PLATFORM, ASVS V5 | Fixed in code (`f8cbc11`): `MandateTermsParser` in Swift mirrors Kotlin. **Test not yet run**: the `ios-sdk` CI job got no macOS runner | `MandateTermsVectorsTests` (3 valid, 17 invalid), pending |
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
