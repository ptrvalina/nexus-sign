# Security findings register

All findings of the internal security review of branch `engineering/production-readiness`, classified by risk and by the OWASP ASVS 4.0 / MASVS 2.0 control group they belong to, with their status and the release decision. Rule of the readiness directive: an open **Critical** or **High** blocks a release; an open **Medium** needs a documented decision. Details of each finding are in the [area reports](security-review/README.md) and the [assessment report](SECURITY_ASSESSMENT_REPORT.md).

This is an **internal review**, not an external penetration test. No external test has been done.

## Summary

| Severity | Found | Fixed | Open | Release effect |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | — |
| High | 4 | 4 | 0 | None open |
| Medium | 16 | 15 | 1 (D-01) | Documented decision below |
| Low | 44 | 6 | 38 | Listed in the area reports; none blocks a pilot alone |
| Info | 19 | 0 | 19 | — |

The third cycle (this directive) closed D-02 and D-07 in code, and found and fixed or recorded six new items (N-01 to N-06). "Fixed" means fixed in code and covered by a test that ran here, unless the row says the test could not run.

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

## New items from this cycle

| ID | Item | Sev. | ASVS / MASVS | Status |
|---|---|---|---|---|
| N-01 | The OpenAPI route check did not parse the document; an invalid YAML passed | Low | ASVS V14 | Fixed: `validate-openapi.py` in CI, negative-tested |
| N-02 | Image user was a name, so Kubernetes could not verify `runAsNonRoot` | Low | ASVS V14 | Fixed: numeric user 10001, checked by `check-manifests.py` |
| N-03 | `CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS` missing from the configuration reference and `.env.example` | Low | ASVS V14 | Fixed |
| N-04 | Confirmation counter increments inside the transaction (a rolled-back transaction is counted) | Info | — | Accepted, documented in monitoring |
| N-05 | Audit export cursor depends on transaction start times; late commits can be skipped without a lag | Info | ASVS V7 | Mitigated: `--lag-seconds`, documented |
| N-06 | Customer calls are not sealed in the evidence chain | Info | ASVS V7 | By design: calls authorize nothing; the call row is immutable once ended |

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
