# Security testing guide

How to run every security-relevant test of NEXUS-SIGN, what each needs, what it proves, and what has to be tested outside the repository. Results of the last run are in the [final engineering report](FINAL_ENGINEERING_REPORT.md); open findings in the [findings register](SECURITY_FINDINGS.md).

## 1. Environments

| Level | Needs | Runs |
|---|---|---|
| L0 Static | Node 22, Python 3 with PyYAML and jsonschema | Repository hygiene, OpenAPI route and structure checks, Kubernetes manifest checks, shared vector checks |
| L1 Unit | L0 + `npm ci` in `auth-core` (OpenSSL on the path) | Unit tests, protocol vectors, attestation checks |
| L2 Service | L1 + PostgreSQL 16 and Redis 7 (`INTEGRATION_DATABASE_URL`, `INTEGRATION_REDIS_URL`) | Integration suites at service and database level, bank database functions, backup/restore |
| L3 HTTP | L2 with the full `node_modules` (`express`, `ioredis`, `prom-client`) | HTTP integration suites (routes, gateway, mTLS, rate of nonces, production startup) |
| L4 HSM | L3 + SoftHSM 2.7 (`SOFTHSM2_MODULE`, `SOFTHSM2_UTIL`) | The eight HSM suites; on a bank HSM see the [HSM acceptance procedure](../operations/hsm-acceptance.md) |
| L5 Browser | L3 + Playwright with Chromium (`PLAYWRIGHT_MODULE`) | Real WebRTC calls between browsers, console screens |
| L6 SDK | Xcode 15+ (iOS), JDK 17 + Android SDK (Android) | SDK unit tests and builds; the Kotlin core alone runs on any JDK (`android-sdk/scripts/jvm-core-tests.sh`) |
| L7 Device | Real iPhones and Android phones | [Device acceptance checklist](DEVICE_ACCEPTANCE_CHECKLIST.md), [biometric procedure](../architecture/biometric-behaviour.md#device-test-procedure-both-platforms) |
| L8 External | Independent testers | Penetration test, cryptographic review, load and resilience tests |

CI runs L0 to L6 (`.github/workflows/ci.yml`) with `REQUIRE_ALL_INTEGRATION_SUITES=1`, so a suite that cannot run fails the job instead of skipping.

## 2. Commands

```sh
# L0
bash auth-core/scripts/check-repository.sh
(cd auth-core && node scripts/check-openapi-routes.mjs && python3 scripts/validate-openapi.py openapi.yaml)
python3 deploy/kubernetes/check-manifests.py
(cd auth-core && npm run test:vectors)

# L1
(cd auth-core && npm test)

# L2 / L3 / L4
export INTEGRATION_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres INTEGRATION_REDIS_URL=redis://127.0.0.1:6379/1
(cd auth-core && REQUIRE_ALL_INTEGRATION_SUITES=1 node --test --test-concurrency=1 test/integration/*.test.mjs)

# L5
(cd auth-core && PLAYWRIGHT_MODULE=$(npm root -g)/playwright node --test test/media/*.test.mjs)

# L6
android-sdk/scripts/jvm-core-tests.sh           # Kotlin core on the JVM
(cd android-sdk && ./gradlew test assembleRelease)
(cd ios-sdk && swift test)                      # or xcodebuild test

# Sandbox and demo bank
(cd sandbox && python3 -m unittest discover -s tests)
node --test demo/bank-backend/test/*.test.mjs
```

## 3. What the tests prove, by security property

| Property | Tests | Level |
|---|---|---|
| Signed bytes = displayed text; any change breaks the signature | `test:vectors` (TS), `SignedTransactionTest` (Kotlin), `SignedTransactionTests` (Swift), sandbox `test_protocol.py`, property and fuzz unit tests, `bank-p256` | L1, L2, L6 |
| Display rules, look-alikes, D-02 layout | Signed-payload and mandate vectors (invalid sets), `display-rules` (HTTP) | L1, L3, L6 |
| Device request authentication, nonces, replay | `device-protocols-v1` vectors, `nonce-store`, `invariants` | L1, L3 |
| Attestation | `attestation-parsers` (test chains, not device tokens), `attestation-policy` | L1, L3 |
| Bank-side independent authorization | `bank-db-authorization`, `bank-db-mandates`, `bank-trust-compromise`, `bank-execution-*` | L2, L4 |
| Evidence completeness and integrity | `evidence-outcomes`, `mandates`, `evidence-forgery-hsm`, `evidence-metadata-binding`, `backup-restore`, `scripts/verify-evidence.mjs` | L2, L4 |
| Access control and scope | `bank-console`, `conversations`, `customer-calls`, `customer-account`, `admin-audit-mtls` | L2, L3 |
| Device replacement and several devices | `device-replacement-hold`, `multiple-devices` (including concurrent writers) | L2 |
| HSM isolation and failure | `hsm-worker-host`, `pkcs11-adapter-deadline`, `hsm`, `master-key-hsm` | L1, L4 |
| Fail-closed production configuration | `production-startup`, `check-manifests.py` | L0, L3 |
| Database rules (append-only, lifecycle, roles) | `migrations`, `db-roles`, `authorization-insert-state`, trigger assertions in most L2 suites | L2, L3 |
| Calls and signalling | `customer-calls` (real Redis Lua), `verification-call`, `test/media/*` | L2, L3, L5 |

## 4. Manual and external tests

| Test | Who | Reference |
|---|---|---|
| Device acceptance on iPhone (Face ID and Touch ID) and Android (with and without StrongBox) | Bank QA with engineering | Device checklist; biometric procedure |
| D-02 on a device: prompt layout with long names, every label set the bank uses | Bank QA | Protocol, confirmation text |
| Bank HSM acceptance | Bank HSM team | HSM acceptance procedure |
| Penetration test: OWASP ASVS L2 for Auth Core and the console, MASVS L2 + R for the SDKs inside the bank app, the gateway configuration | Independent firm | Scope: everything in [security architecture](SECURITY_ARCHITECTURE.md) |
| Cryptographic review of the protocols and the PL/pgSQL verifier | Independent reviewer | [Cryptographic architecture](CRYPTOGRAPHIC_ARCHITECTURE.md) |
| Load and resilience: confirmation latency, HSM breaker under load, Redis and PostgreSQL failover | Bank with engineering | [Monitoring](../operations/monitoring.md) alerts |

## 5. Rules for test results

- A skipped suite is not a pass. Report it as not run, with the reason.
- SoftHSM results are not bank HSM results. Test certificates and verdicts made by the tests are not device tokens.
- Results from an internal review are not a penetration test.
- Record the commit, environment and command of every result.
