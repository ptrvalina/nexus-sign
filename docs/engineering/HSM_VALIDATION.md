# HSM validation

What has been shown about the HSM integration of Auth Core and the bank execution boundary, with the run that shows it. Statuses: PASS (a real test passed), FAIL, PARTIAL, NOT RUN, BLOCKED (infrastructure or access missing).

**SoftHSM is not the bank's HSM.** Every PASS below is on SoftHSM 2.7.0. Nothing here has run on a vendor HSM; the [HSM acceptance procedure](../operations/hsm-acceptance.md) lists what only the bank's HSM can answer.

## Environment of the runs

| | |
|---|---|
| Tool | GitHub Actions job `auth-core / integration (PostgreSQL, Redis, SoftHSM)`, `ubuntu-24.04`, Node 22, PostgreSQL 16 (`postgres:16-alpine`), Redis 7 (`redis:7-alpine`) |
| SoftHSM | 2.7.0 built from the upstream tag, commit pinned (`13e6e86b…`), OpenSSL backend, GOST off ([`ci.yml`](../../.github/workflows/ci.yml)) |
| Command | `REQUIRE_ALL_INTEGRATION_SUITES=1 npm run test:integration` (a suite that cannot run fails the job instead of skipping) |
| Runs | First complete run: run `43932489275`, job `133529146913`, commit `b0ae83b`, 2026-11-16 (349 tests, 0 failed, 0 skipped). Repeated on every later push; the latest is in [CI validation](CI_VALIDATION.md) |
| Log | The job log in GitHub Actions for the run above |

Earlier runs failed for a reason in CI, not in the product: Ubuntu 24.04 packages SoftHSM 2.6.1, which has no `CKM_ECDSA_SHA256` (run `43929146935`: all 8 suites "cannot run"). Documents of earlier cycles that said "CI runs the suites on SoftHSM 2.7" were wrong at the time; since commit `52b5036` CI builds 2.7.0.

## The eight HSM suites

| # | Suite (file) | Tests | Status | What it shows |
|---|---|---|---|---|
| 1 | PKCS#11 adapter (`hsm.test.mjs`) | 10 | PASS | Evidence sealed with the token key and verified with the published key; device signature verification (valid, wrong data, wrong key, malformed); 100 parallel seals; two keys with one label refused; extractable or non-sensitive key refused; unknown token refused; hung operation times out without blocking others; lost session reopened and retried once; fail-fast when all sessions are stuck; re-initialisation keeps the pool |
| 2 | HSM-wrapped master keys (`master-key-hsm.test.mjs`) | 11 | PASS | AES-GCM KEK wraps the three master keys; a database and configuration copy does not open secrets; interrupted master-key rotation completes; KEK rotation re-wraps; **startup refused** with no module, a wrong PIN, no KEK, a KEK that may not decrypt, an imported KEK, plaintext keys next to `MASTER_KEY_SOURCE=hsm`, and no key material in the log |
| 3 | Forged evidence with a valid seal (`evidence-forgery-hsm.test.mjs`) | 13 | PASS | A genuine seal over wrong content (other key, altered terms, re-pointed record, other device, stale enrolment, missing field, wrong method, wrong chain position) is refused by the commit and the verifier; concurrent commits give one commit |
| 4 | Evidence metadata binding (`evidence-metadata-binding.test.mjs`) | 13 | PASS | Changing any row column the seal does not cover is detected; parallel commits on altered records all refused |
| 5 | A compromised Auth Core cannot make the bank execute (`bank-trust-compromise.test.mjs`) | 11 | PASS | Credential enrolled by Auth Core alone, substituted key, unsigned or altered approval, bank revocation ignored by Auth Core, unpinned evidence key, changed chain head, other terms: all refused by the bank side |
| 6 | Bank execution boundary (`bank-execution-boundary.test.mjs`) | 25 | PASS | Positive case executes once; every Auth Core lie above is refused; registry or Auth Core down → held, not executed; parallel requests → one execution; replayed old evidence refused; revocation races; reconciliation without double execution |
| 7 | Execution boundary across processes (`bank-execution-processes.test.mjs`) | 20 | PASS | Separate processes with mutual TLS; state machine enforced by the database for every role; process killed after the provider executed → reconciled, one transfer; stress 40 requests / 4 instances → one transfer per payment |
| 8 | HSM in-place decryption (`hsm-in-place-decryption.test.mjs`) | 3 | PASS (capability check) | The stored format decrypts inside the HSM; wrong associated data refused; `C_UnwrapKey` with `CKM_AES_GCM` is not available on SoftHSM (documented migration path) |
| | **Total** | **106** | **8/8 PASS** | |

## The directive's checklist

| Property | Status | Evidence |
|---|---|---|
| PKCS#11 | PASS (SoftHSM) | Suite 1 |
| AES-GCM | PASS (SoftHSM) | Suites 2, 8 |
| KEK, wrapped master keys | PASS (SoftHSM) | Suite 2 |
| Key rotation | PASS (SoftHSM) | Suite 2; `key-rotation`, `key-rotation-interrupted` (HTTP suites, same run) |
| Key separation | PASS (SoftHSM) | Suite 2 (a wrapped key for another purpose does not unwrap); suite 1 (evidence key unique, non-extractable, sensitive) |
| Key access controls | PARTIAL | Wrong PIN and non-decrypting KEK refused (suite 2); HSM-side roles, partitions and per-application ACLs exist only on a vendor HSM — BLOCKED |
| Failure handling, timeout, fail-closed | PASS (SoftHSM + stalling module double) | Suite 1 (timeout, lost session, fail-fast); suite 2 (startup refused); unit `hsm-worker-host` 6, `pkcs11-adapter-deadline` 3 |
| No silent fallback to an insecure mode | PASS | Suite 2 (no module, wrong PIN, missing KEK: startup refused); unit test "the software HSM adapter is available for development with ALLOW_INSECURE_DEVELOPMENT" and the production posture suite (`production-startup` 3): production refuses the software adapter |
| Audit logging of HSM failures | PARTIAL | Startup failures logged without key material (suite 2); metrics `nexus_hsm_breaker_state`, `nexus_hsm_in_flight`; the HSM's own audit log is the vendor's — BLOCKED |
| Recovery after restart | PASS (SoftHSM) | Suite 2 (rotation across restarts); suite 7 (process killed and restarted) |
| Cryptographic integrity | PASS | Suites 3, 4, 5 |
| The bank does not trust Auth Core's HMAC or answer alone | PASS | Suites 5, 6, 7: the bank side verifies the device signature itself (in-database ECDSA P-256, `bank-p256` 3), against keys it approved with its own trust key, and pins the evidence keys; a fully compromised Auth Core obtains no execution |
| Vendor HSM: concurrent logins, session limits, cluster failover, attribute policy, FIPS mode, latency | BLOCKED | Needs the bank's HSM test partition; procedure: [HSM acceptance](../operations/hsm-acceptance.md) |

## How to reproduce

```sh
# SoftHSM 2.7.0 (the Ubuntu 24.04 package 2.6.1 lacks CKM_ECDSA_SHA256)
git clone --depth 1 --branch 2.7.0 https://github.com/softhsm/SoftHSMv2 && cd SoftHSMv2
sh autogen.sh && ./configure --prefix=/opt/softhsm --with-crypto-backend=openssl --disable-gost && make -j && sudo make install
cd auth-core && npm ci && npm rebuild pkcs11js && npm run build
INTEGRATION_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
INTEGRATION_REDIS_URL=redis://localhost:6379 \
SOFTHSM2_MODULE=/opt/softhsm/lib/softhsm/libsofthsm2.so SOFTHSM2_UTIL=/opt/softhsm/bin/softhsm2-util \
REQUIRE_ALL_INTEGRATION_SUITES=1 npm run test:integration
```

## Not verified

The bank's HSM model and vendor module, an HSM cluster, network partitions between Auth Core and a network HSM, FIPS/approved-mode restrictions (caller-supplied GCM IV), HSM-side audit, and production latency. Status: **BLOCKED** until the bank provides an HSM test partition.
