# Bank HSM acceptance procedure

SoftHSM2 is a software token used to test the PKCS#11 code paths. It is **not** a bank HSM: it has no tamper protection, no certified key storage, no vendor session limits, no cluster failover and none of a vendor's quirks in `C_Login`, `C_FindObjects` or key attributes. Before a pilot, the bank runs this procedure on the HSM model and firmware it will use, with its HSM team present, and records the results.

## Status on this branch

| Environment | What ran |
|---|---|
| Review environment | None of the eight SoftHSM suites: SoftHSM2 cannot be installed there (no package network). The worker-thread host ran against a PKCS#11 double that stalls (`hsm-worker-host.test.mjs`, unit) |
| CI (`auth-core / integration`) | The eight suites on SoftHSM 2.7 with `REQUIRE_ALL_INTEGRATION_SUITES=1`, so a missing SoftHSM fails the job. Not yet run on this branch (nothing pushed) |
| A bank HSM | Never |

## The eight suites and what they prove

| Suite | Proves | Vendor-specific risk it does not cover |
|---|---|---|
| `hsm.test.mjs` | Evidence seals with the token key verify with the published key; customer signatures verify; 100 parallel seals; two keys with one label refused; an extractable or non-sensitive key refused; unknown token refused; a hung operation times out without blocking others; a lost session is reopened once; fail-fast when all sessions are stuck; re-initialisation keeps the pool | Real session limits, latency under load, behaviour after an HSM cluster member fails |
| `master-key-hsm.test.mjs` | Master keys wrapped by an HSM KEK: the service runs with wrapped keys only; a database and configuration copy opens nothing; master key and KEK rotation, also interrupted; wrong purpose, non-decrypting KEK, imported KEK and plaintext keys refused | The vendor's AES-GCM wrap support and attribute policy |
| `hsm-in-place-decryption.test.mjs` | Capability check: decrypting stored secrets inside the HSM and `C_UnwrapKey` with `CKM_AES_GCM` | Whether the vendor supports these mechanisms at all |
| `evidence-forgery-hsm.test.mjs` | A record with a genuine seal but wrong content (other key, altered terms, re-pointed record, stale enrolment, unknown key, missing field, wrong method, wrong position) is refused by the commit and by the offline verifier | — (logic, not the HSM) |
| `evidence-metadata-binding.test.mjs` | Row metadata that disagrees with the sealed payload is refused, also under parallel commits | — |
| `bank-trust-compromise.test.mjs` | A compromised Auth Core cannot make the bank execute: unapproved credentials, substituted keys, forged approvals, unpinned evidence keys, changed chain heads, other terms | — |
| `bank-execution-boundary.test.mjs` | The bank's execution boundary executes once, only for approved, unrevoked, matching, verifiable evidence | — |
| `bank-execution-processes.test.mjs` | The same across processes with mutual TLS and the database state machine | — |

## Procedure on the bank's HSM

Run in a test partition of the production HSM model, never in the production partition, and never with production keys.

### 1. Key ceremony (HSM team, two people)

1. Create a partition (token) labelled for NEXUS-SIGN test, with a crypto-officer PIN for Auth Core.
2. Generate **inside the HSM** an EC P-256 signing key pair, label = `PKCS11_EVIDENCE_KEY_LABEL`, with `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, `CKA_SIGN=true`, `CKA_TOKEN=true`, `CKA_PRIVATE=true`. Record `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE` (Auth Core refuses the key unless all three are true).
3. Generate inside the HSM an AES-256 KEK, label = `PKCS11_KEK_LABEL`, `CKA_WRAP`/`CKA_UNWRAP` or `CKA_ENCRYPT`/`CKA_DECRYPT` as the vendor requires for AES-GCM, non-extractable.
4. Export only the evidence public key; publish it to the bank's verifier (`scripts/bank-trust-statement.mjs`).

### 2. Run the suites against the vendor module

The suites create their own tokens with `softhsm2-util`. On a vendor HSM, create the tokens by hand and point the suites at the vendor module:

```sh
cd auth-core && npm ci && npm run build
export INTEGRATION_DATABASE_URL=postgres://...   INTEGRATION_REDIS_URL=redis://...
export SOFTHSM2_MODULE=/opt/vendor/lib/libvendorpkcs11.so   # the vendor's PKCS#11 library
export SOFTHSM2_UTIL=/path/to/token-setup-wrapper           # a script with softhsm2-util's --init-token/--import interface for the vendor's tool
REQUIRE_ALL_INTEGRATION_SUITES=1 node --test --test-concurrency=1 test/integration/hsm*.test.mjs test/integration/master-key-hsm.test.mjs test/integration/evidence-*-hsm.test.mjs test/integration/evidence-metadata-binding.test.mjs test/integration/bank-*.test.mjs
```

Tests that need SoftHSM-only operations (token initialisation, importing a known key to prove it is refused) need the wrapper or are run by the HSM team by hand with the vendor tool; record which.

### 3. Vendor behaviour Auth Core depends on

| Check | How | Pass |
|---|---|---|
| Login under concurrency | Start three Auth Core instances against the partition; 500 confirmations in 60 s (`scripts/e2e-smoke.mjs` in a loop or the bank's load tool) | No `CKR_USER_ALREADY_LOGGED_IN` or `CKR_SESSION_COUNT` errors; p99 seal latency recorded |
| Session limits | Raise `HSM_SESSION_POOL_SIZE` until the vendor refuses | The refusal is reported at startup, not at the first payment |
| Timeout and breaker | Block the network path to the HSM for 30 s during load (firewall rule) | Calls fail within `HSM_OPERATION_TIMEOUT_MS`; `/readyz` reports the HSM down; `nexus_hsm_breaker_state` = 2; no process restart; after the path returns, the breaker closes and seals resume; `nexus_evidence_unsealed_outcomes` returns to 0 |
| Cluster failover | Fail one HSM cluster member during load | Either no error, or errors only within the timeout, then recovery without a restart |
| Key attributes | `C_GetAttributeValue` on the evidence key and KEK | As in step 1; an imported or extractable key makes Auth Core refuse to start |
| Restart | Restart the HSM appliance (or the partition service) | Auth Core reconnects without a restart (lost session reopened once) |
| Audit | Vendor audit log | Every sign and unwrap by the Auth Core identity is logged; nothing else uses the keys |

### 4. Record

For each step: HSM model, firmware, client library version, partition, date, people present, result, evidence (logs, metric screenshots). A failure in step 3 that leads to a restart loop, a seal without the HSM, or an accepted extractable key blocks the pilot.
