# Security assessment report

Internal security review of NEXUS-SIGN at `2.0.0-rc.2` plus the unreleased changes on branch `engineering/production-readiness`, November 2026. It is not an external penetration test and not a certification; the [release checklist](../operations/release.md) still requires an independent penetration test before production.

## Scope and method

| Area | Covered |
|---|---|
| A1 Authorization core | Authorization creation, canonical bytes, signature verification, confirmation, expiry, idempotency, identity creation |
| A2 Recovery, admin, channels, API | Device replacement, recovery protocol 2, admin console and four-eyes approvals, verification calls, webhooks, OpenAPI contract |
| B Cryptography, HSM, evidence | PKCS#11 adapter, key handling, evidence sealing and verification, master keys |
| C Databases and execution boundary | Auth Core schema and triggers, migrations, the bank database (`bank-integration/`), gateway and payment provider boundary |
| D Mobile SDKs | iOS and Android key handling, parsing and display of signed bytes, offline confirmation, push, pinning |
| E Documentation, CI, tests | Claims against evidence, CI jobs, dependency hygiene, test classification |

Each area was reviewed by reading the code and, where the environment allowed, by running attacks: SQL sessions with the application's and the gateway's database roles against PostgreSQL 16, forged and malformed signatures against the in-database verifier and OpenSSL, and generated display-text cases across the JavaScript, Python and Java rule implementations. The environment had no SoftHSM, no npm, Gradle or Swift toolchains and no phones ([what was run](PRODUCTION_READINESS_REPORT.md#what-was-run)).

## Results

| Severity | Found | Fixed | Partly fixed | Open |
|---|---|---|---|---|
| High | 4 | 4 | 0 | 0 |
| Medium | 16 | 15 | 0 | 1 |
| Low | 44 | 6 | 0 | 38 |
| Info | 19 | 0 | 0 | 19 |

Low and Info findings are listed in the [area reports](security-review/README.md); the open ones that matter for a pilot are in the [known limitations](KNOWN_LIMITATIONS.md).

### High

| ID | Finding | Status | Change |
|---|---|---|---|
| A1-01 | With gateway mTLS on, the phone could not upload the deferred offline signature, so every offline confirmation ended `OFFLINE_UNSIGNED` | Fixed | `56e4fad`; exemptions now tested against `openapi.yaml` |
| A2-01 | The bank backend alone could replace a customer's device and take over any NEXUS ID | Fixed | `d4817d2`: replacement is a request with a hold (default 24 h, production minimum 1 h), approved or cancelled from the enrolled device. Integration impact: 202 `REPLACEMENT_PENDING` |
| C-01 | A bank journal restored from backup could send an already executed payment again | Fixed | `8f33d81`: restore marks; the gateway asks the provider before it submits a marked payment |
| C-02 | The bank database trusted the gateway's statement that the customer's signature was valid | Fixed | `8f33d81`, `a770b4c`: ECDSA P-256 verification inside PostgreSQL (`bank.p256_verify`), tested against OpenSSL on generated valid and corrupted inputs |

### Medium

| ID | Finding | Status | Change |
|---|---|---|---|
| A1-02 | Displayed text allowed look-alike scripts, compatibility characters and layout tricks | Fixed | `4eef752`, `67443c6`: display text rules in Auth Core, both SDKs and the sandbox; 17 new invalid vectors |
| A1-03 | A customer could not decline a payment; the bank could not withdraw one | Fixed | `c18b0f9` |
| A1-04 | A retried identity creation got 409 without the NEXUS ID | Fixed | `d4e60a9`: returns the existing identity (200, `replayed: true`). Integration impact noted in the changelog |
| A2-02 | Recovery revoked the old device silently and left the phrase valid | Fixed | `5c78c61` |
| A2-03 | Platform operators could decide any bank's verification calls | Fixed | `5c78c61` |
| B-01 | Synchronous PKCS#11 calls block the event loop outside the deadline | Fixed | `f7ad5ba`, then `8ee386a`: the PKCS#11 module runs in a worker thread; every call is bounded whatever function it is stuck in, the queue is limited, a circuit breaker opens after consecutive timeouts or a crash and fails closed, a fresh worker is probed after a cooldown, close drains calls in flight. Tested with a stalling module double (`hsm-worker-host`, 6 tests). Residual: master-key unwrapping at startup still runs on the main thread, before traffic; SoftHSM suite not run here |
| B-02 | An imported evidence key was accepted | Fixed | `4a2760b`: `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE` required |
| B-03 | The baseline CLI could seal with a throw-away software key | Fixed | `f93c939` |
| B-04 | Evidence is sealed only for verified authorizations | Fixed | `0768ce3`: declined, rejected, expired, cancelled and offline-unsigned outcomes and every credential revocation are recorded in the transaction that makes them and sealed (`AUTHORIZATION_OUTCOME`, `CREDENTIAL_REVOKED`); payment mandate events are sealed (`MANDATE`, `3e988aa`). The verifier refuses changed and removed records. `evidence-outcomes` (4), `mandates` (8) |
| B-05 | The verifier reported VALID for truncated and empty chains | Fixed | `f93c939` |
| C-03 | Execution was not time-limited in the bank's zone | Fixed | `8f33d81`: execution window (default 1 h) checked in the database |
| C-04 | The registry role could block credentials permanently with unsigned statements | Fixed | `8f33d81`: statements verified with the bank's trust key in the database |
| C-05 | The lifecycle trigger checked updates only; inserts could create a verified, committed row | Fixed for authorizations | `5ba29ec`, migration 024. Credential inserts still unchecked by the database (caught by the runtime integrity check) |
| C-06 | Migrations do not apply to an empty database; upgrade integrity cannot be shown | Fixed | `e4d269c`: baseline, migration ledger with SHA-256 checksums, sequence check, a lock against parallel runs, failure leaves no partial change; fresh install equals `schema.sql`, upgrade from rc.2 tested (`migrations`, 7 tests, rerun with 025–029) |
| D-01 | iOS: the offline secret is usable by the app once it leaves the Secure Enclave | Open — accepted for a controlled pilot with conditions | [Decision](SECURITY_FINDINGS_REGISTER.md#decision-on-d-01-medium-open); protocol fix before production |
| D-02 | Both SDKs: the prompt layout can be ambiguous | Fixed in code (third cycle); device check pending | Labelled prompt, reserved separators, IBAN look-alikes refused in Auth Core, both SDKs and the sandbox; shared vectors |

### Fixed Low findings

D-03 and D-04 (gaps in the display rules, `operation_type` outside them) were fixed with A1-02.

## Second cycle (master completion directive)

Changes made after the first report, each with its own review against the threat model:

| Change | Security property | Verified by |
|---|---|---|
| Several devices per NEXUS ID (`3e8343a`) | A device joins only through a bank request approved by an enrolled device or matured after the hold; the limit is enforced by the database with the identity row locked; a replacement token cannot use an addition request or the reverse | `multiple-devices` (6), including concurrent writers |
| Customer section (`ba3231d`) | Device-signed; only the customer's own data; the security log hides operator names and addresses; relaxing a limit waits for a hold so a stolen unlocked phone cannot raise and use it at once | `customer-account` (7) |
| Payment mandates (`3e988aa`, `2882a8b`) | Own signing domain (`NEXUS-SIGN/MANDATE`), immutable signed terms, debits checked by Auth Core and again by triggers, and by the bank database independently of Auth Core and the gateway (signature, approved key, terms, stop list, period, total) | `mandates` (8), `bank-db-mandates` (5) |
| Conversations (`67caf19`) | Scoped to one NEXUS ID and one bank; operators of other banks and platform operators see nothing; control and bidi characters refused; append-only, hash-chained messages; attachments are references with a SHA-256 | `conversations` (4) |
| CI (`5fbe09a`) | A required suite that cannot run fails CI; the release builds only a tag equal to `VERSION` whose commit passed CI | Checked locally for the skip rule; the workflow change is not run here |

Defects found and fixed during this cycle: a nested template literal in a test helper that kept three SoftHSM suites from loading (`6bc2c61`); an unquoted colon that made `openapi.yaml` unparsable while the route check still passed (fixed before commit in `67caf19`; the route check does not parse YAML, which remains a gap).

Still open: D-01 (iOS offline secret available to the app process), D-02 (prompt layout), D-07 (biometric change differs between platforms), App Attest and Play Integrity tests with recorded tokens, 39 Low and 16 Info findings.

## Found during the final verification

The final test run found that the A2-01 change had broken the test helper `test/integration/support/compromise.mjs` (a nested template literal), so three SoftHSM suites could not load. Fixed in `6bc2c61`; the embedded script was syntax-checked separately. Those suites still skip here for lack of SoftHSM.

## Threat model

The [threat model](../security/threat-model.md) describes release 2.0.0-rc.2. Changes on this branch that alter it:

- Bank backend compromise no longer leads to account takeover by device replacement alone: the attacker must also defeat the hold or the customer's enrolled device (A2-01).
- Gateway compromise no longer lets a forged signature, an unapproved key or an expired authorization through the bank database (C-02, C-03, C-04).
- Restoring the bank database is no longer a path to double execution (C-01).
- New residual risks, recorded in [known limitations](KNOWN_LIMITATIONS.md): a stalled network HSM can block the Auth Core process (B-01, open part); the hold delays legitimate lost-phone replacement by up to `DEVICE_REPLACEMENT_HOLD_SECONDS` unless the bank's process approves it another way; the in-database ECDSA verifier is PL/pgSQL code that has been tested against OpenSSL but not reviewed for side channels (verification uses public data only).

## Third cycle (final production readiness closure)

D-02 and D-07 fixed in code; D-01 decided (accepted for a controlled pilot with conditions, not for production); six new items N-01 to N-06. All findings with their ASVS/MASVS group and decision: [findings register](SECURITY_FINDINGS_REGISTER.md).

## What this report does not cover

- Behaviour on physical iPhones and Android phones (nothing has been run on a device).
- A production HSM (only SoftHSM was ever used, and not in this review).
- The Auth Core HTTP layer end to end (its suites need packages not installable here).
- An external penetration test, load test or resilience test.
