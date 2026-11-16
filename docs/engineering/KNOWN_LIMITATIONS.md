# Known limitations

What NEXUS-SIGN does not do, or has not been shown to do, on branch `engineering/production-readiness` (version `2.0.0-rc.2` plus unreleased changes). Collected from the [threat model](../security/threat-model.md#residual-risks), the [release notes](../operations/release.md), the [security assessment](SECURITY_ASSESSMENT_REPORT.md) and the [feature matrix](PRODUCT_FEATURE_COMPLIANCE_MATRIX.md). A bank reads this before a pilot.

## Not yet shown to work

| Limitation | Consequence | What closes it |
|---|---|---|
| Nothing has been run on a physical iPhone or Android phone | Key generation in Secure Enclave / StrongBox, biometric binding, the confirmation screen, push handling, offline confirmation and recovery on the phone are code, not demonstrated behaviour | The [device acceptance checklist](DEVICE_ACCEPTANCE_CHECKLIST.md) on real devices |
| The SDKs were not compiled in the review environment | Changes to the SDKs on this branch (display rules, decline, device replacement approve and cancel) may not compile | CI jobs `ios-sdk` and `android-sdk` green on the branch |
| No production HSM has been used; SoftHSM 2.7 only, and not in this review | Vendor-specific behaviour of `C_Login`, session limits, failover and key attributes is unknown | Validation on the bank's HSM model |
| The Auth Core HTTP integration suites did not run in this review (they need `express`, `ioredis`, `prom-client`) | Route-level behaviour of the changes on this branch is covered by service-level PostgreSQL tests only | CI job `auth-core / integration` green on the branch |
| No penetration test, load test or resilience test | Throughput, latency and behaviour under attack are unmeasured | The bank acceptance stage of the [implementation path](../integration/pilot-execution-pack.md) |
| App Attest and Play Integrity verification have no tests with real or recorded tokens | A defect in those parsers would not be found by the test suite | Recorded tokens from real devices as test fixtures |

## Functions the product presentation shows that do not exist

Chat with the bank, bot assistant and handover; customer-initiated calls to the bank outside a payment verification; recurring payment mandates; the customer's device list, transaction history, evidence view, settings, limits and security log; customer suspension of the NEXUS ID; several active devices per NEXUS ID; a bank API call to suspend an identity; an event feed of past notifications. Details per page: [feature matrix](PRODUCT_FEATURE_COMPLIANCE_MATRIX.md).

## Security limits of the current design

| Limitation | Detail |
|---|---|
| One active device per NEXUS ID | A second device replaces the first (with the replacement hold). A phone and a tablet cannot both confirm |
| Device replacement hold delays a legitimate replacement | A customer who lost the phone waits up to `DEVICE_REPLACEMENT_HOLD_SECONDS` (default 24 h, minimum 1 h in production) unless the enrolled device approves; the bank's replacement process must plan for this |
| A stalled network HSM can freeze Auth Core | Session open, login, object search and `C_SignInit`/`C_VerifyInit` are synchronous in pkcs11js; set the vendor client's network timeout ([HSM runbook](../operations/runbooks/hsm-unavailable.md)). Finding B-01, partly open |
| Evidence is sealed only for verified authorizations | Declined, rejected and expired outcomes are in the audit log and webhooks, not in the sealed chain (finding B-04) |
| Offline confirmation v1 codes are HMACs under a key Auth Core holds | Whoever holds the database and `DEVICE_SECRET_ENCRYPTION_KEY` can compute a valid v1 code. v1 (`OFFLINE_CONFIRMATION_MODE=immediate`) is refused in production; v2 waits for the device signature |
| Credential rows inserted directly into the database are not refused by the database | They are refused at use by the runtime integrity check against sealed enrolments; authorization inserts are refused by the database since migration 024 |
| Migrations cannot build a database from empty, and there is no migration ledger | Fresh installs use `schema.sql`; an upgrade of an old installation must be rehearsed on a restored copy (finding C-06) |
| iOS offline secret is usable by the app process once it leaves the Secure Enclave | Finding D-01; needs a device to change and verify |
| The confirmation prompt layout can be ambiguous for some field combinations | Finding D-02; needs a device to change and verify |
| DTLS-SRTP for calls is a WebRTC property, not enforced by Auth Core | Finding A2-11 |
| Audio and video show a person; they do not identify them | No liveness or deepfake detection is claimed |
| The in-database ECDSA verifier is PL/pgSQL | Tested against OpenSSL on generated valid and corrupted inputs; slower than native code; not reviewed for timing side channels (it handles public data only) |
| No API rate limiting in Auth Core | Expected at the bank's gateway (finding A1-10) |
| Low and informational review findings | 39 Low and 16 Info findings are open ([area reports](security-review/README.md)) |

## Documentation gaps

No NEXUS ID specification (allocation, uniqueness scope, reuse after revocation), no single cryptographic design document, no production configuration template with every variable, no deployment manifests or Helm chart, no regulatory mapping (PSD2/RTS SCA).
