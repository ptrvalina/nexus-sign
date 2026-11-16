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

## Functions of the product presentation that are partial

Since the second cycle every function has code (see the [feature matrix](PRODUCT_FEATURE_COMPLIANCE_MATRIX.md#remaining-gaps)). Still partial: a customer-initiated call to the bank outside a payment check; a payee check against the bank's own data (the bank's anti-fraud); one biometric-change behaviour on both platforms; console screens for mandates, devices and authorizations; SIEM and anti-fraud connectors; Kubernetes manifests; confirmation-success and HSM-availability metrics. The bot is the bank's own, connected through webhooks and the bank API.

## Security limits of the current design

| Limitation | Detail |
|---|---|
| Several devices: each payment is addressed to one device | The bank chooses the device when it creates an authorization (`credentialId`); the push goes to that device only. A bank that wants any of the customer's devices to answer creates the authorization for the one the customer is using |
| Device replacement hold delays a legitimate replacement | A customer who lost the phone waits up to `DEVICE_REPLACEMENT_HOLD_SECONDS` (default 24 h, minimum 1 h in production) unless the enrolled device approves; the bank's replacement process must plan for this |
| A stalled HSM fails PKCS#11 calls, not the process | Since `8ee386a` the module runs in a worker thread; a stalled call times out, the breaker opens and readiness reports the HSM down. Master-key unwrapping at startup still runs on the main thread, before traffic. Behaviour with a vendor HSM is untested |
| Evidence covers authorizations, outcomes, revocations and mandates; conversations have their own hash chain | Conversation messages are not sealed with the HSM key; their integrity is the per-conversation hash chain and database append-only rules |
| Offline confirmation v1 codes are HMACs under a key Auth Core holds | Whoever holds the database and `DEVICE_SECRET_ENCRYPTION_KEY` can compute a valid v1 code. v1 (`OFFLINE_CONFIRMATION_MODE=immediate`) is refused in production; v2 waits for the device signature |
| Credential rows inserted directly into the database are not refused by the database | They are refused at use by the runtime integrity check against sealed enrolments; authorization inserts are refused by the database since migration 024 |
| Migrations are forward-only | The ledger and checksums (since `e4d269c`) make installs and upgrades repeatable; there are no down migrations. Restore a backup to roll back |
| iOS offline secret is usable by the app process once it leaves the Secure Enclave | Finding D-01; needs a device to change and verify |
| The confirmation prompt layout can be ambiguous for some field combinations | Finding D-02; needs a device to change and verify |
| DTLS-SRTP for calls is a WebRTC property, not enforced by Auth Core | Finding A2-11 |
| Audio and video show a person; they do not identify them | No liveness or deepfake detection is claimed |
| The in-database ECDSA verifier is PL/pgSQL | Tested against OpenSSL on generated valid and corrupted inputs; slower than native code; not reviewed for timing side channels (it handles public data only) |
| Conversation bodies are stored in the Auth Core database in clear text | Protected like the rest of the database; not end-to-end encrypted; the bank sets retention |
| No API rate limiting in Auth Core | Expected at the bank's gateway (finding A1-10) |
| Low and informational review findings | 39 Low and 16 Info findings are open ([area reports](security-review/README.md)) |

## Documentation gaps

No NEXUS ID specification (allocation, uniqueness scope, reuse after revocation), no single cryptographic design document, no production configuration template with every variable, no deployment manifests or Helm chart, no regulatory mapping (PSD2/RTS SCA).
