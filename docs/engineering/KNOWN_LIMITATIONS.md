# Known limitations

What NEXUS-SIGN does not do, or has not been shown to do, on branch `engineering/production-readiness` (version `2.0.0-rc.2` plus unreleased changes), updated in the fourth cycle with the CI results. Collected from the [threat model](../security/threat-model.md#residual-risks), the [release notes](../operations/release.md), the [security assessment](SECURITY_ASSESSMENT_REPORT.md) and the [feature matrix](FUNCTIONAL_COMPLETENESS_MATRIX.md). A bank reads this before a pilot.

## Not yet shown to work

| Limitation | Consequence | What closes it |
|---|---|---|
| Nothing has been run on a physical iPhone or Android phone | Key generation in Secure Enclave / StrongBox, biometric binding, the confirmation screen, push handling, offline confirmation and recovery on the phone are code that compiles and passes unit tests, not demonstrated behaviour | The [device acceptance checklist](DEVICE_ACCEPTANCE_CHECKLIST.md) on real devices ([protocol](RELEASE_BLOCKERS.md)) |
| The SDKs are built and unit-tested in CI only (iOS on a macOS runner, Android with Gradle and Android Lint on both modules); no device or emulator ran them | Hardware-backed paths (Secure Enclave, StrongBox, BiometricPrompt, Keychain access control) are not exercised by unit tests | Device acceptance; details in [SDK validation](SDK_VALIDATION.md) |
| No production HSM has been used; the eight HSM suites pass on SoftHSM 2.7.0 in CI | Vendor-specific behaviour of `C_Login`, session limits, failover, FIPS mode and key attributes is unknown | Validation on the bank's HSM model ([HSM validation](HSM_VALIDATION.md)) |
| No penetration test, load test or resilience test | Throughput, latency and behaviour under attack are unmeasured | The bank acceptance stage of the [implementation path](../integration/pilot-execution-pack.md) |
| App Attest and Play Integrity verification are tested with test chains and verdicts made by the tests, not with real device tokens | A device-specific format detail would not be found | Recorded tokens from real devices as test fixtures |
| Audio and video calls ran between Chromium and Auth Core in CI (WebRTC media tests), not on phones, not through the bank's TURN servers | Mobile network behaviour, audio routing and camera handling on devices are untested | Real audio/video scenarios ([protocol](RELEASE_BLOCKERS.md)) |

## Functions of the product presentation that are partial

One: checking the payee against the bank's own records (Verification of Payee) is the bank's function; NEXUS-SIGN guarantees that the screen shows exactly the signed payee, labelled, and refuses a second account number in other fields. The bot is the bank's own, connected through webhooks and the bank API. See the [functional coverage matrix](FUNCTIONAL_COMPLETENESS_MATRIX.md).

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
| iOS offline secret is usable by the app process once it leaves the Secure Enclave | Finding D-01: **fixed in code** by offline v3 ([register](SECURITY_FINDINGS.md#d-01-medium-fixed-by-offline-confirmation-v3)): the secret serves one authorization only; not yet confirmed on an iPhone |
| The labelled confirmation prompt (D-02 fix) has not been seen on a device | Long names, translated labels and system prompt truncation need a device check |
| DTLS-SRTP for calls is a WebRTC property, not enforced by Auth Core | Finding A2-11 |
| Audio and video show a person; they do not identify them | No liveness or deepfake detection is claimed |
| The in-database ECDSA verifier is PL/pgSQL | Tested against OpenSSL on generated valid and corrupted inputs; slower than native code; not reviewed for timing side channels (it handles public data only) |
| Conversation bodies are stored in the Auth Core database in clear text | Protected like the rest of the database; not end-to-end encrypted; the bank sets retention |
| No API rate limiting in Auth Core | Expected at the bank's gateway (finding A1-10) |
| Low and informational review findings | 10 Low and 7 Info findings remain open, all accepted with a reason ([findings register](SECURITY_FINDINGS.md)); the WebRTC binaries' provenance and licences stay a release blocker (D-015) |
| Customer calls are recorded, not sealed | The call row is immutable once ended; calls authorize nothing |
| Metrics and the audit export | The confirmation counter counts in the confirming transaction; the audit export needs a lag above the longest transaction |

## Documentation gaps

No NEXUS ID specification (allocation, uniqueness scope, reuse after revocation) and no regulatory mapping (PSD2/RTS SCA). Kubernetes manifests exist ([deploy/kubernetes](../../deploy/kubernetes/README.md)) but no Helm chart.
