# Release blockers

What still stands between the current version on `main` (developed on branch `engineering/production-readiness`) and a controlled bank pilot, after the fourth cycle. Every engineering blocker that could be closed with the available tools (CI, SoftHSM, the code) has been closed; see [engineering readiness](ENGINEERING_READINESS.md). What is left needs infrastructure, devices or people that NEXUS-SIGN engineering does not have. None of the checks below may be replaced by a simulation: SoftHSM is not the bank's HSM, a Chromium WebRTC test is not a phone call, a unit test is not a device.

Status of each: **BLOCKED** (needs access that is not available) unless stated.

## Summary

| # | Blocker | Owner | Status | Blocks pilot conditions |
|---|---|---|---|---|
| B1 | Real iPhones | Bank QA (devices), NEXUS-SIGN engineering (build) | BLOCKED | 7, 8, 15, 16 |
| B2 | Real Android phones | Bank QA | BLOCKED | 7, 8, 15, 16 |
| B3 | The bank's HSM | Bank HSM team | BLOCKED | 10, 17 |
| B4 | The bank's test environment (gateway, PostgreSQL/Redis HA, core banking adapter) | Bank | BLOCKED | 17 |
| B5 | Push through the bank's push contour | Bank | BLOCKED | 15 |
| B6 | Real audio and video scenarios | Bank operators + QA | BLOCKED | 15 |
| B7 | Independent external penetration test and cryptographic review | External firm chosen by the bank | BLOCKED | 18, 19 |
| B8 | Bank integration acceptance | Bank | BLOCKED | 17 |
| B9 | D-01 protocol change (iOS offline secret) | NEXUS-SIGN engineering | **Closed in code** (offline v3, `5f2ab00`, CI run `44023147512`); remains: confirmation on an iPhone (part of B1) | 8 (partly) |
| B10 | Verification of Payee | Bank | Bank's function (F17) | 2 (exception) |

## Test protocols

Each protocol states the preconditions, the scenarios and the PASS criterion. A result is recorded with date, device or system model and version, build commit, tester, and the evidence (screen recording, log excerpt, evidence record ID).

### B1, B2. Real iPhone and Android devices

Preconditions: SDK and demo app built by CI from a tagged commit (iOS: signed with the bank's Apple Developer team, App Attest environment `production` for the final run); Auth Core in the bank's test environment; devices: iPhone with Face ID and one with Touch ID (iOS 15 minimum, plus the current iOS); Android with StrongBox (e.g. Pixel 3 or later), one without StrongBox (TEE only), Android 9 (API 28, the minimum) and the current version.

Scenarios: the [device acceptance checklist](DEVICE_ACCEPTANCE_CHECKLIST.md) sections A–G — build and install, enrolment and keys (key in Secure Enclave / StrongBox, `securityLevel` reported correctly, TEE fallback), confirmation display (labelled prompt of D-02 with long names and RTL text, look-alike refusal), TLS pinning, verification calls, offline confirmation, recovery and replacement; biometric change invalidates keys on both platforms ([biometric behaviour](../architecture/biometric-behaviour.md), D-07).

PASS: every checklist item passes on every device class; the key attestation of each enrolment is verified by Auth Core with the production roots; the bank database verifies every signature produced on a device; no item is waived.

### B3. The bank's HSM

Preconditions: an HSM test partition of the production model, the vendor PKCS#11 module, a PIN for a dedicated user, the HSM team present.

Scenarios: the [HSM acceptance procedure](../operations/hsm-acceptance.md): the eight suites against the vendor module (token setup by hand), then the vendor-only checks — concurrent logins and session limits, per-call timeout and breaker under a network cut, cluster failover, key attributes (`CKA_SENSITIVE`, `CKA_EXTRACTABLE=false`, `CKA_LOCAL`), AES-GCM with a caller IV in the HSM's approved mode, restart of the HSM and of Auth Core, HSM audit log entries.

PASS: 8/8 suites pass on the vendor module; Auth Core refuses to start without the HSM and never falls back to a software key; failover completes without a lost or duplicated seal; latency at the bank's peak load within the agreed bound.

### B4, B8. Bank test environment and integration acceptance

Preconditions: the bank's gateway with mutual TLS, PostgreSQL 16 and Redis 7 in the bank's HA configuration, the bank execution boundary installed in the bank database, the core banking (or a payment provider sandbox) adapter.

Scenarios: section 10 of the [pilot execution pack](../integration/pilot-execution-pack.md) (mandatory tests in the bank's infrastructure): positive payment, every Auth Core lie of `bank-trust-compromise` against the real boundary, unknown provider outcome and reconciliation, revocation races, restore from backup, failover of PostgreSQL and Redis during confirmations, load at the expected peak.

PASS: every payment executes exactly once or not at all; no execution without a device signature verified by the bank database; failover loses no confirmed authorization; the bank signs the acceptance protocol.

### B5. Push through the bank's contour

Preconditions: push mode `BANK` configured; the bank's push service delivering to APNs and FCM.

Scenarios: delivery of authorization requests to both platforms, app in foreground, background and killed; delayed and dropped pushes (expiry); a push for another device; notification content visible on the lock screen.

PASS: the content shown comes from the signed request fetched by the app, never from the push; no payment data in the push payload; a lost push ends as `EXPIRED`, never as approved.

### B6. Real audio and video scenarios

Preconditions: the bank's TURN servers; operators with the console; B1/B2 devices.

Scenarios: escalation push → audio → video by bank policy and amount; customer-initiated call; poor network (3G, Wi-Fi to cellular handover); call dropped by each side; operator decision; camera and microphone permission refused; call while another call is active.

PASS: the call never replaces the signature (the authorization stays pending until signed); each call ends with the correct reason in both views; media are DTLS-SRTP; no media through Auth Core.

### B7. External penetration test and cryptographic review

Preconditions: a firm independent of NEXUS-SIGN, with banking experience; scope: Auth Core API, console, both SDKs (including reverse engineering of the demo app), the bank execution boundary, the evidence format, the deployment manifests.

PASS: no open Critical or High finding; Medium findings closed or accepted in writing by the bank.

## What does not block the pilot, but production

D-01 protocol change; the 19 Low findings planned before production ([security findings](SECURITY_FINDINGS.md#triage-of-the-low-findings)); load and resilience tests at production scale; regulatory assessment (PSD2/RTS SCA).
