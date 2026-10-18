# Offline confirmation: threat model (FI-004)

Status (2026-10-18, phase 8): **offline confirmation v2 (deferred device signature) implemented in Auth Core and the Android SDK, written for the iOS SDK; gate G2 stays PARTIAL** until the SDKs are built and run on devices and the residual cases below are accepted. Protocol: [offline confirmation v2](../protocol/offline-confirmation-v2-deferred-signature.md), decision: [ADR 0018](../adr/0018-deferred-device-signature.md). Tests: `auth-core/test/integration/offline-deferred-signature.test.mjs` (v2), `offline-forgery.test.mjs` and `offline-limits.test.mjs` (v1), `master-key-hsm.test.mjs`.

## The path of an offline confirmation

| Step | Where | What is checked or stored | Secret involved |
|---|---|---|---|
| 1. Enrolment | device, Auth Core | Device sends signing, authentication and offline public keys; Auth Core derives `K = HKDF(ECDH(Z), "NEXUS-SIGN/OFFLINE/v1", credentialId)`, stores `K` under the device master key (`credentials.offline_secret_encrypted`, AES-256-GCM, AD `device:<credentialId>`), returns its public key, discards its private key; the keys are sealed in a `CREDENTIAL_ENROLLED` evidence record | device private keys (phone hardware), `K` (both sides), device master key (Auth Core) |
| 2. Operation | bank → Auth Core | `POST /v1/authorizations`: terms validated (display rules), canonicalized, hashed; row immutable by trigger (terms, policy reference and version since migration 022) | — |
| 3. Challenge | bank screen | `GET …/offline-challenge`: only `PENDING_USER`, not expired, credential offline-enabled, within the amount cap; QR `NXS2.` (v2) or `NXS1.` (v1) + canonical bytes | — |
| 4. Device | phone, no network | Strict parse of the bytes, own `credential_id`, expiry by the phone's clock; terms shown from the bytes; local user authentication; **v2: ECDSA signature with the signing key, stored**; then the code `trunc8(HMAC(K, domain ‖ SHA-256(bytes)))` | signing key, offline key / `K` |
| 5. Code submission | customer → bank screen → bank backend → Auth Core | `POST …/offline-confirmation` (bank client credentials, certificate binding) | — |
| 6. Code check | Auth Core | Under row lock: state, expiry, identity and credential `ACTIVE`, enrolment integrity, plan, amount cap, daily ceiling, constant-time compare with the code recomputed from `K`; five failures reject | `K`, device master key |
| 7. Result | Auth Core | v1: `VERIFIED`, evidence `OFFLINE_CODE` (HMAC tag). **v2: `OFFLINE_PROVISIONAL`**, or `VERIFIED` if the device signature is already stored | HSM evidence key (v1) |
| 8. Signature upload (v2) | phone → Auth Core | Device-signed request from the bound credential; signature verified with the enrolment-sealed key over the stored bytes; one per authorization; `OFFLINE_PROVISIONAL` → `VERIFIED` (`OFFLINE_SIGNED`), evidence sealed | device authentication key, HSM evidence key |
| 9. Missing signature (v2) | Auth Core sweep | Deadline passed or credential/identity not `ACTIVE` → `OFFLINE_UNSIGNED`, audit and webhook | — |
| 10. To the bank | webhooks (outbox), `GET /v1/authorizations/{id}`, evidence export | `authorization.offline_provisional`, `.verified`, `.offline_unsigned`, `evidence.appended` with HSM-sealed chain heads | webhook secret |
| 11. Execution | **bank** | The bank decides whether and when to execute; Auth Core's `bank-commit-request` needs `VERIFIED` | — |

## Who can get an offline confirmation accepted — before and after v2

"Accepted" means: Auth Core reports `VERIFIED` and seals evidence. In v2 a code alone yields only `OFFLINE_PROVISIONAL`, which Auth Core never reports as a confirmation.

| Compromise | Preconditions | v1 (code only) | v2 (deferred signature) | Still possible in v2 | Existing measures / evidence |
|---|---|---|---|---|---|
| Network observer, bank screen observer | sees the QR and the typed code | no: code bound to one authorization, single use, 5 attempts | no | nothing beyond v1 | `offline-forgery` 1, 2, 4 |
| Another customer or device | own credential | no: different `K` | no: different `K` and signing key | — | v1 test 2; v2 test 4 |
| Bank backend | bank client credentials | no (guesses only) | no | creates payments, chooses what to show on its own screen (the phone shows the signed bytes), may execute on `PROVISIONAL` at its own risk | v1 tests 1, 2 |
| **Database only** (read/write as the application role) | DB access, no master key | no: `K` encrypted, terms immutable | no: additionally, a signature row it inserts is re-verified, the table is append-only | flip `state` to `VERIFIED` with junk in `signature` (the trigger permits a transition with a signature value) — **no evidence record is produced**, so a bank that relies on sealed evidence is not misled; deny service | v2 tests 14, 15; state-machine property test |
| Database + configuration, `MASTER_KEY_SOURCE=env` | DB copy, device master key | **yes**: decrypt `K`, compute codes (submitted via the bank API or a controlled Auth Core) | **only `OFFLINE_PROVISIONAL`**, ending in `OFFLINE_UNSIGNED` | a provisional result the bank might act on if it ignores the state | v1 test 6; v2 test 16 |
| Database + configuration, `MASTER_KEY_SOURCE=hsm`, no HSM reach | DB copy, wrapped keys | no: master key wrapped by the HSM KEK | no | — | `master-key-hsm` test 2 |
| Database + configuration + HSM reach (PIN) | as above plus network path to the HSM | **yes** | only `OFFLINE_PROVISIONAL` | as the row above | KEY_MANAGEMENT.md |
| **Running Auth Core process** (code execution) | control of the process | **yes**: holds the master key and `K`, computes and accepts codes, seals evidence | cannot produce the device signature, so cannot produce an `OFFLINE_SIGNED` record that verifies | (a) seal a **forged `OFFLINE_CODE` (v1-style) record** with the HSM evidence key — a bank verifier with `--reject-offline-code` refuses it; (b) seal a record with an invalid ECDSA signature — any verifier refuses it; (c) seal a fake `CREDENTIAL_ENROLLED` record for an attacker key and then a validly signed `OFFLINE_SIGNED`/`DEVICE_SIGNATURE` record — detectable only if the bank reconciles enrolments (`evidence.appended` for an enrolment it never initiated); (d) mark authorizations `VERIFIED` without evidence; (e) withhold, delay or refuse signatures and webhooks; (f) serve a different QR to the bank screen — the phone shows those terms, so this depends on the customer reading them | ADR 0009, FI-019 heads |
| Admin console account | operator or admin login (TOTP) | no direct path | no direct path | revoke a credential (provisional confirmations then end `OFFLINE_UNSIGNED`): denial of service; operator decisions for AUDIO/VIDEO channels affect the plan, not the signature | route review; four-eyes revoke (ADR 0014) |
| **Customer's phone compromised** | malware with key use (biometric bypass) | yes | yes: the device key is the trust anchor | sign any authorization the phone receives | attestation at enrolment only (FI-007, open) |
| Stolen phone, no biometrics | possession | no | no | — | biometric-bound keys |

## What changed with v2, precisely

- The trust anchor of an offline confirmation moves from `K` (shared with Auth Core) to the device signing key (only on the phone), the same as online.
- Auth Core's own capability to *confirm* offline payments is removed; its capability to *deny*, *delay* and *mislabel* remains, and so does its capability to forge evidence records of a kind a verifier accepts unless told otherwise (v1 `OFFLINE_CODE`), and to forge enrolments.
- Detection replaces silent acceptance for the insider cases: a code accepted without a following signature becomes `OFFLINE_UNSIGNED` (audit `offline_signature_missing`, webhook `authorization.offline_unsigned`). A genuine signature arriving after the deadline is recorded (`deferred_signature_late`, `verified: true`) for investigation.

## What the device can and cannot establish offline

- It **can** check that the bytes are well formed, name its own credential, and have not expired *by its own clock*; display them; authenticate the user locally; sign them.
- It **cannot** know whether the authorization still exists, was cancelled, was already confirmed (online or on another channel), whether its credential was revoked, or the true time. Auth Core enforces these at upload; until then nothing is confirmed.
- So the signature proves that the enrolled phone approved those exact terms after local user authentication; it does not prove when, that the customer understood them, or that the payment should be executed. **The bank remains the source of truth** for the account, limits, risk and execution.

## Residual risks after v2 (not hidden by limits)

1. **Provisional acted upon.** A bank that executes on `PROVISIONAL` (to keep the branch experience fast) carries the v1 risk for those payments. Auth Core cannot prevent it; it labels the state and refuses its own commit flow. The amount cap and daily ceiling still bound the exposure in that case; they are bounds, not a fix.
2. **Forged v1 records by a controlled Auth Core.** Closed only if the bank's verifier runs with `--reject-offline-code` from the v2 switch date on.
3. **Forged enrolment by a controlled Auth Core.** Requires the bank to reconcile `CREDENTIAL_ENROLLED` heads against its own enrolment and replacement actions (FI-019 delivers the heads; the reconciliation is bank-side and not implemented here).
4. **Compromised phone.** Out of reach of any protocol change; per-operation integrity attestation (FI-007) is open.
5. **Old SDKs.** On a v2 deployment they refuse `NXS2.` QR codes; customers on old app versions cannot confirm offline until the bank ships the SDK.
6. **Rollback of Auth Core's database** after an upload produces a false `OFFLINE_UNSIGNED` (the phone already deleted the signature); never a false `VERIFIED`.
7. **Android UX.** Two biometric prompts (one per key). iOS is designed for one evaluation; not verified on a device.
8. **Unverified platforms.** The iOS implementation is not compiled here; the Android SDK is compiled for the JVM against stubs only.

## Bounds that remain in force

Amount cap per currency (`OFFLINE_CONFIRMATION_MAX_AMOUNT`) and per-credential daily ceiling (`OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY`, counting accepted codes, provisional or not, checked under a per-credential lock in the accepting transaction), both required in production; `OFFLINE_CONFIRMATION_MODE=deferred_signature` required in production.

## Not chosen

- Computing the HMAC inside the HSM: keeps `K` out of process memory but the process can still ask the HSM for a code; it does not move the boundary for an attacker controlling Auth Core.
- Longer codes: raise guessing cost but do not affect the insider case.
- Letting a deferred signature alone confirm a `PENDING_USER` authorization: cryptographically equivalent to an online confirmation, but it would make the deferred endpoint a second online path with different expiry rules; v2 requires both the code and the signature.
- A second signed format with its own domain: the existing canonical bytes already bind every field the decision depends on, including the purpose (`domain`).

## Phase 9: scenario verification against the code

Each row names the test that exercises it on the current code (`offline-deferred-signature.test.mjs` = DS, `offline-enforcement.test.mjs` = EN). "Prevented" means Auth Core refuses; "detected" means it is visible to the bank or an auditor but not stopped.

| Scenario | Attacker gets | Still possible | Prevented | Only detected | Trusted components still needed | Test |
|---|---|---|---|---|---|---|
| Database write access (application role) | rows | set `state = 'VERIFIED'` with junk in `signature`; insert rows into `evidence_records` and `offline_deferred_signatures`; deny service | **commit** of such a row (evidence re-verified: seal, binding, device signature); finalization with an inserted signature row; changing terms, policy, offline fields | the false `VERIFIED` is visible in `GET` until the bank checks evidence; `integrity_violation` audited on the commit attempt | HSM evidence key, enrolment records, Auth Core process | EN 3, 4; DS 14, 15 |
| Database + device master key (`env`) | `K` | compute codes → `OFFLINE_PROVISIONAL` | `VERIFIED`, commit | `OFFLINE_UNSIGNED` after the deadline | device signing key on the phone | DS 16 |
| Knowledge of `K` alone | codes | as above | as above | as above | — | DS 16 |
| Running Auth Core (code execution, HSM session) | everything the process can do | delay or block uploads and webhooks; refuse service; serve a different QR to the bank screen (the phone shows those terms); seal a v1-style `OFFLINE_CODE` record; seal a fake `CREDENTIAL_ENROLLED` and then a validly signed record with an attacker key; mark rows `VERIFIED`; answer the bank's commit request as it likes | nothing inside Auth Core can be relied on | v1 record: a v2 deployment's commit check and `verify-evidence --reject-offline-code` refuse it; invalid ECDSA: any verifier; fake enrolment: only by the bank reconciling `evidence.appended` enrolments with its own enrolment actions | bank-side verifier with keys obtained out of band, bank reconciliation | EN 6 (v1 record), DS 13, 20 |
| Forged evidence record (copied, re-pointed, altered) | a row | — | commit (names another authorization; hash/seal mismatch) | verifier fails it | HSM evidence public keys | EN 4, DS 13 |
| Forged device registration (database only) | a row | — | use of the key (credential integrity against the sealed enrolment) | `integrity_violation` | sealed enrolment | `evidence-integrity` (key replaced in the database cannot approve; verifier rejects a key that differs from the sealed enrolment) |
| Signature by another enrolled device | its own key | — | upload (403 / 422); service-level check without HTTP | audit `deferred_signature_invalid` | — | DS 4, EN 1 |
| Replacement device signs for the replaced one | new credential | — | upload (403); replaced device cannot authenticate (401); sweep ends the authorization `OFFLINE_UNSIGNED` | webhook `authorization.offline_unsigned` | — | EN 5 |
| Device revoked before the upload | — | — | upload; commit | `OFFLINE_UNSIGNED` (`credential_not_active`) | — | DS 5 |
| Signature reuse (repeat, other authorization, after deadline) | a valid signature | — | second transition (`ALREADY_RECORDED`, one evidence record); use for another authorization (422); late use (409) | `deferred_signature_late` with `verified: true` | — | DS 1, 3, 8, 8b, 10 |
| Alternative endpoint or webhook | API access | — | device `/signature`, bank `/signature`, second code, escalation: all refuse an `OFFLINE_PROVISIONAL` authorization; Auth Core has no inbound webhook that changes state | — | — | EN 2 |
| Old SDK | code only | — | `NXS2.` refused by the SDK parser; a code alone is never `VERIFIED` | — | — | Android `OfflineSignatureQueueTest`; DS 1 |
| Configuration change | config access | set `immediate` outside production with `ALLOW_INSECURE_DEVELOPMENT=true` | `immediate` in production (startup refused); `immediate` outside production without the insecure flag (startup refused) | startup warning lists `OFFLINE_CONFIRMATION_MODE=immediate` | deployment review | DS 18, EN 7, unit posture test |

## Phase 10: compromise scenarios re-assessed against the code (2026-10-18)

Changes since phase 9 that matter here: the commit check also requires the record's chain position and link; `confirmed` in the bank's `GET` is derived from evidence that verifies now, not from the state column; the device parsers check ID and nonce formats. Tests: `evidence-forgery-hsm.test.mjs` (FH, records with a genuine SoftHSM seal), EN, DS.

| Scenario | The attacker can | Auth Core prevents | Detected afterwards | Still possible |
|---|---|---|---|---|
| Database access only | write rows (state, evidence, signature rows), read ciphertexts | commit of a `VERIFIED` row without valid evidence; finalization with an inserted signature; changes to terms, policy, offline fields; reading `K` | `confirmed: false` + `evidenceProblem` in `GET`; `integrity_violation` on a commit attempt; the bank's retained chain heads (`--heads`) | deny service; make `GET` show `state: VERIFIED` (with `confirmed: false`) |
| Database + master keys | compute offline codes | `VERIFIED` and commit without the device signature | `OFFLINE_UNSIGNED` | provisional states the bank must not act on |
| Access to a running Auth Core (API calls as a bank or device it impersonates, no code execution) | what the API allows that identity | everything above | audit log | — |
| Full control of Auth Core (code execution, HSM session) | everything the process can: seal records with the real evidence key (FH shows the commit check and the verifier still refuse wrong signatures, other keys, wrong positions), seal a fake enrolment plus records signed by its key, answer commits as it likes, block or delay | nothing; the checks run in the same process | only outside Auth Core: the bank's verifier with keys obtained out of band, `--reject-offline-code`, `--heads`, reconciliation of `CREDENTIAL_ENROLLED` heads with the bank's own enrolment actions (not implemented) | forged enrolments followed by validly signed approvals; denial of service |
| Customer device compromised (key use) | sign any authorization the phone receives | — | — | everything the device key authorizes (FI-007) |
| Registered operator abusing the console | mark an AUDIO/VIDEO channel VERIFIED or FAILED for calls they claimed; revoke devices (four-eyes) | confirming a payment: the operator decision only satisfies a plan step, the device signature is still required | audit of claim and decision; evidence `verificationFactors` names the operator | pass a customer through a call the operator did not conduct honestly |
| Device registration compromised (fake enrolment) | via database only: replace keys in a row | use of a key that differs from the sealed enrolment (credential integrity) | `integrity_violation` | via a controlled Auth Core: see that row |
| Repeated execution | resend commit requests, reuse evidence | a second commit with another reference (409); one `COMMIT_REQUESTED` per authorization under the row lock (FH: 20 parallel same reference → one recorded request; 10 different → one accepted) | — | the bank executing twice on its side if it ignores the commit result (bank's idempotency on `bankTransactionReference`) |
| HSM failure | — | start with an unavailable HSM; sealing without the HSM (confirmation fails, nothing committed) | logs, readiness | outage of confirmations |
| HSM compromise (key use) | seal arbitrary records | records whose device signature, binding, enrolment link or chain position is wrong (FH) | verifier | records consistent in every respect for a key also enrolled through the compromise (with a controlled Auth Core) |
| Data substitution before signing | change what the bank screen or the API shows | anything the device does not display: the device signs only bytes it parsed strictly and displayed; formats are checked (phase 10) | the evidence carries the signed bytes | look-alike payee names are signed as they are (vector added; FI-034 open); the customer may not read the screen |
| Delivery channel compromise (network, push, QR) | observe, delay, replay, drop | replay of device requests (nonces), replay of codes (single use), signatures for other authorizations | — | delay and drop: provisional confirmations end `OFFLINE_UNSIGNED` |

Who executes: Auth Core never moves money. The bank's system executes, and the only point where Auth Core can stop it is `bank-commit-request`: the evidence check and the `PENDING → COMMIT_REQUESTED` transition happen in one transaction under the authorization's row lock, so there is no window between check and state change inside Auth Core. Between Auth Core's 202 and the bank's own execution the bank is responsible: execute once per `bankTransactionReference`, only after the 202, and report the result.
