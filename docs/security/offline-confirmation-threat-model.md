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
