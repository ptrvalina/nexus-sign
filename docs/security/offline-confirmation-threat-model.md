# Offline confirmation: threat model (FI-004)

Status: **partially mitigated; gate G2 stays open.** A complete correction needs a protocol change that is a product-owner decision (below). Tests: `auth-core/test/integration/offline-forgery.test.mjs`, `offline-limits.test.mjs`, `master-key-hsm.test.mjs`.

## Protocol, end to end

1. **Enrolment.** The device generates an offline key pair (iOS: Secure Enclave; Android: in memory, see FI-031) and sends the public key. Auth Core generates a fresh P-256 key pair, computes the ECDH secret, derives `K = HKDF-SHA256(Z, "NEXUS-SIGN/OFFLINE/v1", credentialId)`, stores `K` encrypted under the device master key (`credentials.offline_secret_encrypted`, AES-256-GCM, associated data `device:<credentialId>`), discards its private key and returns its public key. The device derives the same `K`; Android imports it into the Keystore behind biometrics.
2. **Authorization.** The bank creates the authorization; its terms are immutable in the database (trigger) and canonicalized.
3. **Challenge.** The bank screen shows `NXS1.<canonical bytes>` as a QR code, only within the amount cap and currency list.
4. **Device.** The phone parses the bytes strictly, shows the terms, and after a biometric check computes `code = trunc8(HMAC-SHA256(K, "NEXUS-SIGN/OFFLINE-CODE/v1" ‖ 0x00 ‖ SHA-256(bytes)))`.
5. **Submission.** The customer types the code on the bank screen; the bank backend submits it (bank API, client credentials and certificate).
6. **Verification.** Under a row lock: state and expiry, identity and credential active, plan satisfied, daily limit per credential, then constant-time comparison with the code recomputed from `K` and the stored terms. Five failures reject the authorization. A match seals evidence with `confirmationMethod: OFFLINE_CODE`, `signatureFormat: hmac`.

## Security boundary

The code is a MAC under a key shared by the device and Auth Core. It proves to Auth Core that something holding `K` approved these exact bytes. It cannot prove to a third party that the device did, because Auth Core holds `K` too. The device signing key (ECDSA, non-repudiable) is not used offline.

## Who can produce an accepted code

| Attacker capability | Can they get an offline confirmation accepted? | Evidence |
|---|---|---|
| Network attacker, bank screen observer | No: an 8-digit code is bound to one authorization and its bytes; single use; 5 attempts (5 in 10^8) | `offline-forgery` tests 1, 2, 4 |
| Another enrolled customer or device | No: their `K` differs | test 2 |
| Bank backend compromised (creates and submits authorizations) | No, without `K`: it can create a payment and submit guesses, nothing more | tests 1, 2 |
| Database write access only | No: terms are immutable; `K` is encrypted | test 3; schema triggers |
| Database copy + device master key (`MASTER_KEY_SOURCE=env`) | **Yes**: decrypt `K`, compute the code, submit through the bank API (needs bank client credentials and certificate) or through a compromised Auth Core | test 6 (residual risk, documented) |
| Database copy + configuration with `MASTER_KEY_SOURCE=hsm`, no HSM access | No: the master key is wrapped by the HSM KEK | `master-key-hsm` test 2 |
| Database copy + configuration + network access to the HSM (PIN in configuration) | **Yes** | KEY_MANAGEMENT.md |
| Control of a running Auth Core process | **Yes** (holds the master key in memory, can compute and accept codes) | inherent |
| Admin console operator | No direct path: the console cannot submit offline codes or read `K` | route review |

Bounds on the residual cases: amount cap per currency (`OFFLINE_CONFIRMATION_MAX_AMOUNT`), at most N offline confirmations per credential per 24 h (`OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY`, audit event `offline_confirmation_limit_reached`), both required in production, both set in the deployment configuration (a database change cannot raise them). Every offline confirmation is labelled `OFFLINE_CODE` in the evidence and the verifier counts them separately.

## Complete correction: deferred device signature (owner decision)

Proposal: during the same biometric confirmation the device also signs the canonical bytes with its signing key (ECDSA, the key used online) and keeps the signature. When it is online again it uploads it (`POST /v1/mobile/authorizations/{id}/deferred-signature`, device-signed). Auth Core verifies it against the credential's sealed signing key and appends an evidence record `OFFLINE_CONFIRMATION_SIGNED` linking to the `OFFLINE_CODE` record. The bank may hold the commit until the signed record exists, or accept the payment and treat an offline confirmation without a signature after N hours as a security event.

| Aspect | Consequence |
|---|---|
| Protocol | New device endpoint; new evidence record type; SDK stores pending signatures and uploads them |
| Compatibility | Additive for banks and existing devices; evidence verifiers before the change would not know the new record type (needs a verifier update before banks rely on it) |
| Android | The offline HMAC key and the signing key each need a `CryptoObject`; a second biometric prompt, or a time-bound authentication key, must be accepted |
| iOS | One `LAContext` can authorize both Secure Enclave keys within one prompt |
| Security result | A forged code without the device has no matching signature; detection is certain, prevention only if the bank waits for the signature |
| Product cost | A payment confirmed fully offline is only provisionally proven until the phone is online |

**Decision needed from the product owner:** adopt the deferred signature (and whether banks must wait for it), or accept the residual risk with the caps for the pilot. Until then FI-004 remains PARTIAL and gate G2 open.

## Not chosen

- Computing the HMAC inside the HSM (K wrapped by the KEK and used through `C_Sign` with `CKM_SHA256_HMAC`): keeps `K` out of process memory but the process can still ask the HSM for a code, so it does not move the boundary for an attacker controlling Auth Core.
- Longer codes: raise guessing cost (already 5 in 10^8) but do not affect the insider case.
