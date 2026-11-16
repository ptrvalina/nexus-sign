# Cryptographic architecture

Every key, algorithm, signed structure and derivation NEXUS-SIGN uses, where it lives and how the three implementations (Auth Core in TypeScript, the Android SDK in Kotlin, the iOS SDK in Swift) are kept byte-compatible. Detailed formats are in the [protocol specifications](../protocol/README.md); key handling in [key management](KEY_MANAGEMENT.md) and [HSM key management](../security/hsm-key-management.md). Branch `engineering/production-readiness`.

## Principles

1. **The customer's private keys never leave the device's secure hardware.** Secure Enclave (iOS) or Android Keystore (StrongBox if present, else TEE), each use gated by a strong biometric.
2. **What is shown is what is signed.** The device parses and displays the exact canonical bytes it signs; JSON convenience fields are cross-checked and never displayed ([authorization protocol](../protocol/authorization-protocol-v1.md)).
3. **One signing domain per purpose.** Payments and mandates use different `domain` constants, so a signature for one is never valid for the other.
4. **Auth Core attests, the bank decides.** Auth Core seals evidence with an HSM key; the bank verifies the device signature and its own approval of the device key independently, in its own database ([bank credential trust](../protocol/bank-credential-trust-v1.md)).
5. **Shared vectors.** Each protocol has a vector file generated independently of the server code; all implementations run it.

## Key inventory

| Key | Algorithm | Generated / stored | Used for | Exposure |
|---|---|---|---|---|
| Device signing key | ECDSA P-256 / SHA-256 | Secure Enclave (`.biometryCurrentSet`), Keystore (`setUserAuthenticationRequired`, `setInvalidatedByBiometricEnrollment`) | Payment and mandate signatures, recovery setup | Never leaves hardware; invalidated by a biometric change |
| Device request key | ECDSA P-256 | As above, no biometric per use | Signing every device request (method, path, time, nonce, credential, body hash) | Never leaves hardware |
| Device offline key | iOS: ECDH P-256 in the Secure Enclave. Android: HMAC-SHA256 key imported into the Keystore | At enrolment | Offline 8-digit codes | iOS returns the ECDH secret to the app process (finding D-01); Android never exposes it |
| Offline key `K` (server side) | HKDF-SHA256 over ECDH with a per-credential server key that is then discarded | Database, AES-256-GCM under `DEVICE_SECRET_ENCRYPTION_KEY` | Verifying offline codes | Whoever holds the database and that master key can compute codes; production requires v2 (device signature) so a code alone never commits |
| Push key `K` | HKDF-SHA256 over ECDH (ephemeral server key) | Device (Keystore / Keychain), database (encrypted) | AES-256-GCM sealing of push content, HMAC receipts | As above |
| Recovery key | ECDSA P-256 | Created on the device; private half wrapped with AES-256-GCM under `HKDF(PBKDF2(phrase, 210 000))`, stored by Auth Core | Proving possession of the phrase | 2^128 phrase space for SDK-generated phrases |
| Evidence sealing key | ECDSA P-256 / SHA-256 | Bank HSM, generated inside, non-extractable (`CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE` checked at startup) | Sealing every evidence record | Never outside the HSM |
| KEK | AES-256 | Bank HSM, non-extractable | Wrapping the three master keys (AES-256-GCM, AAD bound to purpose) | Never outside the HSM |
| Master keys (webhook, device, admin) | AES-256-GCM | Wrapped in configuration, unwrapped into process memory at startup | Encrypting stored secrets (`k1$<keyId>$…`, AAD `<purpose>:<owner>`) | Process memory |
| Webhook secret (per bank) | HMAC-SHA256 | Database, encrypted | Signing webhooks `v1=HMAC(secret, timestamp.body)` | Bank and Auth Core |
| Admin TOTP secret | HMAC-SHA1 (RFC 6238) | Database, encrypted | Second factor of console logins | Admin's authenticator and Auth Core |
| Bank trust key | ECDSA P-256 | The bank, outside Auth Core | Signing the bank's approval and revocation of each device key | Never seen by Auth Core |
| Verification provider / operator results | ES256 JWS | Provider key (bank-registered) | Signed audio/video verification results bound to session, authorization and device | — |
| TURN credentials | HMAC-SHA1 (coturn REST) | Derived per call, nothing stored | Time-limited TURN access | — |
| Attestation roots | X.509 (Apple App Attestation Root CA, Google hardware attestation roots) | Pinned in configuration / code | Device attestation at enrolment | Public |

## Signed structures

| Structure | Bytes signed | Signer | Verifier |
|---|---|---|---|
| Payment authorization | Canonical JSON of 15 fields, keys sorted recursively, `domain = NEXUS-SIGN/TRANSACTION-AUTH`, `protocol_version = "1"` | Device signing key | Auth Core, the bank database (`bank.approve`, PL/pgSQL P-256), the offline verifier |
| Mandate terms | Canonical JSON of 17 fields, `domain = NEXUS-SIGN/MANDATE`; `total_limit_minor` may be `null` | Device signing key | Auth Core, the bank database (`mandate_problem`) |
| Device request | `NEXUS-SIGN/DEVICE-REQUEST/v1`, method, path and query as sent, timestamp, nonce, credential ID, hex SHA-256 of the body, joined with `\n` ([device protocol](../protocol/device-authentication-and-offline-confirmation.md)) | Device request key | Auth Core, one-time nonce |
| Offline code | `HMAC-SHA256(K, "NEXUS-SIGN/OFFLINE-CODE/v1" ‖ 0x00 ‖ SHA-256(canonical bytes))` truncated to 8 digits; v2 additionally a deferred device signature | Device offline key (+ signing key in v2) | Auth Core |
| Evidence record | `evidenceHash = SHA-256(canonicalJson(sealedPayload))`, seal = ECDSA over the hash; records chained by sequence and previous hash per NEXUS ID | HSM evidence key | Anyone with the public key: `scripts/verify-evidence.mjs`, the bank |
| Bank trust statement | Canonical statement of approval/revocation of a credential key | Bank trust key | Bank database, bank tools |
| Conversation message | `SHA-256` chain per conversation (no signature) | — | Auth Core (`verifyConversation`) |

The display rules that apply to every displayed value are part of the signed-bytes contract: both SDKs refuse signed bytes that break them ([display text rules](../protocol/authorization-protocol-v1.md#display-text-rules)).

## Byte-level compatibility of the three implementations

| Vector file | Auth Core (TypeScript) | Android core (Kotlin, JVM) | iOS (Swift) |
|---|---|---|---|
| `signed-payload-v1.json` (8 valid, 59 invalid, 7 response mismatches, amount formatting, prompt text) | Verified: `check-signed-payload-vectors.mjs` compares the server's canonical encoding and refusals | **Verified on this branch**: `SignedTransactionTest` (`android-sdk/scripts/jvm-core-tests.sh`) | Test exists (`SignedTransactionTests`); **not run** (no Xcode here) |
| `mandate-terms-v1.json` (3 valid, 17 invalid) | Verified (`mandates.test.mjs`: server encodes the vector bytes) | **Verified** (`MandateTermsVectorsTest`) | Parser exists in `NEXUSSignSDK.swift`; no vector test yet |
| `device-protocols-v1.json` (request signing input, ECDH, HKDF, HMAC, codes) | Verified (unit) | **Verified** (`DeviceProtocolTest`) | Test exists; not run |
| `bank-trust-v1.json` | Verified (unit) | **Verified** (`BankTrustVectorsTest`) | Test exists; not run |
| `secure-push-v1.json` | Verified (unit) | Test exists (`SecurePushTest`, needs Android) ; not run | Test exists; not run |
| `recovery-v2.json` | Verified (unit) | Test exists (Android-only classes); not run | Test exists; not run |

The JVM run compiles the platform-independent Kotlin sources with the Kotlin 2.0.21 compiler of a Gradle distribution and runs 39 JUnit tests; it is not the Android build (no Keystore, BiometricPrompt or OkHttp). `check-vector-copies.mjs` ensures each vector file has exactly one iOS copy identical to the master.

## Randomness

Node.js `crypto.randomBytes`/`randomUUID` (OS CSPRNG) on the server; `SecRandomCopyBytes`/CryptoKit on iOS; `SecureRandom` on Android. Nonces: 32 bytes per authorization, one-time device request nonces stored in PostgreSQL (production) with expiry.

## Known cryptographic limits

| Limit | Status |
|---|---|
| iOS offline secret leaves the Secure Enclave (D-01) | Open, Medium. Bounded by the production requirement of offline v2: a code alone yields `OFFLINE_PROVISIONAL`, never `VERIFIED`, and only `VERIFIED` commits. Protocol fix (per-authorization server ephemeral key) designed, not implemented |
| Offline v1 codes are HMACs under a key Auth Core holds | v1 refused in production (startup blocker) |
| The PL/pgSQL ECDSA verifier in the bank database | Tested against OpenSSL with valid and corrupted inputs; not reviewed for timing (public data only) |
| Conversation messages are hash-chained, not sealed | By design; they authorize nothing |
| No production HSM has been used | [HSM acceptance procedure](../operations/hsm-acceptance.md) |
| No external cryptographic review | Required before production |
