# Device authentication and offline confirmation

After enrolment the phone needs nothing from the bank's backend or from any cloud service to authenticate itself or to confirm a transaction:

- **Device-signed requests.** The phone signs every request to Auth Core with a hardware key. No access token exists, so none can be stolen, logged or replayed.
- **Offline confirmation.** The customer confirms a transaction shown as a QR code (branch, ATM, web banking) with a phone that has no network. The phone shows the transaction, asks for the biometric and displays an 8-digit code, which the customer types on the bank's screen.

The bank backend is involved once, to vouch for the customer at enrolment: it requests a single-use `BOOTSTRAP` token (`POST /v1/mobile/sessions`). Recovery works the same way with a recovery session.

## Keys on the device

| Key | Algorithm | Unlock | Purpose |
|---|---|---|---|
| Signing | ECDSA P-256 | Biometric, every use | Signs the canonical authorization bytes ([protocol v1](authorization-protocol-v1.md)) |
| Authentication | ECDSA P-256 | Device unlocked, no prompt | Signs each request to Auth Core |
| Offline | iOS: ECDH P-256 in the Secure Enclave. Android: HMAC-SHA256 key in the Keystore | Biometric, every use, bound to the prompt that shows the transaction | Computes offline confirmation codes |

All keys are generated in the Secure Enclave or the Android Keystore (StrongBox when available) and are not exportable. The three public keys are sent in one enrolment request and covered by one App Attest or Play Integrity attestation:

```text
challenge || 0x00 || signing PEM || 0x00 || authentication PEM || 0x00 || offline PEM
```

Auth Core accepts only strict PEM text (header, base64 lines, footer), so the binding cannot be shifted by embedded NUL bytes or trailing data. On Android the signing and authentication keys also carry Keystore key attestation chains, from which Auth Core takes the credential's security level ([Android key attestation](../security/attestation.md#android-key-attestation)).

Enrolment and recovery generate a new key set next to the current one and switch to it only after Auth Core has confirmed. The switch and the new credential ID are written together: on Android in one `SharedPreferences.commit()`, on iOS through a pending record that is applied with the re-tag and survives a crash in between.

## Device-signed requests

Headers:

| Header | Value |
|---|---|
| `X-NEXUS-Credential` | Credential ID returned at enrolment |
| `X-NEXUS-Timestamp` | Unix time in seconds |
| `X-NEXUS-Nonce` | 16 to 64 characters, base64url alphabet, fresh for every request |
| `X-NEXUS-Signature` | Base64 DER ECDSA P-256 / SHA-256 signature by the authentication key |

Signed bytes, UTF-8, lines joined with `\n`:

```text
NEXUS-SIGN/DEVICE-REQUEST/v1
<HTTP method, upper case>
<path and query exactly as sent, percent-encoded, e.g. /v1/mobile/authorizations/...>
<timestamp>
<nonce>
<credential ID>
<lowercase hex SHA-256 of the body bytes; of the empty string for GET>
```

Auth Core checks, in this order:

1. The headers are well formed and the timestamp is within `DEVICE_REQUEST_MAX_SKEW_SECONDS` (default 300 s) of server time. A rejection carries `serverTime`, so a phone with a wrong clock corrects its offset (at most 24 hours) and retries once.
2. The credential is `ACTIVE`, has an authentication key, and its keys match its sealed enrolment record ([runtime integrity check](evidence-format.md#runtime-integrity-check)); the signature verifies over the bytes above. The path is the request target as received, prefixed with `DEVICE_REQUEST_PATH_PREFIX` when the gateway strips one.
3. The nonce has not been seen for this credential (stored for 2 × `DEVICE_REQUEST_MAX_SKEW_SECONDS` + 60 s, 660 s by default, `SET NX`). It is recorded only after the signature has verified, so nobody can use up another device's nonces.
4. The NEXUS ID is `ACTIVE`.

Every enrolled device authenticates this way; there is no bearer token for an enrolled device. `POST /v1/mobile/bootstrap` and recovery completion require the authentication public key (`authPublicKeyPem`, 400 without it), and their responses always carry `requestAuthentication: DEVICE_SIGNATURE`. Devices enrolled by an SDK before 1.2 have no authentication key and can no longer call the mobile API; they are enrolled again through [device replacement](../architecture/device-replacement.md). `SESSION` tokens issued by 1.x and 2.0.0-rc.1 that are still in Redis are refused with 401.

The SDKs accept an authorization ID only in UUID form before building a signed request, so an ID from a push message or deep link cannot steer a signature to another endpoint.

## Offline confirmation

### Enrolment

1. The device sends its offline public key with the other enrolment keys.
2. Auth Core generates a fresh P-256 key pair for this credential, computes the ECDH shared secret `Z` (the 32-byte x coordinate) and derives

   ```text
   K = HKDF-SHA256(IKM = Z, salt = "NEXUS-SIGN/OFFLINE/v1", info = credential ID, L = 32)
   ```

   It stores `K` encrypted with `DEVICE_SECRET_ENCRYPTION_KEY` (AES-256-GCM, associated data bound to the credential ID), discards the server private key and returns the server public key (`offlineServerPublicKeyPem`).
3. iOS keeps the offline key in the Secure Enclave and computes `Z` and `K` for each confirmation, inside the biometric prompt. Android agrees `K` once, from an ephemeral in-memory key pair, imports it into the Keystore as a non-exportable HMAC key that needs a biometric for every use, and wipes every other copy.

Offline confirmation is enabled per deployment with `OFFLINE_CONFIRMATION_ENABLED=true`.

### Confirming a transaction

1. The bank's screen calls `GET /v1/authorizations/{id}/offline-challenge` and shows `qrPayload` as a QR code:

   ```text
   NXS1.<base64url of the canonical authorization bytes>
   ```

2. The phone reads the QR code and applies the same strict checks as online: canonical form, every field, protocol version, and that the `credential_id` is its own and `expires_at` has not passed.
3. It shows the transaction from those bytes, asks for the biometric, and computes

   ```text
   tag  = HMAC-SHA256(K, "NEXUS-SIGN/OFFLINE-CODE/v1" || 0x00 || SHA-256(canonical bytes))
   code = RFC 4226 dynamic truncation of tag, modulo 10^8, 8 digits
   ```

4. The customer types the code on the bank's screen, which sends it to `POST /v1/authorizations/{id}/offline-confirmation`.
5. Auth Core locks the authorization row, recomputes the code, compares it in constant time and counts a wrong code as a failed attempt. Parallel submissions are therefore serialized. The fifth failure rejects the authorization: five guesses among 10^8 codes. A correct code runs the same checks as a device signature (identity, credential, adaptive verification plan) and seals evidence with `confirmationMethod: OFFLINE_CODE`.

Because the code covers the hash of the exact bytes the phone displayed, a QR code with different terms produces a different code, and the code cannot be reused for another authorization.

### What an offline code proves

> Since 2.0.0, with `OFFLINE_CONFIRMATION_MODE=deferred_signature` (default, required in production), a code alone no longer confirms: see [offline confirmation v2](offline-confirmation-v2-deferred-signature.md). This section describes v1.

An offline code proves that the enrolled device, after a biometric check, confirmed the transaction it displayed. Unlike a device signature, it is computed with a key that Auth Core also holds, so it is not independently verifiable by a third party. The evidence record says so (`confirmationMethod`, `signatureFormat: hmac`), and `scripts/verify-evidence.mjs` reports such records separately. Banks that need non-repudiation for a payment type should require online confirmation for it.

## Limits

- Without network the phone cannot learn that its credential was revoked. Auth Core rejects codes for a revoked credential or a suspended NEXUS ID, so revocation still takes effect at the moment of confirmation.
- The phone checks expiry against its own clock; Auth Core enforces the authoritative expiry.
- If the enrolment response is lost after Auth Core has registered the new keys (network failure, app killed), the phone discards the unconfirmed keys while Auth Core already holds the new credential. Nothing is signed with keys Auth Core does not know. A new `BOOTSTRAP` token for the identity is then refused with 409 `ACTIVE_CREDENTIAL_EXISTS`: the bank issues one with a [replacement authorization](../architecture/device-replacement.md) after re-identifying the customer, or the customer uses recovery.

## Test vectors

`auth-core/test-vectors/device-protocols-v1.json` (generated by `generate-device-protocol-vectors.mjs`, independently of the server code) pins the request signing input, including a percent-encoded path, and the ECDH, HKDF, HMAC and code values for fixed keys. Auth Core, the Android SDK and the iOS SDK run the same file.
