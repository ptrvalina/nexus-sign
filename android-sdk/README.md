# NEXUS-SIGN Android SDK

Native Android SDK embedded into the bank's existing mobile application.

## Requirements

- Android 9 (API 28) or later; compile SDK 34; Java 17
- Kotlin library module `com.nexis.nexussign`
- StrongBox is used when present; if StrongBox key generation fails, the SDK falls back to a TEE-backed key. Auth Core takes the security level from the key attestation, not from the SDK's report, and applies `ANDROID_KEY_SECURITY_POLICY`: under `REQUIRE_STRONGBOX` a device whose keys end up in the TEE cannot enrol.
- A secure lock screen (PIN, pattern or password). Since 2.0 enrolment and recovery are refused without one (`KeyguardManager.isDeviceSecure`), with `NoAuthenticationMethodEnrolled`.
- Auth Core 2.0 or later. Auth Core 2.0 in production refuses Android enrolment and recovery from SDK 1.4, which sends no key attestation.

## Public flow

1. The bank backend creates a NEXUS ID for the customer.
2. When `bootstrap()` asks for a token, the host app gets one from its own backend, which calls Auth Core `POST /v1/mobile/sessions` with `{ nexusId, purpose: "BOOTSTRAP" }`.
3. `NEXUSSignSDK.bootstrap()` requests a `BOOTSTRAP` token and creates the signing and request-authentication keys in the Keystore, plus the key material for offline confirmation. One Play Integrity token covers all of them. The signing and authentication keys are generated with a Keystore attestation challenge derived from the enrolment challenge, and their attestation chains are sent automatically (`keyAttestation`); the host app does nothing for this ([Android key attestation](../docs/security/attestation.md#android-key-attestation)). From then on the SDK signs every request with the authentication key; it holds no token.
4. The host app sends the credential ID and `signingKeyFingerprint()` (the SHA-256 of the signing key, computed on the device) to its own backend, which approves exactly that key for the customer before it executes anything confirmed with it; the same after replacement and recovery ([bank credential trust](../docs/protocol/bank-credential-trust-v1.md)).
5. The bank backend creates a transaction authorization.
6. The SDK fetches the exact authorization object and verifies it.
7. `approve()` signs the exact server-issued canonical bytes after biometric authentication.
8. Auth Core verifies the signature and consumes the authorization atomically. The bank executes only after its own check of the evidence.

## Configuration

```kotlin
val sdk = NEXUSSignSDK(context, NEXUSSignConfig(
    bankId = "mybank",
    baseUrl = "https://nexus-sign.mybank.example",
    sessionTokenProvider = { purpose ->
        // Your backend authenticates the customer and calls Auth Core
        // POST /v1/mobile/sessions { "nexusId": ..., "purpose": purpose.name }
        bankApi.nexusToken(purpose.name)
    },
    playIntegrityCloudProjectNumber = 123456789012,
    promptTitle = getString(R.string.confirm_payment),
    promptCancelText = getString(R.string.cancel),
    recoverySetupPromptText = getString(R.string.confirm_recovery_phrase),
))
```

| Parameter | Default | Meaning |
|---|---|---|
| `recoverySetupPromptText` | `"Confirm your new recovery phrase"` | Description of the biometric prompt shown by `generateRecoveryPhrase()`. New in 2.0 |
| `allowEmulatorHostHttp` | `false` | Development only: accept `http://10.0.2.2`, the emulator's alias for the developer's machine. New in 2.0; leave it off in release builds |
| `requestTimeoutMillis` | `10_000` | Network request timeout |
| `certificatePins` | empty | Public-key pins for the host of `baseUrl`, `sha256/<base64 SHA-256 of the SubjectPublicKeyInfo>` (OkHttp `CertificatePinner`). Empty relies on the platform's certificate validation only. When set: at least two distinct pins (current key and a backup key kept offline), https only; a chain matching none of them fails the request. New in 2.0.0 (FI-006) |
| `playIntegrityCloudProjectNumber` | `null` | The bank's Google Cloud project number for Play Integrity; without it no integrity token is sent |

| Token purpose | Lifetime | Used by |
|---|---|---|
| `BOOTSTRAP` | 5 minutes, single use | `bootstrap()` only |

`NEXUSTokenPurpose` has only `BOOTSTRAP`, and the token provider is called only by `bootstrap()`. Every other device request is signed with the authentication key; without an enrolled device it fails with `NEXUSSignError.NotRegistered`. A device enrolled by an SDK before 1.2 has no authentication key and is enrolled again through a replacement `BOOTSTRAP` token. Recovery completion uses the recovery session's own access token.

`baseUrl` must use HTTPS; plain HTTP is accepted only for a server on the device itself (`localhost`, `127.0.0.1`) or, with `allowEmulatorHostHttp = true`, the emulator host (`10.0.2.2`). Requests carry `User-Agent: NEXUSSign-Android/<version>`; the version is `NEXUS_SIGN_SDK_VERSION`.

If a device-signed request is rejected because the phone's clock is off, the SDK corrects its offset from the server time and retries once. If the Auth Core base URL has a path prefix that the gateway strips, set `DEVICE_REQUEST_PATH_PREFIX` on Auth Core.

`isRegistered()` is true only when Auth Core has confirmed the credential (after `bootstrap()` or `recoverIdentity`) and the key is still in the Keystore. A customer who already has an enrolled device can be enrolled again only with a `BOOTSTRAP` token that the bank backend requested with a replacement authorization after re-identifying the customer; otherwise `bootstrap()` fails with `ServerError(409, ...)` (`ACTIVE_CREDENTIAL_EXISTS`). If enrolment fails, the current keys stay in place.

## Audio and video verification calls

When the bank's verification plan asks for an AUDIO or VIDEO step, the customer talks to a bank operator in the app before signing ([ADR 0017](../docs/adr/0017-in-app-audio-video-calls.md)). This SDK opens the session (`openVerificationCall`), signs the signalling (`callSignalling`) and runs the call state machine (`VerificationCallController`); the media, permissions and call screen are in the optional module [android-sdk-calls](../android-sdk-calls/README.md). The call never confirms the payment: after the operator's VERIFIED, call `approve` as usual.

## Offline confirmation

When the bank has enabled it, the customer can confirm a transaction shown as a QR code (branch, ATM, web banking) with no network on the phone:

```kotlin
val challenge = sdk.readOfflineChallenge(scannedText)        // verifies the bytes, no network
show(challenge.transaction)                                   // same fields as online
val code = sdk.confirmOffline(challenge, activity)            // biometric prompt(s), then 8 digits

// Offline confirmation v2: whenever the app starts and when the connection returns
lifecycleScope.launch { sdk.submitPendingOfflineSignatures() }
```

With a `NXS2.` QR code (`challenge.requiresDeviceSignature`, the default on Auth Core 2.0.0) the SDK first signs the transaction with the signing key — its own biometric prompt, because Android binds a key to one prompt — and stores the signature, then shows the second prompt for the code. Auth Core confirms the payment when the signature arrives; `submitPendingOfflineSignatures()` uploads what is pending and keeps what could not be delivered ([offline confirmation v2](../docs/protocol/offline-confirmation-v2-deferred-signature.md)). Pending signatures are kept in `com.nexis.nexussign.<bankId>.offline`; exclude it from backup like the keys file.

The offline key is an HMAC key in the Keystore that can only be used through the `BiometricPrompt` showing the transaction (`CryptoObject(Mac)`); it works from Android 9. Check `isOfflineConfirmationAvailable()` before offering it. See [docs/architecture/device-authentication-and-offline-confirmation.md](../docs/protocol/device-authentication-and-offline-confirmation.md).

The SDK contains no bank OAuth client credentials and has no customer-facing UI of its own; the biometric prompt texts come from the host app.

Keystore keys never leave the device. The SDK keeps its registration state in the shared preferences file `com.nexis.nexussign.<bankId>.keys`; exclude it from Auto Backup and device-to-device transfer in the app's `data_extraction_rules.xml`, so that a restored app does not carry a registration without its keys.

If Play Integrity is not configured or fails, the SDK still sends the enrolment with the reason, and Auth Core decides according to the bank's policy (`REQUIRE_VALID_ATTESTATION`, on in production).

## Secure push (bank push mode NEXUS)

When the bank uses NEXUS-SIGN secure push, Auth Core sends authorization requests and the bank's messages (incoming payment, card spending) to this app through FCM. Each message is sealed for this device and sent as data only; Google sees only the envelope. The SDK has no Firebase dependency: the app keeps its own `FirebaseMessagingService` and hands the data to the SDK. Banks that run their own push system (push mode `BANK`) skip this section. Specification: [docs/architecture/secure-push.md](../docs/protocol/secure-push.md).

```kotlin
class BankMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        // Also call at every launch and after bootstrap() or recovery.
        scope.launch { runCatching { sdk.registerPush(token) } }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val push = runCatching { sdk.openPush(message.data) }.getOrNull() ?: return  // not a NEXUS-SIGN push, or it did not open
        showNotification(push.title, push.body, push.messageId, push.authorizationId)
        scope.launch { runCatching { sdk.confirmPushReceipt(push) } }
    }
}
```

The first registration for a credential agrees the push key with Auth Core; later ones only update the token. The key is imported into the Keystore (a decrypt-only AES-GCM key and an HMAC key for receipts) and works while the phone is locked. For `AUTHORIZATION_REQUEST`, pass `authorizationId` to `fetchAuthorization` when the customer opens the notification: the confirmation screen comes from the signed bytes, never from the push text. `fetchPushMessage(messageId)` loads a message by ID; `unregisterPush()` stops delivery and deletes the key.

## Errors the host app should handle

| Error | Meaning / what to do |
|---|---|
| `AuthorizationPayloadInvalid` | The signed bytes disagree with the displayed fields, contain characters that are not allowed in displayed text, or are addressed to another device (`wrong_device`). Nothing was signed; treat as a security event. |
| `AuthorizationExpired` | Ask the bank backend for a new authorization. |
| `AuthenticationDenied` | The customer cancelled or failed the biometric prompt. |
| `BiometryLockedOut` | Too many failed attempts; the customer must unlock the device first. |
| `BiometryUnavailable`, `NoAuthenticationMethodEnrolled` | Offer another channel or ask the customer to set up a secure lock screen and enrol a strong biometric. |
| `CredentialInvalidated` | The biometric enrolment changed, so Android invalidated the key; the SDK deleted it. Run recovery, or ask the bank backend for a replacement `BOOTSTRAP` token and enrol again. |
| `NotRegistered` | Run `bootstrap()` (or recovery) first. |
| `OfflineConfirmationUnavailable` | The device was enrolled without offline confirmation; offer online confirmation. |
| `PushMessageInvalid` | A message did not open as a NEXUS-SIGN secure push (`no_push_key`: call `registerPush` again; `decryption_failed`: altered or for another device). Show nothing from it. |
| `DeviceLocked` | A request was made while the device was locked (e.g. from a push); retry once it is unlocked. |
| `InvalidRecoveryPhrase` | Wrong or mistyped phrase. Detected on the device, without using a server attempt; also reported when Auth Core refuses the proof (401). |
| `ServerError` | Auth Core rejected the request, e.g. 403 when the identity is suspended. |
| `NetworkUnavailable` | Retry or fall back to another channel. |

## Showing and signing a transaction ("what you see is what you sign")

`fetchAuthorization(id)` parses the exact bytes the device will sign, requires them to be in canonical form (no duplicate keys, no alternative escaping, no extra or missing fields) and checks that every field of the response agrees with them. Build the confirmation screen **only** from the signed values:

```kotlin
val authorization = sdk.fetchAuthorization(id)
val tx = authorization.signedTransaction()
amountView.text = "${tx.formattedAmount()} ${tx.currency}"   // e.g. "1250.00 PLN"
beneficiaryView.text = tx.beneficiaryDisplay()                // e.g. "PL61109010140000071219812874 · Jan Kowalski"
referenceView.text = tx.transactionReference

val outcome = sdk.approve(authorization, activity)
```

`approve()` re-verifies the payload, takes the expiry from the signed bytes, shows `tx.confirmationText()` as the `BiometricPrompt` description (with explicit confirmation required) and signs those same bytes. It switches to the main thread for the prompt itself, so it can be called from any coroutine scope tied to the activity. If the payload does not verify, both calls throw `NEXUSSignError.AuthorizationPayloadInvalid` and nothing is signed — treat it as a security event, not as a retryable network error.


Since 2.0.0 the beneficiary display and the prompt text put the account identifier first (`iban`, `account` or `account_number`), then the name, so a long name cannot push the account out of the system prompt (FI-003). Beneficiary values are at most 140 characters. Your own confirmation screen should show every beneficiary field in full and wrap rather than truncate. Format: [authorization protocol, confirmation text](../docs/protocol/authorization-protocol-v1.md#confirmation-text).

## Recovery

The SDK implements [recovery protocol 2](../docs/protocol/recovery-protocol-v2.md).

```kotlin
val words = sdk.generateRecoveryPhrase(activity)   // biometric prompt, then show the 12 words
```

`generateRecoveryPhrase(activity: FragmentActivity)` creates 12 BIP-39 words and a P-256 recovery key on the device, wraps the recovery private key under a key derived from the phrase, and registers the recovery public key and the wrapped key with Auth Core. Since 2.0 it takes an activity: the customer confirms with a `BiometricPrompt` (description `recoverySetupPromptText`), because the registration is signed with the device's signing key and a new phrase replaces the previous one. It throws `NotRegistered` before enrolment, the biometric errors above, or `CredentialInvalidated`. Neither the phrase nor the recovery private key leaves the device. The SDK refuses parameters other than protocol 2, PBKDF2-HMAC-SHA256 and a 32-byte key, iterations outside 100 000–5 000 000 and a salt shorter than 16 bytes.

`recoverIdentity(session, recoveryPhrase)` takes the `NexusRecoverySession` the bank backend received from `POST /v1/recovery/sessions`, passed on unchanged. Since 2.0 it carries `recoveryPublicKeyPem` and `wrappedRecoveryKey` next to `sessionId`, `nexusId`, `nonce`, `accessToken`, `parameters` and `expiresAt`; a session without them is refused with `ServerError(0, ...)`. The phrase is accepted as typed or pasted (case and whitespace are normalized). The SDK opens the wrapped key with the phrase, so a wrong phrase fails on the device (`InvalidRecoveryPhrase`) and uses no server attempt, then signs the recovery proof with the recovery key. It generates the replacement keys in a spare Keystore slot, with key attestation bound to the session nonce, and switches the active slot only after Auth Core confirms the recovery. A wrong phrase, a network failure or an interrupted call leaves the existing keys untouched. A recovery session allows five proofs; start a new session from the bank backend.

Phrases set up with SDK 1.4 or earlier (recovery protocol 1) are refused by Auth Core 2.0; the customer sets up a new phrase with `generateRecoveryPhrase` while the device is still enrolled.

## Tests

```bash
./gradlew testDebugUnitTest assembleRelease
```

All unit tests are plain JVM tests. `SignedTransactionTest`, `DeviceProtocolTest`, `RecoveryProtocolTest` and `SecurePushTest` are driven by `signed-payload-v1.json`, `device-protocols-v1.json`, `recovery-v2.json` and `secure-push-v1.json`, read directly from `auth-core/test-vectors/` (Gradle test resources `srcDir("../auth-core/test-vectors")`), so the tests need a full repository checkout. `NEXUSSignConfigTest` covers the base URL rules, including `allowEmulatorHostHttp`. `RecoveryPhraseTest` checks the BIP-39 encoding against the reference vectors and the input normalization; `KeySlotsTest` covers the two-slot key replacement used by enrolment and recovery.
