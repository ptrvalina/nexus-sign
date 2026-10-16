# NEXUS-SIGN iOS SDK

Native iOS SDK embedded into the bank's existing mobile application.

## Requirements

- iOS 15 or later, Swift 5.9 (Xcode 15 or later)
- Swift Package Manager: add this package and depend on the `NEXUSSign` product
- A device with a Secure Enclave. The simulator is suitable only for UI work.
- A device passcode. Since 2.0 the keys are created with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`: a device without a passcode cannot enrol, and the system deletes the keys when the passcode is removed.
- Auth Core 2.0 or later for recovery setup (recovery protocol 2).

## Public flow

1. The bank backend creates a NEXUS ID for the customer.
2. When `bootstrap()` asks for a token, the host app gets one from its own backend, which calls Auth Core `POST /v1/mobile/sessions` with `{ nexusId, purpose: "BOOTSTRAP" }`.
3. `NEXUSSignSDK.bootstrap()` requests a `BOOTSTRAP` token and creates three Secure Enclave keys: signing, request authentication and offline. One App Attest attestation covers all three. From then on the SDK signs every request with the authentication key; it holds no token.
4. The bank backend creates a transaction authorization.
5. The SDK fetches the exact authorization object and verifies it.
6. `approve()` signs the exact server-issued canonical bytes after biometric authentication.
7. Auth Core verifies the signature and consumes the authorization atomically.

## Configuration

```swift
let sdk = NEXUSSignSDK(config: NEXUSSignConfig(
    bankID: "mybank",
    baseURL: URL(string: "https://nexus-sign.mybank.example")!,
    sessionToken: { purpose in
        // Your backend authenticates the customer and calls Auth Core
        // POST /v1/mobile/sessions { "nexusId": ..., "purpose": purpose.rawValue }
        try await bankAPI.nexusToken(purpose: purpose.rawValue)
    },
    recoverySetupPromptText: NSLocalizedString("recovery.setup.prompt", comment: "")
))
```

`recoverySetupPromptText` (default `"Confirm to set up your recovery phrase"`) is the reason shown in the Face ID / Touch ID prompt of `generateRecoveryPhrase()`; localize it in the host app. `keychainAccessGroup`, `pushKeychainAccessGroup` and `requestTimeout` (default 10 s) are optional.

`certificatePins` (new in 2.0.0, FI-006) pins the public key of the host of `baseURL`: a set of `sha256/<base64 SHA-256 of the SubjectPublicKeyInfo>` strings, the same form as the Android SDK. Empty (the default) relies on the system's certificate validation only. When set, give at least two pins (the current key and a backup key kept offline) and an https URL; the system validation runs first, then a connection whose chain has none of the pinned keys is cancelled. Supported key types: P-256, P-384, RSA 2048/3072/4096. Compute a pin with:

```bash
openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

| Token purpose | Lifetime | Used by |
|---|---|---|
| `BOOTSTRAP` | 5 minutes, single use | `bootstrap()` only |

`NEXUSTokenPurpose` has only `BOOTSTRAP`, and the token provider is called only by `bootstrap()`. Every other device request is signed with the authentication key; without an enrolled device it fails with `notRegistered`. A device enrolled by an SDK before 1.2 has no authentication key and is enrolled again through a replacement `BOOTSTRAP` token. Recovery completion uses the recovery session's own access token.

`baseURL` must use HTTPS; plain HTTP is accepted only for a server on the local machine. Requests carry `User-Agent: NEXUSSign-iOS/<version>`; the version is `NEXUSSignVersion.current`.

If a device-signed request is rejected because the phone's clock is off, the SDK corrects its offset from the server time and retries once. If the Auth Core base URL has a path prefix that the gateway strips, set `DEVICE_REQUEST_PATH_PREFIX` on Auth Core.

`isRegistered()` is true only when Auth Core has confirmed the credential (after `bootstrap()` or `recoverIdentity`) and the key is still on the device. A customer who already has an enrolled device can be enrolled again only with a `BOOTSTRAP` token that the bank backend requested with a replacement authorization after re-identifying the customer; otherwise `bootstrap()` fails with `serverError(statusCode: 409, ...)` (`ACTIVE_CREDENTIAL_EXISTS`). If enrolment fails, the current keys stay in place.

## Offline confirmation

When the bank has enabled it, the customer can confirm a transaction shown as a QR code (branch, ATM, web banking) with no network on the phone:

```swift
let challenge = try sdk.readOfflineChallenge(qrPayload: scannedText)   // verifies the bytes, no network
show(challenge.transaction)                                             // same fields as online
let code = try await sdk.confirmOffline(challenge)                      // Face ID / Touch ID, then 8 digits
```

The Secure Enclave key agreement runs inside the biometric prompt that shows the transaction. Check `isOfflineConfirmationAvailable()` before offering it. See [device authentication and offline confirmation](../docs/protocol/device-authentication-and-offline-confirmation.md).

## Secure push (bank push mode NEXUS)

When the bank uses NEXUS-SIGN secure push, Auth Core sends authorization requests and the bank's messages (incoming payment, card spending) to this app through APNs. Each message is sealed for this device; Apple sees only an envelope and the generic alert text configured on Auth Core. Banks that run their own push system (push mode `BANK`) skip this section. Specification: [secure push](../docs/protocol/secure-push.md).

1. Share a keychain access group between the app and a Notification Service Extension, and pass it as `pushKeychainAccessGroup` in `NEXUSSignConfig` (the push key is stored there; the device keys stay where they are).
2. Register at every launch, after `bootstrap()` or recovery, and whenever the token changes:

   ```swift
   func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
       Task { try? await sdk.registerPush(deviceToken: deviceToken, environment: .production) }  // .development for debug builds
   }
   ```

   The first registration for a credential agrees the push key with Auth Core; later ones only update the token.

3. Open the message in the extension, so the notification shows the real text and the bank learns it was delivered:

   ```swift
   final class NotificationService: UNNotificationServiceExtension {
       private let reader = NEXUSSignPushReader(bankID: "mybank", keychainAccessGroup: "TEAMID.com.mybank.shared")

       override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
           let content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
           guard let message = try? reader.open(userInfo: request.content.userInfo) else {
               contentHandler(content)   // not a NEXUS-SIGN push, or it did not open: the generic text stays
               return
           }
           content.title = message.title
           content.body = message.body
           content.userInfo["nexusMessageId"] = message.messageId
           if let authorizationId = message.authorizationId { content.userInfo["nexusAuthorizationId"] = authorizationId }
           Task {
               try? await reader.sendReceipt(for: message, baseURL: URL(string: "https://nexus-sign.mybank.example")!)
               contentHandler(content)
           }
       }
   }
   ```

4. In the app, `openPush(userInfo:)` opens a message received in the foreground, and `fetchPushMessage(messageID:)` loads one by ID. For `.authorizationRequest`, pass `authorizationId` to `fetchAuthorization` and continue as usual: the confirmation screen comes from the signed bytes, never from the push text. `confirmPushReceipt(_:)` sends the receipt from the app.

`unregisterPush()` stops delivery to this device and deletes its push key. The push key is a device-only keychain item readable after the first unlock, so the extension can use it while the phone is locked; it is not a Secure Enclave key.

## Errors the host app should handle

| Error | Meaning / what to do |
|---|---|
| `authorizationPayloadInvalid` | The signed bytes disagree with the displayed fields, contain characters that are not allowed in displayed text, or are addressed to another device (`wrong_device`). Nothing was signed; treat as a security event. |
| `authorizationExpired` | Ask the bank backend for a new authorization. |
| `authenticationDenied` | The customer cancelled or failed Face ID / Touch ID. |
| `biometryLockedOut` | Too many failed attempts; the customer must unlock the device with the passcode first. |
| `biometryUnavailable`, `noAuthenticationMethodEnrolled` | Offer another channel or ask the customer to set up biometrics. |
| `credentialInvalidated` | The biometric enrolment changed (a finger or face was added or removed) since the device was enrolled, so the keys can no longer be used. Run recovery, or ask the bank backend for a replacement `BOOTSTRAP` token and enrol again. New in 2.0. |
| `notRegistered` | Run `bootstrap()` (or recovery) first. |
| `offlineConfirmationUnavailable` | The device was enrolled without offline confirmation; offer online confirmation. |
| `pushMessageInvalid(reason:)` | A notification did not open as a NEXUS-SIGN secure push (`no_push_key`: call `registerPush` again; `decryption_failed`: altered or for another device). Show nothing from it. |
| `invalidRecoveryPhrase` | Wrong or mistyped phrase. Detected on the device, without using a server attempt; also reported when Auth Core refuses the proof (401). |
| `serverError(statusCode:message:)` | Auth Core rejected the request, e.g. 403 when the identity is suspended. |
| `networkUnavailable` | Retry or fall back to another channel. |

The SDK contains no bank OAuth client credentials and has no customer-facing UI of its own.

Keys are created with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and are never part of a backup. The SDK's registration state lives in `UserDefaults`; if a backup is restored to another device, `isRegistered()` is false there because the keys are missing, and the app enrols the device again.

If App Attest is unavailable or fails, the SDK still sends the enrolment with the reason, and Auth Core decides according to the bank's policy (`REQUIRE_VALID_ATTESTATION`, on in production).

## Showing and signing a transaction ("what you see is what you sign")

`fetchAuthorization(authorizationID:)` parses the exact bytes the device will sign, requires them to be in canonical form (no duplicate keys, no alternative escaping, no extra or missing fields) and checks that every field of the response agrees with them. Build the confirmation screen **only** from the signed values:

```swift
let authorization = try await sdk.fetchAuthorization(authorizationID: id)
let tx = try authorization.signedTransaction()
amountLabel.text = "\(tx.formattedAmount) \(tx.currency)"   // e.g. "1250.00 PLN"
beneficiaryLabel.text = tx.beneficiaryDisplay                // e.g. "PL61109010140000071219812874 · Jan Kowalski"
referenceLabel.text = tx.transactionReference

let outcome = try await sdk.approve(authorization: authorization)
```

`approve()` re-verifies the payload, takes the expiry from the signed bytes, shows `tx.confirmationText` in the system biometric prompt and signs those same bytes. If the payload does not verify, both calls throw `NEXUSSignError.authorizationPayloadInvalid(reason:detail:)` and nothing is signed — treat it as a security event, not as a retryable network error.

Decode any NEXUS-SIGN payload your app receives from the bank backend (for example `NexusRecoverySession`) with `JSONDecoder.nexus()`: Auth Core timestamps carry milliseconds, which the default and `.iso8601` strategies reject.


Since 2.0.0 the beneficiary display and the prompt text put the account identifier first (`iban`, `account` or `account_number`), then the name, so a long name cannot push the account out of the system prompt (FI-003). Beneficiary values are at most 140 characters. Your own confirmation screen should show every beneficiary field in full and wrap rather than truncate. Format: [authorization protocol, confirmation text](../docs/protocol/authorization-protocol-v1.md#confirmation-text).

## Recovery

The SDK implements [recovery protocol 2](../docs/protocol/recovery-protocol-v2.md).

`generateRecoveryPhrase()` creates 12 BIP-39 words and a P-256 recovery key on the device, wraps the recovery private key under a key derived from the phrase, and registers the recovery public key and the wrapped key with Auth Core. Since 2.0 the customer confirms with Face ID or Touch ID (prompt text `recoverySetupPromptText`): the registration is signed with the device's signing key, and a new phrase replaces the previous one. It throws `notRegistered` before enrolment, the biometric errors above, or `credentialInvalidated`. Neither the phrase nor the recovery private key leaves the device. The SDK refuses parameters other than protocol 2, PBKDF2-HMAC-SHA256 and a 32-byte key, iterations outside 100 000–5 000 000 and a salt shorter than 16 bytes.

`recoverIdentity(session:recoveryPhrase:)` takes the `NexusRecoverySession` the bank backend received from `POST /v1/recovery/sessions`, passed on unchanged. Since 2.0 it carries `recoveryPublicKeyPem` and `wrappedRecoveryKey` next to `sessionId`, `nexusId`, `nonce`, `accessToken`, `parameters` and `expiresAt`; a session without them is refused with `serverError(statusCode: 0, ...)`. The phrase is accepted as typed or pasted (case and whitespace are normalized). The SDK opens the wrapped key with the phrase, so a wrong phrase fails on the device (`invalidRecoveryPhrase`) and uses no server attempt, then signs the recovery proof with the recovery key. It generates the replacement keys under separate keychain tags and activates them only after Auth Core confirms the recovery. A wrong phrase, a network failure or an interrupted call leaves the existing keys untouched; if the app is killed after Auth Core confirmed the recovery, the new keys are activated on next use. A recovery session allows five proofs; start a new session from the bank backend.

Phrases set up with SDK 1.4 or earlier (recovery protocol 1) are refused by Auth Core 2.0; the customer sets up a new phrase with `generateRecoveryPhrase()` while the device is still enrolled.

## Tests

`swift test` runs on macOS (the package declares `.macOS(.v12)` for this); CI runs it on every change. `SignedTransactionTests`, `DeviceProtocolTests`, `RecoveryProtocolTests` and `SecurePushTests` use the vectors in `Tests/NEXUSSignTests/Resources/` (`signed-payload-v1.json`, `device-protocols-v1.json`, `secure-push-v1.json`, `recovery-v2.json`). These are copies of `auth-core/test-vectors/`, because SwiftPM bundles only resources inside the package; `npm run generate:vectors` in `auth-core/` writes both, and `npm run test:vectors` fails when a copy differs. The PBKDF2 derivation of the recovery protocol uses CommonCrypto `CCKeyDerivationPBKDF`; `RecoveryProtocolTests` pins its output against `recovery-v2.json`.
