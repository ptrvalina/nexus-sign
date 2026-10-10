# Secure push

NEXUS-SIGN can deliver push messages to the bank's own app: authorization requests, and the bank's notifications to its customers (incoming payment, card spending, account and security notices). Everything runs inside the bank's app; there is no separate app.

A bank chooses one of two push modes per bank client:

| Push mode | Package | Who sends the push | Use |
|---|---|---|---|
| `BANK` (default) | Sign | The bank's own push system | The bank already runs push. NEXUS-SIGN adds the signing layer on top: the app fetches and verifies the authorization when the bank's push arrives. Nothing in the bank's push channel changes. |
| `NEXUS` | Full Pack | Auth Core, through APNs and FCM | The bank has no push system. Auth Core sends the authorization request push itself and delivers the bank's messages with `POST /v1/push-messages`. |

The mode is set when the bank client is registered (`node dist/cli/registerClient.js <clientId> [webhookUrl] --push-mode=NEXUS`). In both modes the customer approves what the signed bytes show ([protocol v1](authorization-protocol-v1.md)), never the text of a push.

## Who can read a message

Apple, Google and the database see no message content. Each message is sealed for one device with a key only that device and Auth Core hold, before it is stored:

- APNs receives an alert with the bank's generic text (`PUSH_ALERT_TITLE`, for example "New message") and the sealed envelope. The app's notification service extension decrypts the envelope and replaces the text before the notification is shown.
- FCM receives a data-only message holding the sealed envelope. The app decrypts it and shows the notification itself. The NEXUS-SIGN SDKs contain no Firebase code; FCM is only the transport Android offers for waking an app.
- The message category is not sent to either provider. Authorization requests are recognisable to the providers only by their collapse identifier and their short expiry.
- The `push_messages` table holds the envelope, never the plaintext. A database administrator sees which customer received a message, when, its category and, for an authorization request, its authorization ID, but not what it said.

Auth Core itself can decrypt any message: it holds every push key, encrypted with `DEVICE_SECRET_ENCRYPTION_KEY` from the bank's secrets manager. The bank backend sends the plaintext to Auth Core over its mTLS connection, so the bank and Auth Core (which runs in the bank's infrastructure) are the only places the text exists outside the phone.

## Push key

Agreed once per device credential, when the app registers for push (`POST /v1/mobile/push-registration`, signed by the device's authentication key):

1. The SDK generates an ephemeral P-256 key pair in memory and sends the public key (`devicePublicKeyPem`) with the APNs or FCM token.
2. Auth Core generates its own ephemeral key pair, computes the ECDH shared secret `Z` (the 32-byte x coordinate) and derives

   ```text
   K = HKDF-SHA256(IKM = Z, salt = "NEXUS-SIGN/PUSH/v1", info = credential ID, L = 32)
   ```

   It stores `K` encrypted with `DEVICE_SECRET_ENCRYPTION_KEY` (AES-256-GCM, associated data `device:push:<credential ID>`), discards both private keys and returns its public key (`serverPublicKeyPem`).
3. The SDK derives the same `K` and stores it:
   - iOS: a device-only keychain item (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, never synced or backed up) in the keychain access group the app shares with its notification service extension. The Secure Enclave holds only asymmetric keys, so `K` is protected by the data-protection keychain rather than the Secure Enclave.
   - Android: imported into the Android Keystore twice, as a decrypt-only AES-GCM key and as an HMAC key for receipts. The SDK keeps no copy of the bytes after the import.

   Neither requires the phone to be unlocked: a message arriving on a locked phone can be shown and confirmed, as the platform's lock-screen settings allow.

Both sides name the key with

```text
keyId = b64url(first 16 bytes of HMAC-SHA256(K, "NEXUS-SIGN/PUSH-KEY-ID/v1"))
```

Auth Core returns `keyId` with the agreement, and the SDK stores the key only if its own `keyId` is the same. A later token refresh sends only the token and `keyId`; Auth Core updates the token only when the IDs match, and answers 409 otherwise, for example when the answer to an earlier agreement was lost. The SDK then deletes its key and agrees a new one. It never keeps a key while an agreement is in progress, and runs one registration at a time.

A new credential (re-enrolment, recovery) needs a new key, because `K` is bound to the credential ID; the SDKs agree one automatically when `registerPush` finds no key for the current credential. A new agreement fails the messages still queued under the previous key (`PUSH_KEY_REPLACED`). Revoking a credential, re-enrolment, recovery and revoking the NEXUS ID delete the old credential's registration in the same transaction.

The APNs registration is accepted only for an iOS credential and FCM only for an Android one. A bank client in push mode `BANK` gets 403.

## Envelope

```text
AAD = "NEXUS-SIGN/PUSH/v1" "\n" messageId "\n" credentialId        (UTF-8)
ct  = AES-256-GCM(K, IV = 12 random bytes, AAD, plaintext) || 16-byte tag

envelope = { "v": 1, "id": messageId, "cid": credentialId, "iv": b64url(IV), "ct": b64url(ct) }
```

The plaintext is UTF-8 JSON:

| Field | Content |
|---|---|
| `v` | `1` |
| `category` | `AUTHORIZATION_REQUEST`, `INCOMING_PAYMENT`, `OUTGOING_PAYMENT`, `CARD_TRANSACTION`, `ACCOUNT`, `SECURITY`, `GENERAL` |
| `title` | 1 to 120 characters |
| `body` | Up to 600 characters; line breaks allowed |
| `authorizationId` | For `AUTHORIZATION_REQUEST`: the authorization the app fetches and verifies; otherwise `null` |
| `data` | Up to 16 string fields for the app (account ID, screen name); keys `^[A-Za-z][A-Za-z0-9_]{0,31}$`, values up to 256 characters |
| `sentAt` | RFC 3339 time the message was sealed |

Auth Core refuses a title or body with control, format (bidi, zero-width) or separator characters, other than line breaks in the body, and any plaintext over 2048 bytes; the SDKs check the text again before showing it. The largest allowed message stays inside the 4 KB APNs and FCM payload limits.

Where the envelope travels:

- APNs: `{"aps": {"alert": {...}, "mutable-content": 1, "sound": "default"}, "nexus": <envelope>}` with `apns-push-type: alert`, `apns-priority: 10`, `apns-expiration` set to the message expiry, `apns-id` set to the message ID.
- FCM HTTP v1: `data: {"nexus": "<envelope as JSON text>"}`, `android.priority: HIGH`, `android.ttl` until the message expiry.
- `GET /v1/mobile/push-messages/{id}` returns it to the device, for when the app opens before the push arrives.

## Delivery receipt

After decrypting, the device proves it with

```text
receipt = b64url(HMAC-SHA256(K, "NEXUS-SIGN/PUSH-RECEIPT/v1" "\n" messageId "\n" credentialId))
```

sent to `POST /v1/push-receipts/{messageId}` with `{credentialId, receipt}`. The receipt is its own authentication: only the device and Auth Core hold `K`. This lets the iOS notification service extension and the Android messaging service confirm delivery while the phone is locked, when the request-signing key cannot be used. Auth Core accepts it only for an `ACTIVE` credential and compares in constant time; an unknown message, an unknown credential and a wrong receipt get the same 404 after the same work. A source address with 100 failed receipts in 5 minutes is refused for 15 minutes (429).

The receipt covers the message ID, not the ciphertext: `DELIVERED` means that the holder of the device's push key acknowledged that message.

## Message lifecycle

```text
QUEUED ──provider accepts──> SENT ──receipt──> DELIVERED
   │                            │
   └─ invalid token, rejected,  └─ (authorization request only) no receipt within
      retries used up, expired      pushTimeoutSeconds: push.timeout webhook
          ──> FAILED / EXPIRED
```

| Status | Meaning |
|---|---|
| `QUEUED` | Waiting for APNs or FCM. Retried after 5 s, 30 s, 2 min, 10 min and 30 min on temporary errors (429, 5xx, network), never past the expiry. |
| `SENT` | Accepted by the provider. Not yet seen by the device. |
| `DELIVERED` | The device decrypted the message and sent its receipt. |
| `FAILED` | Final: no push registration, the token was rejected (the registration is retired), the provider rejected the message, the retries were used up, or the device's key was replaced or cannot be read. |
| `EXPIRED` | Final: not handed to the provider before it expired, including when the next retry would come after the expiry. |

A receipt can arrive while the message is still `QUEUED` (the app fetched it directly); it is then `DELIVERED` as well.

Messages expire after `PUSH_MESSAGE_TTL_SECONDS` (default 24 h, at most 28 days) or the `ttlSeconds` the bank gives, whichever is shorter. An authorization request push expires with its authorization.

## Authorization requests in push mode NEXUS

`POST /v1/authorizations` queues the push in the same database transaction as the authorization: there is no authorization without its push and no push for a rolled-back authorization. The text is the bank's `pushNotification.title` and `.body`, or `PUSH_AUTHORIZATION_TITLE` and `PUSH_AUTHORIZATION_BODY`. It only invites the customer to open the app, where the SDK fetches the authorization and shows it from the signed bytes. The response carries `push.messageId` and `push.status`.

A push that cannot be sent never blocks the authorization. It is recorded as `FAILED` and the bank receives `push.failed` at once, so it can use another channel (an SMS inviting the customer to open the app, or the offline code at a branch): `NO_PUSH_REGISTRATION` when the device has not registered for push, `PUSH_KEY_UNAVAILABLE` when its push key cannot be read, `PUSH_DELIVERY_DISABLED` when `PUSH_DELIVERY_ENABLED` is off.

When the provider accepted the push but the device has not sent a receipt within the plan's `pushTimeoutSeconds`, the bank receives `push.timeout`, provided the authorization can still be approved (`PENDING_USER`, not expired) and its plan is still at the PUSH step. The bank decides what follows: escalate with `PUSH_TIMEOUT`, offer the offline code, or cancel. Auth Core does not escalate on its own, because the risk decision stays with the bank.

APNs and FCM collapse authorization request pushes (`nexus-authorization`), so a newer request replaces an older one on the device.

## Webhooks

Sent to the bank client's webhook, in the same transaction as the state change ([integration guide](../integration/bank-backend-guide.md)):

| Event | Payload |
|---|---|
| `push.delivered` | `messageId`, `nexusId`, `category`, `authorizationId`, `deliveredAt` |
| `push.failed` | `messageId`, `nexusId`, `category`, `authorizationId`, `reason`: `NO_PUSH_REGISTRATION`, `NO_ACTIVE_REGISTRATION`, `PUSH_KEY_REPLACED`, `PUSH_KEY_UNAVAILABLE`, `PUSH_DELIVERY_DISABLED`, `DEVICE_TOKEN_INVALID`, `REJECTED`, `RETRIES_EXHAUSTED`, `PROVIDER_NOT_CONFIGURED`, `EXPIRED` |
| `push.timeout` | `messageId`, `nexusId`, `authorizationId`, `sentAt` |

## Configuration

`PUSH_DELIVERY_ENABLED=true` starts the push worker. It requires `DEVICE_SECRET_ENCRYPTION_KEY` and at least one provider:

- APNs: `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_PRIVATE_KEY_PEM` (the `.p8` auth key's text) and `APNS_TOPIC` (the app's bundle ID). Token-based authentication; one provider token is reused for 50 minutes.
- FCM: `FCM_PROJECT_ID` and `FCM_SERVICE_ACCOUNT_JSON` (a service account allowed to send to the project).

Startup refuses a partly configured provider. All settings: [configuration reference](../operations/configuration.md).

## In the app

- iOS: `registerPush(deviceToken:environment:)` from `didRegisterForRemoteNotificationsWithDeviceToken`; a notification service extension with `NEXUSSignPushReader` that opens the message, replaces the text and sends the receipt; `openPush(userInfo:)` and `fetchPushMessage(messageID:)` in the app. See the [iOS SDK guide](../../ios-sdk/README.md).
- Android: `registerPush(fcmToken)` from `onNewToken`; `openPush(remoteMessage.data)` and `confirmPushReceipt` in `onMessageReceived`, then the app shows the notification. See the [Android SDK guide](../../android-sdk/README.md).

For `AUTHORIZATION_REQUEST` the app passes `authorizationId` to `fetchAuthorization` and continues as for any authorization.

## Limits

- The push key is not held in the Secure Enclave on iOS (see above). Someone who can read the app's keychain on an unlocked, compromised device can read that device's messages; the signing key, which approves payments, is unaffected.
- `DELIVERED` means the SDK decrypted the message, not that the customer read it.
- Apple and Google see that a message was sent to a device, when, and its size.
- A message sealed before a re-enrolment cannot be opened by the new credential; it fails or expires.
- Without `DEVICE_SECRET_ENCRYPTION_KEY` the push keys cannot be decrypted; every device has to register for push again.

## Test vectors

`auth-core/test-vectors/secure-push-v1.json` (generated by `generate-secure-push-vectors.mjs`, independently of the server code) pins the key agreement and key ID, three sealed messages with their receipts, and seven envelopes a device must refuse. Auth Core, the iOS SDK and the Android SDK run the same file.
