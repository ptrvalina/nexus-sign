# 0008. Secure push delivery with per-device sealed messages

## Status

Accepted

## Date

2026-10-01

## Context

Banks that already run a push system use NEXUS-SIGN as a signing layer: their push wakes the app, which fetches and verifies the authorization. Banks without a push system need NEXUS-SIGN to deliver authorization requests, and their customers expect the usual notifications in the bank's app (incoming payments, card spending), with the full text.

Apple and Google are the only way to wake an app on iOS and Android, so a push has to pass through APNs or FCM. A bank cannot accept that either of them, or anyone with access to Auth Core's database, reads its customers' transaction notifications.

## Decision

- A push mode per bank client: `BANK` (default; the bank's push system, nothing changes) or `NEXUS` (Auth Core delivers through APNs and FCM).
- At push registration the device and Auth Core agree a 32-byte push key over ECDH P-256 with ephemeral keys on both sides: `K = HKDF-SHA256(Z, salt "NEXUS-SIGN/PUSH/v1", info credential ID, 32 bytes)`. Auth Core stores `K` encrypted with `DEVICE_SECRET_ENCRYPTION_KEY`; iOS keeps it as a device-only keychain item readable after first unlock, shared with the notification service extension; Android imports it into the Keystore as a decrypt-only AES-GCM key and an HMAC key.
- Every message is sealed with AES-256-GCM under `K`, with the message and credential IDs as associated data, before it is stored. Providers receive only the envelope: a generic alert text for APNs (replaced by the extension after decrypting) and data-only messages for FCM. The category is not sent.
- Delivery is confirmed by a receipt `HMAC-SHA256(K, "NEXUS-SIGN/PUSH-RECEIPT/v1\nmessageId\ncredentialId")`, accepted without other authentication, so the extension can confirm while the phone is locked. Failed receipts are throttled per source address.
- Both sides name the key with a key ID derived from `K`. A token refresh carries it and is refused when Auth Core holds another key, so a device and Auth Core that ended up with different keys (a lost answer, concurrent registrations) recover by agreeing a new one. The SDKs run one registration at a time and keep no key while an agreement is in progress.
- An outbox (`push_messages`) and a worker deliver with retries until the message expires. The bank learns the outcome through `push.delivered`, `push.failed` and, for authorization requests without a receipt within `pushTimeoutSeconds`, `push.timeout`. Auth Core does not escalate verification on its own.
- In push mode `NEXUS` the authorization request push is queued in the transaction that creates the authorization. Its text only invites the customer to open the app.
- The SDKs contain no Firebase or APNs client code beyond receiving the token and the payload the platform hands to the app.

## Consequences

- Apple, Google and database administrators cannot read message content. They can see that a device received a message, when, and its size; providers can tell authorization requests from other messages by their collapse identifier and short expiry, and the database holds the category in clear. Auth Core holds the push keys and can decrypt.
- On iOS the push key is protected by the data-protection keychain, not by the Secure Enclave, because the Secure Enclave holds no symmetric keys and the extension must work without user interaction. A compromise of the unlocked device exposes its messages, not its signing key.
- The receipt proves that the SDK decrypted the message, not that the customer read it.
- Re-enrolment and recovery need a new push registration; the SDKs agree a new key when they find none for the current credential.
- Losing `DEVICE_SECRET_ENCRYPTION_KEY` makes every push registration unusable, as it does for offline keys.
- Shared vectors: `auth-core/test-vectors/secure-push-v1.json`. Specification: [secure push](../protocol/secure-push.md).
