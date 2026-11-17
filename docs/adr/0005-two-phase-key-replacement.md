# 0005. Two-phase key replacement on the device

## Status

Accepted

## Date

2026-09-30

## Context

Enrolment and recovery replace the device keys: Auth Core registers new public keys and revokes the previous credential. If the phone deletes its working keys first and the request then fails (wrong recovery phrase, network error, app killed), the customer is left without a usable credential. If the phone switches keys but records the new credential ID separately, a crash between the two writes leaves it signing with new keys under the old ID, or the reverse.

Two attempts running at the same time in one app would also share the replacement key slot.

## Decision

- Each attempt generates a complete new key set (signing, authentication, offline) next to the current one: under separate keychain tags on iOS, in a spare Keystore slot on Android (`KeySlots.kt`).
- The new keys are promoted only after Auth Core has confirmed the enrolment or recovery. On any failure the new set is deleted and the current keys are untouched.
- Android writes the active-slot pointer, the new credential ID and the request authentication mode in one `SharedPreferences.commit()` before the previous keys are deleted.
- iOS records the confirmed credential ID, the offline server key and the request authentication mode as a pending record with `replacementCommitPending`, then deletes the old keys and re-tags the new ones. If the app stops in between, the next key lookup uses the confirmed replacement keys and completes the promotion (`KeyManager.swift`).
- Enrolment and recovery are serialized per process: a `Mutex` on Android, an actor (`ReplacementGate`) on iOS.

## Consequences

- A failed re-enrolment or recovery leaves the working keys in place.
- The device never signs with keys whose credential ID it has not recorded.
- If the enrolment response is lost after Auth Core has registered the new keys, the phone discards them while Auth Core has already replaced the previous credential. The host app requests a new `BOOTSTRAP` token and enrols again; nothing is signed with keys Auth Core does not know.
- Promotion on iOS depends on keychain re-tagging of Secure Enclave keys, which can only be verified on physical devices; this has not been done yet ([device acceptance checklist](../engineering/DEVICE_ACCEPTANCE_CHECKLIST.md)).
- Covered by `KeySlotsTest` on Android. See [device authentication](../protocol/device-authentication-and-offline-confirmation.md#keys-on-the-device).

## Note

[ADR 0012](0012-explicit-device-replacement.md) changed the third consequence: a `BOOTSTRAP` token for an identity that still has a credential that is not revoked is refused with 409 `ACTIVE_CREDENTIAL_EXISTS`. After a lost enrolment response the bank backend issues the token with a replacement authorization, or the customer uses recovery. The device-side decision above is unchanged.
