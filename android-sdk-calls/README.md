# NEXUS-SIGN Android SDK: in-app verification calls (optional)

Audio and video calls between the customer and a bank operator, when the bank's verification plan asks for one before the customer signs ([ADR 0017](../docs/adr/0017-in-app-audio-video-calls.md)). This module adds the media (libwebrtc) and a call screen to the core SDK ([android-sdk](../android-sdk/README.md)). Bank apps that do not offer calls do not need it.

> **Status:** development approval only. The WebRTC binary (`io.github.webrtc-sdk:android:150.7871.01`) has open provenance and licence items that block production use: [THIRD_PARTY_MEDIA.md](../docs/engineering/THIRD_PARTY_MEDIA.md). Not yet built or tested on a device in this repository's history; see the [device checklist](../docs/engineering/DEVICE_ACCEPTANCE_CHECKLIST.md).

## What a call is, and is not

- The operator sees the transaction terms (from the bytes the device will sign) and records VERIFIED or FAILED in the admin console. Auth Core records who decided (`method: OPERATOR`, `issuer: <operator>`).
- A call never confirms a payment. After VERIFIED the customer still confirms with `sdk.approve(...)`.
- Nothing is recorded. Media goes between the phone and the operator's browser (or the bank's TURN server), encrypted with DTLS-SRTP.
- No identity proof, liveness detection or deepfake resistance is claimed.

## Setup

```kotlin
// settings.gradle.kts / build.gradle.kts of the bank app
implementation("com.nexis:nexus-sign-android")
implementation("com.nexis:nexus-sign-android-calls")
```

The module's manifest adds `RECORD_AUDIO`, `CAMERA`, `MODIFY_AUDIO_SETTINGS` and `INTERNET`. Ask for them at run time right before the call:

```kotlin
val missing = CallPermissions.missing(context, VerificationChannel.VIDEO)
if (missing.isNotEmpty()) permissionLauncher.launch(missing.toTypedArray())
```

## Placing a call

```kotlin
val authorization = sdk.fetchAuthorization(id)                 // verified signed bytes
val call = VerificationCallSession.open(sdk, context, authorization, VerificationChannel.VIDEO)
callView.bind(this, call, authorization.signedTransaction().confirmationText())
call.start(this)                                              // activity = LifecycleOwner

val ended = call.controller.state.first { it is CallState.Ended } as CallState.Ended
when (val reason = ended.reason) {
    is CallEndReason.Decided -> if (reason.verified) sdk.approve(authorization, this)
    CallEndReason.OperatorLeft, CallEndReason.Expired, CallEndReason.CancelledByCustomer, CallEndReason.ConnectionLost -> { /* offer to call again (3 sessions per channel) */ }
    else -> { /* closed by Auth Core: authorization no longer pending, credential revoked, ... */ }
}
```

Which channel to use comes from the bank's backend (its policy) or from `GET /v1/mobile/authorizations/{id}/verification-plan`.

## Behaviour

| Situation | What happens |
|---|---|
| Offer and candidates | The phone always offers. Its candidates are sent after the offer; the operator's are applied after the answer |
| Network drop (DISCONNECTED for 4 s, or FAILED) | ICE restart with a new offer, at most twice; then the call ends (`ConnectionLost`) and the session is cancelled so the customer can call again |
| Short signalling outage | Polling retries with backoff until the session expiry |
| Retried message | Same `messageId`; Auth Core relays it once |
| Duplicate, stale or unexpected messages | Ignored (`ignoredMessages` counts them) |
| Operator decides | `Decided(verified)`; media released |
| Operator hangs up | `OperatorLeft`; session cancelled by Auth Core |
| Session expired / closed elsewhere | `Expired` / `Closed(reason)` from the server's bye, or locally at `expiresAt` without network |
| App in background | Camera stopped (Android does not allow background capture), restarted in the foreground unless the customer turned it off. The microphone stays on while the activity exists |
| Activity destroyed (not a rotation) | Call hung up, media released |

Camera and microphone state are in `controller.capture` and shown on the call screen at all times (red dot and text). Turning the camera off stops the capturer itself, so the system indicator goes off too.

## Codecs

Only VP8 and VP9 are negotiated for video (no H.264/H.265; see THIRD_PARTY_MEDIA.md). Audio uses libwebrtc's default (Opus).

## Testing

- `android-sdk` JVM tests: `VerificationCallControllerTest` (state machine with Auth Core's relay rules) and `CallConformanceTest` (state machine and wire format against a running Auth Core, scripted media; CI job `sdk-call-conformance`).
- CI job `android-sdk-calls` builds this module against the real AAR and records its SHA-256.
- Media on a device: [device checklist](../docs/engineering/DEVICE_ACCEPTANCE_CHECKLIST.md).
