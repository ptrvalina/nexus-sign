# NEXUS-SIGN iOS SDK: in-app verification calls (optional)

Audio and video calls between the customer and a bank operator, when the bank's verification plan asks for one before the customer signs ([ADR 0017](../docs/adr/0017-in-app-audio-video-calls.md)). This package adds the media (libwebrtc) and a SwiftUI call screen to the core SDK ([ios-sdk](../ios-sdk/README.md)). Bank apps that do not offer calls do not need it.

> **Status:** development approval only. The WebRTC binary (`stasel/WebRTC` 153.0.0) has open provenance and licence items that block production use: [THIRD_PARTY_MEDIA.md](../docs/engineering/THIRD_PARTY_MEDIA.md). This package has not been compiled in this repository's working environment (no Swift toolchain); CI job `ios-sdk-calls` builds it. Device tests: [checklist](../docs/engineering/DEVICE_ACCEPTANCE_CHECKLIST.md).

## What a call is, and is not

- The operator sees the transaction terms (from the bytes the device will sign) and records VERIFIED or FAILED. Auth Core records who decided.
- A call never confirms a payment: after VERIFIED, `approve(authorization:)` as usual.
- Nothing is recorded; media is DTLS-SRTP between the phone and the operator's browser or the bank's TURN server.
- No identity proof, liveness detection or deepfake resistance is claimed.

## Setup

Add the package (local path or the repository) and, in the app's Info.plist, `NSMicrophoneUsageDescription` and, for video, `NSCameraUsageDescription`.

```swift
import NEXUSSign
import NEXUSSignCalls

guard await CallPermissions.request(for: .video) else { return }
let session = try await sdk.openVerificationCall(authorization: authorization, channel: .video)
let call = try VerificationCallModel(sdk: sdk, session: session, terms: try authorization.signedTransaction().confirmationText)
// present VerificationCallView(model: call), then:
call.start()
// when call.state becomes .ended(.decided(verified: true)): try await sdk.approve(authorization: authorization)
```

## Behaviour

Same state machine as Android (`VerificationCallController` in the core SDK): offer first, candidate buffering, ICE restart after a drop (at most twice), retries with the same `messageId`, endings from the server's bye or the session expiry, media released exactly once. In the background the camera stops (iOS does not allow background capture) and restarts when the app is active, unless the customer turned it off. Leaving the call screen hangs up.

Only VP8 and VP9 are negotiated for video; audio uses Opus.

## Testing

- `ios-sdk` XCTest: `VerificationCallControllerTests` (state machine; CI job `ios-sdk`).
- `ios-sdk-calls` build: CI job `ios-sdk-calls`.
- Media on a device: [device checklist](../docs/engineering/DEVICE_ACCEPTANCE_CHECKLIST.md).
