# 0017. In-app audio and video verification calls

## Status

Accepted for implementation. WebRTC binaries in the SDK call modules: development approval by the product owner on 2026-10-18 (D-015); production approval pending the open items in [THIRD_PARTY_MEDIA.md](../engineering/THIRD_PARTY_MEDIA.md).

## Date

2026-10-16

## Context

Adaptive verification (PUSH → AUDIO → VIDEO) existed only as a server-side plan. The SDKs had no media, signalling or user interface, and Auth Core accepted any result the bank gateway reported . The product requires the calls inside the bank's own app, with results that Auth Core can authenticate, and a deployment inside the bank's controlled infrastructure without a third party processing media by default.

## Decision

1. **Transport: WebRTC.** Media is encrypted by DTLS-SRTP, as negotiated by the WebRTC stacks; Auth Core never receives media. No custom media encryption.
2. **Participants.** The customer's device (the enrolled credential of the authorization) and either:
   - a bank operator in the admin console (password and TOTP login, role `operator` or higher, scoped to the bank); or
   - an external verification provider, whose result arrives as a signed token ([verification result v1](../protocol/verification-result-v1.md)).
   Which of the two a bank uses is set per channel by the Auth Core operator (`cli/verificationSetup.js`).
3. **Signalling through Auth Core.** SDP offer and answer and ICE candidates are relayed by Auth Core over HTTPS:
   - device side: `/v1/mobile/verification-sessions/{id}/signals`, device-signed like every device request;
   - operator side: `/admin/api/verification-calls/{id}/signals`, behind the admin session.
   Messages are kept in Redis only for the life of the session. A long poll (at most 20 s) avoids a WebSocket dependency and works through the existing gateway.
   Auth Core enforces the order atomically: only the device offers, and only when its previous offer is answered (so an ICE restart cannot collide with another offer); only the operator answers; candidates follow the sender's own description; nothing follows a party's bye. A retried message with the same `messageId` is relayed once (D-016).
   When the session or authorization is closed anywhere, the next long poll relays a `bye` from `server` with the reason (D-017).
4. **Authorization of a call.**
   - The device may join only sessions of its own authorization and credential.
   - One operator claims a call (Redis `SET NX`, audited) and only that operator can signal and decide.
   - Calls are listed and claimable only while the session is `IN_PROGRESS`, the authorization is `PENDING_USER` and operator verification is enabled for the channel.
5. **NAT traversal.** STUN and TURN of the bank (coturn recommended). Auth Core issues TURN credentials per session with the TURN REST convention (`use-auth-secret`: username `<expiry>:<sessionId>`, HMAC-SHA1 password); they expire with the session. Without TURN, calls work only where direct connectivity exists.
6. **Outcome.**
   - An operator decision or a verified provider token closes the session.
   - A declined call (customer cancel), an operator hanging up without a result (`release`, D-018) or an unanswered call (session expiry after 5 minutes) neither verifies nor fails. The plan returns to `PENDING`; at most three sessions per channel and authorization.
   - The device must still sign the same transaction bytes. A call never authorizes a transaction on its own.
7. **No recording.** Neither Auth Core nor the console records audio or video. Recording would be a separate decision with privacy, retention and legal review.
8. **What a call proves.** Encryption in transit (DTLS-SRTP), participant authentication (device signature, operator login) and authorization to verify (claim, channel enabled, bank scope) are each enforced. The evidence records who stated the result (`method`, `issuer`). It does not record how the person was identified: no biometric identity verification, liveness detection or synthetic-media resistance is claimed.

## Consequences

- **WebRTC library in optional modules.** The core SDKs carry no WebRTC. The call modules `android-sdk-calls` (`io.github.webrtc-sdk:android`) and `ios-sdk-calls` (`stasel/WebRTC`) link prebuilt libwebrtc from community distributions, pinned exactly. libwebrtc is BSD-3-Clause with Google's patent grant; the binaries also contain third-party components with their own licences, and codec patents (H.264) are outside the grant, so the modules negotiate only VP8/VP9. Provenance, checksums and the licence inventory are open release blockers ([THIRD_PARTY_MEDIA.md](../engineering/THIRD_PARTY_MEDIA.md)). This adds roughly 10–20 MB to a bank app that includes a module.
- **State machine in the core SDKs.** The device-side call logic (`VerificationCallController`) is in the core SDKs, identical on both platforms and testable without WebRTC; the modules implement `CallMediaEngine` with the native WebRTC APIs (D-019).
- **Operator capacity.** Operator verification needs staff available within the session lifetime; otherwise calls expire and the bank escalates or cancels.
- **Infrastructure.** The bank operates TURN (UDP 3478, TLS 5349) reachable from the internet, and keeps `WEBRTC_TURN_SECRET` in its secrets manager.
- **Browser support.** The operator console needs a current browser with WebRTC and a secure context (HTTPS or localhost).
- **Testing.** Real media between two Chromium instances, including an ICE restart and an operator hang-up, is tested in `auth-core/test/media/webrtc-call.test.mjs` (CI job `auth-core-media`). The Kotlin state machine runs against a real Auth Core with scripted media (`sdk-call-conformance`). Native media in the SDK modules needs device tests (`docs/engineering/DEVICE_ACCEPTANCE_CHECKLIST.md`).
