# 0017. In-app audio and video verification calls

## Status

Accepted for implementation; owner approval pending for the WebRTC binaries in the SDKs (see Consequences) and for production use.

## Date

2026-10-16

## Context

Adaptive verification (PUSH → AUDIO → VIDEO) existed only as a server-side plan. The SDKs had no media, signalling or user interface, and Auth Core accepted any result the bank gateway reported (forensic inventory FI-001, FI-002). The product requires the calls inside the bank's own app, with results that Auth Core can authenticate, and a deployment inside the bank's controlled infrastructure without a third party processing media by default.

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
4. **Authorization of a call.**
   - The device may join only sessions of its own authorization and credential.
   - One operator claims a call (Redis `SET NX`, audited) and only that operator can signal and decide.
   - Calls are listed and claimable only while the session is `IN_PROGRESS`, the authorization is `PENDING_USER` and operator verification is enabled for the channel.
5. **NAT traversal.** STUN and TURN of the bank (coturn recommended). Auth Core issues TURN credentials per session with the TURN REST convention (`use-auth-secret`: username `<expiry>:<sessionId>`, HMAC-SHA1 password); they expire with the session. Without TURN, calls work only where direct connectivity exists.
6. **Outcome.**
   - An operator decision or a verified provider token closes the session.
   - A declined call (customer cancel) or an unanswered call (session expiry after 5 minutes) neither verifies nor fails. The plan returns to `PENDING`; at most three sessions per channel and authorization.
   - The device must still sign the same transaction bytes. A call never authorizes a transaction on its own.
7. **No recording.** Neither Auth Core nor the console records audio or video. Recording would be a separate decision with privacy, retention and legal review.
8. **What a call proves.** Encryption in transit (DTLS-SRTP), participant authentication (device signature, operator login) and authorization to verify (claim, channel enabled, bank scope) are each enforced. The evidence records who stated the result (`method`, `issuer`). It does not record how the person was identified: no biometric identity verification, liveness detection or synthetic-media resistance is claimed.

## Consequences

- **WebRTC library in the SDKs.** iOS and Android SDKs need a WebRTC library: Google's libwebrtc, BSD-3-Clause, distributed as prebuilt binaries by several projects. This adds about 10–20 MB to the bank app and a native dependency to the supply chain; the choice of build and its verification needs owner approval.
- **Operator capacity.** Operator verification needs staff available within the session lifetime; otherwise calls expire and the bank escalates or cancels.
- **Infrastructure.** The bank operates TURN (UDP 3478, TLS 5349) reachable from the internet, and keeps `WEBRTC_TURN_SECRET` in its secrets manager.
- **Browser support.** The operator console needs a current browser with WebRTC and a secure context (HTTPS or localhost).
- **Testing.** Real media between two Chromium instances is tested in `auth-core/test/media/webrtc-call.test.mjs` (CI job `auth-core-media`). Native SDK calls need device tests (`docs/engineering/DEVICE_ACCEPTANCE_CHECKLIST.md`).
