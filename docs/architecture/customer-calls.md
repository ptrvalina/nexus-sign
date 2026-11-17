# Calls the customer starts ("talk to the bank")

The customer calls the bank from the bank's app by audio or video, outside a payment check (presentation page 12). The bank's operators answer from the admin console. Code: `auth-core/src/services/customerCallService.ts`, migration `030_customer_calls.sql`, console `auth-core/public/admin/customer-calls.js`, SDK methods `requestBankCall`, `bankCalls`, `bankCall`, `customerCallSignalling` (iOS and Android).

A verification call ([adaptive verification](adaptive-verification.md)) belongs to one payment and ends with a recorded result. A customer call belongs to no payment and records no result: it is a conversation with the bank by voice or video. Both use the same WebRTC signalling relay and the same call engine in the SDKs.

## Lifecycle

```
WAITING ──operator answers──▶ CONNECTED ──either side ends / longest duration / revocation──▶ ENDED
   ├── customer stops waiting ──▶ CANCELLED
   └── nobody answers in CUSTOMER_CALL_WAIT_SECONDS, or the device or NEXUS ID is no longer active ──▶ MISSED
```

The database enforces the transitions, keeps who called, from which device, on which channel and who answered, and refuses to change a finished call or to delete any call (trigger `customer_calls_lifecycle`, `customer_calls_no_delete`). One call per NEXUS ID can be open (unique index `idx_customer_calls_open`).

## Who may do what

| Step | Who | Rule |
|---|---|---|
| Enable the channels | The platform operator, for one bank client: `node dist/cli/verificationSetup.js customer-calls <clientId> <AUDIO,VIDEO \| none>` | Off by default. Audit `customer_call_channels_changed` |
| Ask for a call | An `ACTIVE` device of an `ACTIVE` NEXUS ID, device-signed: `POST /v1/mobile/customer-calls` `{channel, topic, conversationId?}` | Channel enabled (else 409 `CALL_CHANNEL_NOT_ENABLED`); no other open call (409 `CALL_ALREADY_OPEN`); the topic is one line that passes the display rules |
| See the queue | Operators of the same bank (`operator` role or higher): `GET /admin/api/customer-calls` | Platform accounts and other banks see nothing |
| Answer | The first operator: `POST /admin/api/customer-calls/{id}/answer` | A row update `WAITING → CONNECTED`, so two operators cannot both answer (409 `CALL_NOT_WAITING` for the second); a retry by the same operator returns the call |
| Signal | The device that asked (`/v1/mobile/customer-calls/{id}/signals`) and the operator who answered (`/admin/api/customer-calls/{id}/signals`) | The device may send its offer while the call waits; the operator only after answering. Signalling order as for verification calls (only the device offers, only the operator answers, candidates after the description, nothing after bye, per-message IDs make retries safe) |
| End | Either party: `POST …/end` | `CONNECTED → ENDED` (`hung_up` by the customer, `operator_ended` by the operator) or `WAITING → CANCELLED`. The other party receives `bye` |
| Close by the server | The expiry worker and every read | Past `expiresAt` (`no_operator_answered` while waiting, `max_duration` after `CUSTOMER_CALL_MAX_SECONDS`), device revoked (`credential_revoked`), NEXUS ID suspended or revoked (`identity_not_active`). Both parties receive one `bye` from `server` |

## What the bank is told

Webhooks `customer_call.requested`, `customer_call.answered` and `customer_call.ended` carry the call (`callId`, `nexusId`, `credentialId`, `channel`, `topic`, `conversationId`, `state`, `operator`, times, `endedBy`, `endReason`, `durationSeconds`). `GET /v1/customer-calls/{callId}` returns the state for reconciliation. A `MISSED` call is the bank's cue to call the customer back.

## What is recorded, and what is not

Recorded: the call row (above) and the audit events `customer_call_requested`, `customer_call_answered`, `customer_call_ended` with the actor. Not recorded: audio, video, the SDP or ICE contents beyond the life of the call (signalling lives in Redis under `ccall:{callId}` until a minute after the call's time ends). Media goes directly between the phone and the operator's browser, or through the bank's TURN server, encrypted by WebRTC (DTLS-SRTP); Auth Core never receives it. Calls are not sealed in the evidence chain: they authorize nothing.

A call shows a person; it does not identify them. Nothing said in a customer call confirms a payment.

## Verification status

| What | How | Result |
|---|---|---|
| Lifecycle, scope, one operator, signalling rules on a real Redis (Lua script), server bye, webhooks, audit, database refusals | `test/integration/customer-calls.test.mjs` on PostgreSQL and Redis 7, services loaded directly | 4/4 passed in the review environment |
| SDK: joining a customer call and the call engine | `CustomerCallWireTest`, `VerificationCallControllerTest` on the JVM (`android-sdk/scripts/jvm-core-tests.sh`) | Passed |
| HTTP routes, the console in a browser with real media, iOS | `test/media/customer-call.test.mjs` (two browsers, DTLS-SRTP), CI jobs `auth-core / integration`, `media`, `ios-sdk` | **Not run** in the review environment (no `express`, no Xcode) |
| On a phone | Device acceptance checklist | **Not run** |
