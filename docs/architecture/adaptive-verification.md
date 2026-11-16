# Adaptive verification and escalation

The bank can require additional verification factors before an authorization may be signed. The cryptographic signature always remains the final proof of intent. Audio and video checks are additional factors: they never replace the signature and are never a standalone authorization method.

## Verification paths

| Level | Path |
|---|---|
| Standard | Push / in-app confirmation → biometric unlock → cryptographic signature |
| Elevated | Push → audio verification → cryptographic signature |
| High | Push → audio verification → video verification → cryptographic signature |
| Push not delivered | Delivery timeout → audio → video (if required by policy) → cryptographic signature |

## Escalation triggers

- push not delivered, or delivery unknown after the configured timeout;
- amount above the bank's policy threshold;
- a decision of the bank's risk or policy engine;
- a customer request for additional confirmation;
- failure of a previous verification channel.

## Plan model

Auth Core creates a verification plan in the same database transaction as the authorization, from the bank's `verificationPolicy` in `POST /v1/authorizations`:

| Policy field | Effect |
|---|---|
| `requireAudio`, `requireVideo` | Minimum factor for this authorization |
| `highAmountThresholdMinor` | Amounts at or above it require at least AUDIO |
| `audioAvailable`, `videoAvailable` | `false` leaves the channel out for this authorization. A channel is available only if the bank can verify it: a provider key registered for it or operator verification enabled for it (`cli/verificationSetup.js`). A requirement no available channel meets is refused (409 `VERIFICATION_CHANNEL_UNAVAILABLE`). |
| `pushTimeoutSeconds` | 10–300 s, default 30 |
| `clientEscalationAllowed` | Whether the customer may ask for a stronger check from the app |

The plan has two pointers:

- `requiredStep` is the strongest factor that must be completed before the device signature is accepted. It can only be raised.
- `currentStep` is the factor to perform next. Factors run in the order PUSH → AUDIO → VIDEO; a channel the bank has not enabled is skipped.

Transitions:

| Event | Result |
|---|---|
| Valid device signature on a PUSH-level plan | Plan `VERIFIED`; PUSH is satisfied by the signature itself |
| AUDIO or VIDEO session completed with `VERIFIED` | Next factor becomes current, or the plan becomes `VERIFIED` once `requiredStep` is reached |
| AUDIO fails and VIDEO is enabled | Escalated to VIDEO (`CHANNEL_FAILURE`) |
| The last available factor fails | Plan `FAILED`, authorization `REJECTED` |
| Escalation (`PUSH_TIMEOUT`, `RISK_POLICY`, `CLIENT_REQUEST`, …) | `requiredStep` raised; a request for the same or a weaker step returns 409 |
| Signature while the plan is not `VERIFIED` | Signature refused, authorization stays pending |

Only one session per authorization is open at a time; opening a new one supersedes the previous one. Sessions expire after five minutes and are single-use.

## Invariants

1. The bank's risk engine is the authoritative source for escalation decisions.
2. The level can only increase. An idempotent replay of the create request returns the original plan, even if it carries a weaker policy.
3. The client cannot select a weaker path for itself.
4. An audio or video session is bound to the `authorization_id`, NEXUS ID, policy version and a one-time nonce.
5. Audio and video results are accepted only as a provider result token that Auth Core verifies itself ([verification result v1](../protocol/verification-result-v1.md)), or as the decision of an authenticated bank operator in the admin console. The bank gateway only relays tokens; neither it nor the mobile client can report a session as verified.
6. Sessions have a short TTL and are single-use.
7. After any additional verification, the device must still sign the same canonical payload.
8. A bank commit is allowed only for a `VERIFIED` authorization.
9. Evidence records the verification factors and their hashes; raw media is not required to be stored in NEXUS-SIGN.

## Media privacy

Raw audio and video belong to a separate, bank-controlled data domain. By default NEXUS-SIGN stores only minimal evidence: provider reference, channel, result, timestamps and the SHA-256 hash of the provider assertion. Recordings are retained only under a separate bank retention and access policy.

## Threat model

The design addresses voice cloning, deepfakes, replay, media injection, provider compromise, session hijacking, notification abuse, downgrade attacks, operator misuse and leakage of recordings. The mitigations are short-lived sessions, nonce binding, trusted provider assertions, monotonic policy, the mTLS gateway, the audit trail and cryptographic transaction binding.

## Terminology

- **Push:** a delivery channel.
- **Audio / video:** additional verification factors.
- **Biometric:** local permission to use the device credential.
- **Cryptographic signature:** proof that the credential holder approved exactly this transaction payload.

A `VERIFIED` video session does not authorize a transaction without the subsequent signature.

## API

| Operation | Bank API | Mobile API |
|---|---|---|
| Read the plan | `GET /v1/authorizations/{id}/verification-plan` | `GET /v1/mobile/authorizations/{id}/verification-plan` |
| Escalate | `POST /v1/authorizations/{id}/verification/escalate` `{reason, requestedStep?}` | `POST /v1/mobile/authorizations/{id}/verification/escalate` (reason `CLIENT_REQUEST`, if the policy allows it) |
| Open an AUDIO or VIDEO session | `POST /v1/authorizations/{id}/verification-sessions` `{channel}` | `POST /v1/mobile/authorizations/{id}/verification-sessions` `{channel}` |
| Report the provider result | `POST /v1/authorizations/{id}/verification-sessions/{sessionId}/complete` `{sessionNonce, result, providerReference, assertion}`, gateway mTLS required | — |

Completed factors are included in the sealed evidence record ([evidence format](../protocol/evidence-format.md)).

## Implementation

- `auth-core/src/services/adaptiveVerificationService.ts`
- `auth-core/migrations/008_adaptive_verification_escalation.sql` (included in `schema.sql`)
- End-to-end scenarios in `auth-core/scripts/e2e-smoke.mjs`: AUDIO required by amount; push timeout → failed AUDIO → VIDEO, with a refused downgrade; failed VIDEO rejecting the authorization; customer-requested escalation
