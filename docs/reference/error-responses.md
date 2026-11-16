# Error responses

This page lists the HTTP status codes and error bodies Auth Core returns, how a bank backend treats each class, and how the responses seen by the mobile SDKs surface as SDK errors. Host app handling of SDK errors is described in the [iOS SDK](../../ios-sdk/README.md#errors-the-host-app-should-handle) and [Android SDK](../../android-sdk/README.md#errors-the-host-app-should-handle) READMEs.

## Body formats

Most errors use one JSON shape (`Error` in [openapi.yaml](../../auth-core/openapi.yaml)):

```json
{ "error": "Credential is not ACTIVE for the specified NEXUS ID" }
```

The `error` text is for logs and operators. It is not a stable identifier; branch on the status code, on `code` where it is present, and on the documented fields below.

Some 409 responses carry a machine-readable `code` next to `error`, for the cases a caller must distinguish:

```json
{ "error": "The confirmation is older than 3600 s; request a new authorization", "code": "CONFIRMATION_TOO_OLD" }
```

`code` values are listed in [conflict codes](#conflict-codes). A 409 without `code` is a state conflict to be reconciled by reading the resource.

| Source | Body |
|---|---|
| Request validation (Zod schema) | `{"error": "Invalid request", "details": [{"path": "beneficiary.iban", "message": "..."}]}` |
| Malformed JSON, unsupported charset | `{"error": "Malformed request body"}` (400) |
| Body larger than 32 KB (JSON) or 4 KB (form body on `/oauth/token`) | `{"error": "Request body is too large"}` (413) |
| `/oauth/token` (RFC 6749 section 5.2) | `{"error": "invalid_request" \| "invalid_client" \| "unsupported_grant_type", "error_description"?: "..."}`, with `Cache-Control: no-store` |
| Throttling (`/oauth/token`, admin login) | `{"error": "too_many_attempts", "retryAfterSeconds": 900}` and a `Retry-After` header (429) |
| Attestation refused (`/v1/mobile/bootstrap`, recovery completion) | `{"error": "Device attestation verification failed"}` (403). The body has no `reason` or `code`; the reason (for example a key attestation failure or an unavailable status list) is only in the Auth Core log entry `Device attestation refused` |
| Device signature outside the time window | `{"error": "Device request timestamp is outside the accepted window", "serverTime": 1790000000}` (401) |
| Admin approval requests (`POST /admin/api/identities/{nexusId}/revoke`, `/reactivate`) | 202 with the approval: `approvalId`, `action`, `nexusId`, `clientId`, `reason`, `requestedBy`, `requestedAt`, `expiresAt`, `status` (`PENDING`), `decidedBy`, `decidedAt` |
| Unexpected failure | `{"error": "Internal server error"}` (500); details go to the Auth Core log only |

Signature and offline-code submissions return a verification result instead of an error body:

```json
{ "status": "FAILED", "reason": "signature_verification_failed", "attempts": 2 }
```

## Status codes

| Status | Raised by | Typical messages | Bank backend treatment |
|---|---|---|---|
| 200 with `status: FAILED` | Signature and offline-code submissions | See [confirmation results](#confirmation-results) | Not an HTTP error. Do not resubmit the same proof. Read `GET /v1/authorizations/{id}` |
| 400 | Validation, `ValidationError` | `Invalid request`, `Idempotency-Key header is required`, `Invalid beneficiary value for "name": control, format or separator characters are not allowed`, `Invalid transaction_reference: control, format or separator characters are not allowed` | Do not retry unchanged. Fix the request; a 400 in production indicates an integration defect |
| 401 | Bank token check (`middleware/auth.ts`) | `Missing, expired, or invalid access token` | Obtain a new token from `/oauth/token` and retry once. A second 401, or `invalid_client` on `/oauth/token`, means the secret was rotated, the client is `DISABLED`, or the client certificate presented is not registered for the client: stop and alert |
| 401 | `/oauth/token` | `invalid_client`: wrong secret, unknown or disabled client, or (with `REQUIRE_MTLS_HEADER`) a client certificate not registered for the client (audit event `bank_certificate_mismatch`) | Do not retry with the same secret and certificate |
| 401 | Mobile endpoints (`middleware/mobileAuth.ts`), recovery completion | See [mobile responses](#mobile-responses-and-sdk-errors) | Handled by the SDK |
| 403 | Gateway check (`middleware/mtlsGateway.ts`) | `mTLS gateway required`, `Verified client certificate required`, `Verified client certificate fingerprint required` | Configuration fault in the gateway or `TRUSTED_PROXY_IPS`. Do not retry |
| 403 | `ForbiddenError` | `A request signed by the enrolled device is required`, `Client escalation is not permitted by policy`, `Verification session nonce is invalid`, `A second admin must approve this request` | Do not retry. The action is not permitted in this deployment or by this policy |
| 403 | Credential integrity check (`credentialIntegrity.ts`) | `Credential integrity check failed: <reason>` (recovery setup) | Security incident; see [evidence verification failure](../operations/runbooks/evidence-verification-failure.md) |
| 401, 403 | Admin console (`middleware/adminAuth.ts`, `routes/admin.ts`) | 401 `Not logged in, or session expired`, `Invalid username, password or one-time code`; 403 `This action requires the 'operator' role or higher`, `Cross-origin request refused` | Log in again (401); do not retry (403) |
| 404 | `NotFoundError` and the domain not-found errors | `NEXUS ID ... was not found`, `Credential ... was not found`, `Authorization ... was not found`, `No evidence exists for this authorization`, `Recovery session was not found or expired` | Do not retry. The ID is unknown to this bank client; a credential that is already `REVOKED` also returns 404 on revoke |
| 409 | `ConflictError`, duplicate customer, recovery not configured | `NEXUS ID is SUSPENDED`, `Credential is not ACTIVE for the specified NEXUS ID`, `Transaction reference or idempotency key already exists for this bank client`, `Idempotency-Key is already bound to a different authorization request`, `Authorization is PENDING_USER; only a VERIFIED authorization can be committed`, `Verification already requires AUDIO; downgrade or repetition is not possible`, `Recovery has not been configured for this NEXUS ID`; with `code`, see [conflict codes](#conflict-codes) | Branch on `code` when present. Otherwise do not retry unchanged; read the current state with the matching `GET` and reconcile |
| 410 | `GoneError`, expired confirmation | `Authorization expired`, `Verification session expired`, `Approval request has expired`; on submissions the body is `{"status": "EXPIRED"}` | Do not retry. Create a new authorization with a new `transactionReference` |
| 413 | Body parser | `Request body is too large` | Do not retry unchanged |
| 429 | Login throttle | `too_many_attempts` | Wait `Retry-After` seconds. Only failed attempts are counted |
| 500 | Unhandled error | `Internal server error` | Retry with backoff, following the [retry rules](#retry-rules) |
| 503 | `/readyz` | `{"status": "not ready"}` | PostgreSQL, Redis or the HSM self-test failed; the load balancer takes the instance out of routing |

A path that matches no route returns 401 without a bank token and the framework's non-JSON 404 with one.

## Conflict codes

| `code` | Raised by | Meaning | Caller action |
|---|---|---|---|
| `ACTIVE_CREDENTIAL_EXISTS` | `POST /v1/mobile/sessions` without `replacement`; `POST /v1/mobile/bootstrap` when a device was enrolled concurrently | The identity has an `ACTIVE` credential | Re-identify the customer and issue a token with `replacement {method, reference}`, use recovery, or revoke the old credential first ([device replacement](../integration/bank-backend-guide.md#device-replacement)) |
| `CREDENTIAL_NOT_ATTESTED` | `POST /v1/authorizations` with `REQUIRE_VALID_ATTESTATION=true` | The credential's `attestationStatus` is not `VERIFIED` | The customer enrols the device again |
| `IDENTITY_NOT_ACTIVE` | `POST /v1/authorizations/{id}/bank-commit-request` | The NEXUS ID is no longer `ACTIVE` | Do not commit |
| `CREDENTIAL_NOT_ACTIVE` | `POST /v1/authorizations/{id}/bank-commit-request`; `POST /admin/api/identities/{nexusId}/devices/{id}/revoke` | The credential that confirmed is no longer `ACTIVE` (revoked, replaced, recovered); in the console, the device is already removed | Do not commit; ask the customer again. In the console: refresh |
| `CONFIRMATION_TOO_OLD` | `POST /v1/authorizations/{id}/bank-commit-request` | The confirmation is older than `BANK_COMMIT_MAX_AGE_SECONDS` | Create a new authorization |
| `RECOVERY_LOCKED` | `POST /v1/recovery/sessions` | 10 or more failed recovery proofs for the identity in sessions opened in the last 24 hours | Wait, or replace the device after re-identification ([recovery lockout](../operations/runbooks/recovery-lockout.md)) |
| `RECOVERY_PROTOCOL_RETIRED` | `POST /v1/recovery/sessions`, recovery completion | The identity's phrase uses recovery protocol 1, which was removed | The customer sets up a new phrase on the enrolled device, or the bank replaces the device |
| `RECOVERY_SETUP_EXPIRED` | `POST /v1/mobile/recovery/setup` | The salt was not issued to this credential within the last 600 s, or differs | Handled by the SDK: request new parameters |
| `RECOVERY_INTEGRITY` | `POST /v1/recovery/sessions`, recovery completion | The stored recovery configuration is not the identity's latest sealed `RECOVERY_CONFIGURED` record, or its key (and, at session creation, salt or iteration count) differs from that record (`integrity_violation`) | Security incident; do not retry |
| `APPROVAL_PENDING` | `POST /admin/api/identities/{nexusId}/revoke`, `/reactivate` | A request for the same identity and action is already waiting for approval | Approve or reject the pending request |
| `CONVERSATION_CLOSED` | Sending in, or handing over, a conversation | The conversation was closed | Open a new conversation |
| `CONVERSATION_NOT_WITH_BOT` | `POST /v1/conversations/{id}/bot-messages` | A person has taken over or the conversation waits for one; the bot no longer answers | Do not answer from the bot |
| `CONVERSATION_NOT_WAITING` | `POST /admin/api/conversations/{id}/claim` | The conversation is not waiting for an operator | Refresh the queue |
| `CONVERSATION_NOT_ASSIGNED` | Operator answer, release or close | Another operator took the conversation | Refresh the queue |
| `CALL_CHANNEL_NOT_ENABLED` | `POST /v1/mobile/customer-calls` | The bank does not take calls from the app on this channel ([customer calls](../architecture/customer-calls.md)) | The app offers the channels the bank takes, or a conversation |
| `CALL_ALREADY_OPEN` | `POST /v1/mobile/customer-calls` | The customer already has a call waiting or connected | Rejoin or end that call |
| `CALL_NOT_OPEN` | Signals or end of a customer call | The call ended, was cancelled or was missed | None; ask for a new call |
| `CALL_NOT_WAITING` | `POST /admin/api/customer-calls/{id}/answer`, operator signals | Another operator answered, the call is no longer waiting, or the operator has not answered it | Refresh the queue |
| `MESSAGE_ID_REUSED` | Sending a message | The `clientMessageId` was used before for another text | Use a new id for a new message |
| `MANDATE_REFERENCE_EXISTS` | `POST /v1/mandates` | The bank client already has a mandate with this `mandateReference` | Use a new reference; changed terms are a new mandate |
| `MANDATE_NOT_PENDING` | `POST /v1/mobile/mandates/{id}/signature` | The mandate is no longer waiting for a signature | Handled by the SDK: refresh the mandate |
| `MANDATE_OFFER_EXPIRED` | `POST /v1/mobile/mandates/{id}/signature` | The time to sign (`offerExpiresAt`) has passed | The bank proposes the mandate again |
| `MANDATE_STATE_CONFLICT` | `POST /v1/mobile/mandates/{id}/decline`, `/suspend`, `/resume`, `/revoke`; `POST /v1/mandates/{id}/withdraw`; `POST /admin/api/mandates/{id}/hold`, `/release`, `/withdraw` | The action is not possible in the mandate's state (for example resuming a revoked mandate) | Read the mandate's state |
| `MANDATE_HELD_BY_BANK` | `POST /v1/mobile/mandates/{id}/resume` | The bank's staff hold the mandate; only the bank lifts the hold ([bank console](../operations/bank-console.md)) | The app tells the customer to contact the bank |
| `SAME_STAFF_MEMBER` | `POST /admin/api/mandates/{id}/release` | The staff member who placed the hold cannot lift it | Another member of staff releases it |
| `MANDATE_INTEGRITY` | `POST /v1/mobile/mandates/{id}/signature` | The stored terms no longer hash to the stored terms hash | Security incident; do not retry |
| `DEBIT_REFERENCE_REUSED` | `POST /v1/mandates/{id}/debits` | The `debitReference` was used before with another amount or currency | Use a new reference for a different debit |
| `MANDATE_DEBIT_REFUSED` | `POST /v1/mandates/{id}/debits` | The debit is outside the signed terms; the body carries the recorded decision and `reason` (`MANDATE_NOT_ACTIVE`, `NOT_YET_VALID`, `VALIDITY_ENDED`, `CURRENCY_MISMATCH`, `ABOVE_PAYMENT_LIMIT`, `PERIOD_ALREADY_DEBITED`, `ABOVE_TOTAL_LIMIT`) | Do not debit |
| `CUSTOMER_LIMIT_EXCEEDED` | `POST /v1/authorizations` | The amount is above a limit the customer set in the bank's app (per payment, or the total of the last 24 hours in that currency, counting open and confirmed payments) | Tell the customer; they can raise the limit, which applies after `CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS` |
| `DEVICE_LIMIT_REACHED` | `POST /v1/mobile/sessions` with `addition` | The NEXUS ID already has as many active devices as the bank client allows (`max_devices_per_identity`) | Remove a device first, or raise the bank's limit |
| `NO_ACTIVE_DEVICE` | `POST /v1/mobile/sessions` with `addition`; enrolment with an addition token | The customer has no active device to add one to | Enrol (first device) or replace instead |
| `DEVICE_REQUEST_OPEN` | `POST /v1/mobile/sessions` with `addition` or `replacement` | A device request of the other kind is still open for this NEXUS ID | Wait until it is used, cancelled or expired |
| `REPLACEMENT_REQUIRED` | `POST /v1/mobile/sessions` without `replacement` for an identity that had a device (now revoked); enrolment with a replacement token that names no replacement request | Revoking first does not skip the device replacement hold | Request a replacement after re-identifying the customer, or use recovery ([device replacement](../architecture/device-replacement.md)) |
| `REPLACEMENT_NOT_USABLE` | `POST /v1/mobile/bootstrap` with a replacement token | The replacement request was cancelled by the enrolled device, expired, was already used, or is still on hold | Ask again with `POST /v1/mobile/sessions`; while it answers 202 `REPLACEMENT_PENDING`, wait for the customer's approval or the end of the hold |
| `REPLACEMENT_NOT_PENDING` | `POST /v1/mobile/device-replacements/{id}/approve` or `/cancel`; `POST /admin/api/identities/{nexusId}/device-requests/{id}/cancel` | No pending replacement request with this ID for the device's NEXUS ID | Handled by the SDK: refresh the list |
| `RECOVERY_PHRASE_USED` | `POST /v1/recovery/sessions`, recovery completion | The phrase already recovered this identity; the recovered device has not set up a new one | The customer sets up a new phrase on the recovered device; a lost recovered device is replaced by the bank |
| `AUTHORIZATION_NOT_PENDING` | `POST /v1/mobile/authorizations/{id}/decline`, `POST /v1/authorizations/{id}/cancel` | The authorization is no longer `PENDING_USER` | Read its state; nothing to withdraw |
| `CREDENTIAL_MISMATCH` | `POST /v1/mobile/authorizations/{id}/decline` | The authorization is bound to another device | None (the request came from the wrong device) |
| `CREDENTIAL_INTEGRITY` | `POST /v1/mobile/authorizations/{id}/deferred-signature` | The credential's keys do not match its sealed enrolment record | Security incident; do not retry |
| `EVIDENCE_INVALID` | `POST /v1/authorizations/{id}/bank-commit-request` | The authorization's evidence does not support a commit (the message names the problem) | Do not commit; security incident |
| `OFFLINE_LIMIT_EXCEEDED` | `GET /v1/authorizations/{id}/offline-challenge` | The amount is above `OFFLINE_CONFIRMATION_MAX_AMOUNT`, or the credential reached `OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY` | Confirm online |
| `VERIFICATION_ATTEMPTS_EXHAUSTED` | Opening an audio or video verification session | The channel was attempted the maximum number of times for this authorization | Create a new authorization or decline the payment |
| `VERIFICATION_CHANNEL_UNAVAILABLE` | `POST /v1/authorizations`, escalation | A required verification step has no verifier at this bank | Register a verification provider or enable operator verification |

## Confirmation results

`POST /v1/authorizations/{id}/signature`, `POST /v1/mobile/authorizations/{id}/signature` and `POST /v1/authorizations/{id}/offline-confirmation` answer 200 with `VERIFIED` or `FAILED`, or 410 with `EXPIRED`.

| `reason` | Counts as an attempt | Meaning |
|---|---|---|
| `signature_verification_failed` | Yes | The signature does not verify over the canonical bytes with the credential's key |
| `malformed_signature` | Yes | The signature is not strict base64 |
| `offline_code_invalid` | Yes | The code does not match |
| `signature_attempt_limit` | Yes, the fifth | The authorization is `REJECTED` |
| `Authorization is VERIFIED` (or another state) | No | The authorization is closed; a resubmission after a lost response shows this |
| `NEXUS ID is SUSPENDED`, `Credential is not valid for this authorization`, `Authorization has no bound credential` | No | Identity or credential state does not allow confirmation |
| `credential_integrity` | No | The credential's keys differ from its sealed enrolment, or the key changed during confirmation; audited as `integrity_violation`. Treat as a security incident |
| `Required verification (AUDIO) has not been completed` | No | The verification plan has not reached `requiredStep`; the authorization stays `PENDING_USER` |
| `Authorization was finalized concurrently` | No | Another request consumed or closed it first |
| `Offline confirmation is not enabled on this deployment`, `The device is not enrolled for offline confirmation` | No | Offline confirmation is not available for this authorization |

`attempts` is the number of invalid attempts so far. Signatures and offline codes share the limit of five. A `VERIFIED` result also carries `evidence` (`evidenceId`, `chainSequence`, `evidenceHash`), the position of the sealed record.

## Retry rules

A 5xx response or a network failure leaves the outcome unknown. The safe retry depends on the endpoint:

| Endpoint | Retry after an unknown outcome |
|---|---|
| `POST /oauth/token` | Retry |
| `POST /v1/authorizations` | Retry with the same `Idempotency-Key` and the same body; the original authorization returns with 200 |
| `POST /v1/nexus-identities` | A retry returns 409 if the first request succeeded. The bank API has no lookup by `bankCustomerRef`, so the bank records the request and treats a 409 on retry as an operator case |
| `POST /v1/mobile/sessions` | Retry; each call issues a new token. A request with `replacement` writes one `credential_replacement_authorized` audit event per call |
| `POST .../signature`, `POST .../offline-confirmation` | Read `GET /v1/authorizations/{id}` first. A resubmission of a proof that was accepted returns `FAILED` with `Authorization is VERIFIED` |
| `POST .../bank-commit-request` | Retry with the same `bankTransactionReference` |
| `POST .../bank-commit-result` | Retry with the same `state` |
| `POST .../verification/escalate` | Read the plan first; a repeated escalation to the same step returns 409 |
| `POST .../verification-sessions` | Retry; the new session cancels the previous one |
| `POST .../verification-sessions/{sessionId}/complete` | Retry; a completed session returns 409 `Verification session is VERIFIED` (or `FAILED`), which confirms the first call |
| `POST /v1/credentials/{id}/revoke` | Retry; 404 on retry means the credential is already revoked |
| `POST /v1/recovery/sessions` | Retry; each call opens a new session |
| `POST /admin/api/identities/{nexusId}/revoke`, `/reactivate` | A retry returns 409 `APPROVAL_PENDING` if the first request was recorded |
| `POST /admin/api/approvals/{id}/approve`, `/reject` | A retry returns 409 `Approval request is EXECUTED` (or `REJECTED`), which confirms the first call |

## Mobile responses and SDK errors

The SDKs call the device-facing endpoints themselves. Both turn an Auth Core rejection into `serverError(statusCode:message:)` (iOS) or `ServerError(statusCode, serverMessage)` (Android), where `message` is the `error` field, except for the cases mapped below.

| Auth Core response | iOS SDK | Android SDK | Host app action |
|---|---|---|---|
| Network failure, timeout, no HTTP response | `networkUnavailable` | `NetworkUnavailable` | Retry, or offer another channel |
| 401 `Device request timestamp is outside the accepted window` with `serverTime` | Retried once after clock correction (offset up to 24 hours); then `serverError(401)` | Same; then `ServerError(401)` | Treat a remaining 401 as an enrolment problem |
| 401 `Device signature does not verify`, `Unknown credential or no device authentication key`, `Device request nonce has already been used` | `serverError(401)` | `ServerError(401)` | The credential is revoked or replaced, or failed the integrity check: enrol again or run recovery |
| 401 `Missing, expired, or invalid bootstrap token` on `/v1/mobile/bootstrap` | `serverError(401)` | `ServerError(401)` | Request a new `BOOTSTRAP` token |
| None: a device request without an enrolled device, or with a device enrolled by an SDK before 1.2 (no authentication key) | `notRegistered` | `NotRegistered` | Enrol the device; a pre-1.2 enrolment through [device replacement](../integration/bank-backend-guide.md#device-replacement) |
| 403 `NEXUS ID is SUSPENDED` or `REVOKED` | `serverError(403)` | `ServerError(403)` | Tell the customer to contact the bank |
| 403 `Device attestation verification failed` | `serverError(403)` | `ServerError(403)` | Enrolment refused by policy; offer support |
| 409 `Bootstrap token has already been used` | `serverError(409)` | `ServerError(409)` | Request a new `BOOTSTRAP` token |
| 409 `ACTIVE_CREDENTIAL_EXISTS` on `/v1/mobile/bootstrap` | `serverError(409)` | `ServerError(409)` | The bank backend decides on device replacement |
| 409 `RECOVERY_SETUP_EXPIRED` on recovery setup | `serverError(409)` | `ServerError(409)` | Set up recovery again |
| 200 `FAILED` on signature | `approve` returns `.failed` | `approve` returns `FAILED` | The bank backend reads the authorization state |
| 410 on signature | `authorizationExpired` | `AuthorizationExpired` | The bank creates a new authorization |
| 401 `Invalid recovery proof` | `invalidRecoveryPhrase` | `InvalidRecoveryPhrase` | With protocol 2 a wrong phrase is normally detected on the device before any request (same error); a 401 means the proof reached Auth Core and failed. Five attempts per session, ten per identity in 24 hours |
| 404 `Recovery session not found or expired` | `serverError(404)` | `ServerError(404)` | The session expired, was used or is locked; the bank opens a new one |
| 409 `RECOVERY_INTEGRITY` | `serverError(409)` | `ServerError(409)` | Recovery refused; contact the bank |

The SDKs raise some errors before any request: `authorizationPayloadInvalid` / `AuthorizationPayloadInvalid` when the signed bytes fail the device-side checks, `authorizationExpired` / `AuthorizationExpired` when the device clock is past `expires_at`, `invalidRecoveryPhrase` / `InvalidRecoveryPhrase` for a phrase that is not a valid 12-word BIP-39 phrase or that does not open the wrapped recovery key, `credentialInvalidated` / `CredentialInvalidated` when the device's biometric enrolment changed since the keys were created, and on Android `NoAuthenticationMethodEnrolled` when the device has no secure lock screen or no biometric.

The recovery session errors `RECOVERY_LOCKED` and `RECOVERY_PROTOCOL_RETIRED` are returned to the bank backend, which opens the session, not to the SDK. A malformed recovery session or out-of-range KDF parameters surface as `serverError(statusCode: 0, ...)` / `ServerError(0, ...)`.
