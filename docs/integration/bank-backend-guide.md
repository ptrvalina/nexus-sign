# Bank backend integration guide

This guide follows the order in which a bank team builds its integration with Auth Core. The API contract is [openapi.yaml](../../auth-core/openapi.yaml); error handling is in [error responses](../reference/error-responses.md). `auth-core/scripts/e2e-smoke.mjs` runs the same sequence against a deployed instance and serves as a working reference.

The examples use these shell variables. Every bank call goes through the bank's mTLS gateway with a client certificate registered for the bank client (step 1); add the certificate options (`--cert`, `--key`) the gateway requires.

```bash
BASE=https://nexus-sign.mybank.example
TOKEN=<access_token from step 2>
```

## 1. Register the bank client

Bank clients are registered by an operator with database access, not over HTTP. Run the tool (`node dist/cli/registerClient.js`, or `npm run register-client --` in `auth-core/`) with the deployment's `DATABASE_URL` and `REDIS_URL`, and `WEBHOOK_SECRET_ENCRYPTION_KEY` when a webhook URL is given:

```bash
npm run register-client -- mybank-payments https://hooks.mybank.example/nexus-sign \
  --push-mode=BANK --mtls-cert-sha256=3b1f...9c0a
```

The tool prints `client_secret` and, with a webhook URL, `webhook_secret`. Neither is shown again. Store both in the bank's secrets manager.

`--mtls-cert-sha256` registers the SHA-256 fingerprints (64 hex digits, colons allowed) of the client certificates the bank presents to the gateway, comma-separated; list two during a certificate rollover. With `REQUIRE_MTLS_HEADER=true` (always in production) Auth Core issues and accepts tokens only over a gateway connection whose verified certificate has one of these fingerprints. A client with no registered fingerprint cannot obtain a token. The bank computes the fingerprint with:

```bash
openssl x509 -in client.pem -noout -fingerprint -sha256
```

Running the tool again for the same client ID generates new secrets, revokes every access token issued to the client, and sets the webhook URL and push mode to the values given: without a URL the webhook is removed, without `--push-mode` the mode is `BANK`. The registered fingerprints are kept when `--mtls-cert-sha256` is omitted and replaced when it is given.

To register or change certificates later, including a certificate rollover, the operator uses `setClientCertificates`, which replaces only the fingerprints and does not rotate the secrets or revoke tokens:

```bash
npm run set-client-certificates -- mybank-payments 3b1f...9c0a,7e42...d1b8   # old and new during a rollover
npm run set-client-certificates -- mybank-payments 7e42...d1b8               # after the switch
```

`--push-mode=NEXUS` registers a bank without a push system of its own: Auth Core then delivers authorization requests and the bank's messages through [secure push](../protocol/secure-push.md) (step 7). The default, `--push-mode=BANK`, leaves delivery to the bank's push system.

The webhook URL is checked at each delivery: HTTPS only unless `WEBHOOK_REQUIRE_HTTPS=false`, the host must be in `WEBHOOK_ALLOWED_HOSTS` when that list is set, and addresses in private or reserved ranges are refused.

## 2. Obtain an access token

`POST /oauth/token` implements the OAuth 2.0 client credentials grant. Credentials are accepted in a form body, a JSON body or HTTP Basic authentication.

```bash
curl -s -X POST "$BASE/oauth/token" \
  -d grant_type=client_credentials -d client_id=mybank-payments -d client_secret="$CLIENT_SECRET"
```

```json
{ "access_token": "...", "token_type": "Bearer", "expires_in": 3600 }
```

The request must come over the gateway connection authenticated with a registered client certificate; a correct secret with another certificate is refused with 401 `invalid_client` and recorded as the audit event `bank_certificate_mismatch`. The same binding is checked on every bank API call: a token presented with an unregistered certificate receives 401.

The lifetime is `OAUTH_TOKEN_TTL_SECONDS` (default 3600). Reuse the token until it expires. Failed attempts are counted per source address: 20 failures within 300 seconds lock that address for 900 seconds (429 with `Retry-After`). Every bank API call sends `Authorization: Bearer $TOKEN`.

Auth Core reuses an `X-Correlation-Id` or `X-Request-Id` request header as the log correlation ID and returns it in `X-Correlation-Id`.

## 3. Create a NEXUS ID

```bash
curl -s -X POST "$BASE/v1/nexus-identities" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"bankCustomerRef":"CUST-0042"}'
```

```json
{ "nexusId": "418273650", "status": "ACTIVE", "createdAt": "2026-10-01T09:00:00.000Z" }
```

One bank client has at most one non-revoked NEXUS ID per `bankCustomerRef`; a second request returns 409. The bank API has no lookup by `bankCustomerRef`, so the bank stores `nexusId` with its customer record when the first response arrives. `GET /v1/nexus-identities/{nexusId}` returns the identity, its status and `evidenceHead`, the latest record of its evidence chain (step 12).

## 4. Issue a BOOTSTRAP token for the app

The SDK asks the host app for a token through its token provider. The app forwards the request to the bank backend, which authenticates the customer by its own means and calls:

```bash
curl -s -X POST "$BASE/v1/mobile/sessions" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"nexusId":"418273650","purpose":"BOOTSTRAP"}'
```

```json
{ "accessToken": "ms_...", "tokenType": "Bearer", "expiresIn": 300, "nexusId": "418273650",
  "purpose": "BOOTSTRAP", "attestationChallenge": "..." }
```

The bank backend returns `accessToken` to the app. A `BOOTSTRAP` token is valid for 300 seconds and enrols exactly one key set. The identity must be `ACTIVE` (409 otherwise).

A plain `BOOTSTRAP` token is issued only while the identity has no enrolled device. If it has an `ACTIVE` credential, the request is refused with 409 and `code: ACTIVE_CREDENTIAL_EXISTS`; the bank then follows [device replacement](#device-replacement).

`BOOTSTRAP` is the only purpose; `purpose: "SESSION"` returns 400. An enrolled device signs its own requests and needs no token from the bank backend. A device enrolled by an SDK before 1.2 has no authentication key and is enrolled again through [device replacement](#device-replacement).

## 5. The app enrols the device

The SDK calls `bootstrap()`: it generates the signing, authentication and offline keys, attests them, and calls `POST /v1/mobile/bootstrap` with the token. Details are in the [iOS SDK](../../ios-sdk/README.md), [Android SDK](../../android-sdk/README.md) and [device authentication](../protocol/device-authentication-and-offline-confirmation.md) documents.

The enrolment response reaches the app, not the bank backend. The app reads the credential ID (`NexusMobileRegistration.credentialId`, or `credentialID` on the iOS SDK and `credentialId` on the Android SDK) and sends it to the bank backend. The bank backend checks it before use:

```bash
curl -s "$BASE/v1/credentials/$CREDENTIAL_ID" -H "Authorization: Bearer $TOKEN"
```

The bank accepts the credential when `nexusId` matches, `state` is `ACTIVE` and `attestationStatus` is `VERIFIED`. With `REQUIRE_VALID_ATTESTATION=true` (always in production) an enrolment without valid attestation is refused, so `UNKNOWN` appears only in development and integration environments.

With `REQUIRE_VALID_ATTESTATION=true`, Android devices must send Keystore key attestation chains (SDK 2.0); the credential's `securityLevel` is the one the attestation proves, not the one the app claims.

Enrolment seals a `CREDENTIAL_ENROLLED` record with the device's keys and its attestation in the identity's evidence chain. Before the keys are used, Auth Core compares them with that record; see [evidence and integrity](#12-retrieve-and-verify-evidence).

### Device replacement

Design: [device replacement](../architecture/device-replacement.md).

A customer with a new phone whose old credential is still enrolled gets a new device in one of three ways, each after the bank has re-identified the customer through its own controls:

| Path | When | Call |
|---|---|---|
| Replacement token | The bank re-identified the customer, for example at a branch or by video identification | `POST /v1/mobile/sessions` with `replacement` |
| Recovery | The customer has the recovery phrase | Step 13 |
| Revoke, then enrol | The old device is lost or stolen and must be stopped now | Step 14, then a plain `BOOTSTRAP` token |

```bash
curl -s -X POST "$BASE/v1/mobile/sessions" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"nexusId":"418273650","purpose":"BOOTSTRAP","replacement":{"method":"BRANCH_VISIT","reference":"CASE-2026-1187"}}'
```

| Field | Rule |
|---|---|
| `replacement.method` | `BRANCH_VISIT`, `VIDEO_IDENTIFICATION`, `IN_APP_STRONG_AUTHENTICATION` or `OTHER`: how the bank re-identified the customer |
| `replacement.reference` | 1 to 128 characters: the bank's case reference |

Issuing the token writes the audit event `credential_replacement_authorized` with `method` and `reference`. When the new device enrols with the token, Auth Core in one transaction revokes the old credential and cancels its `PENDING_USER` authorizations, seals the new credential's enrolment with reason `REPLACEMENT`, the replaced credential IDs, `method` and `reference`, and sends the webhook `credential.replaced`. In push mode `NEXUS`, with `PUSH_DELIVERY_ENABLED` and a push registration on the old device, the old device receives a `SECURITY` notice (`PUSH_REPLACEMENT_TITLE`, `PUSH_REPLACEMENT_BODY`).

When the old credential was revoked first, the enrolment replaces nothing: no `credential.replaced` webhook and no notice are sent.

## 6. Create an authorization

```bash
curl -s -X POST "$BASE/v1/authorizations" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H "Idempotency-Key: pay-7f3a9c01" \
  -d '{
    "nexusId": "418273650",
    "credentialId": "'"$CREDENTIAL_ID"'",
    "transactionReference": "TX-2026-000154",
    "operationType": "transfer",
    "amountMinor": "125000",
    "currency": "PLN",
    "beneficiary": { "name": "Jan Kowalski", "iban": "PL61109010140000071219812874" },
    "policyReference": "TRANSFER-DEFAULT",
    "policyVersion": "2026-09",
    "expiresInSeconds": 120
  }'
```

| Field | Rule |
|---|---|
| `nexusId`, `credentialId` | The credential must be `ACTIVE` and belong to the NEXUS ID (409 otherwise). With `REQUIRE_VALID_ATTESTATION=true` its `attestationStatus` must be `VERIFIED`; otherwise 409 `CREDENTIAL_NOT_ATTESTED` and the customer enrols the device again |
| `transactionReference` | 1-128 characters, unique per bank client for all time |
| `operationType` | 1-32 characters, for example `transfer` |
| `amountMinor` | Decimal string in minor units, no leading zeros, at most 30 digits |
| `currency` | `^[A-Z]{3}$` |
| `beneficiary` | Up to 16 string fields; keys match `^[a-z][a-z0-9_]{0,63}$`; values up to 512 characters |
| `policyReference`, `policyVersion` | The bank's policy, 1-128 and 1-64 characters |
| `verificationPolicy` | Optional, see [adaptive verification](#11-adaptive-verification) |
| `expiresInSeconds` | 30-900, default 120 |
| `correlationId` | Optional, up to 128 characters, copied into the evidence |

No string field and no beneficiary value may contain Unicode control, format, line separator or paragraph separator characters (categories Cc, Cf, Zl, Zp). Auth Core refuses them with 400, and both SDKs refuse to display such bytes.

`Idempotency-Key` is required unless `REQUIRE_IDEMPOTENCY_KEY=false`, up to 128 characters. A retry with the same key and the same `nexusId`, `credentialId`, `transactionReference`, `operationType`, `amountMinor`, `currency`, `beneficiary`, `policyReference` and `policyVersion` returns the original authorization and its original verification plan with status 200. The same key with different values returns 409. `verificationPolicy`, `expiresInSeconds` and `correlationId` are not compared, so a replay cannot weaken the plan.

The 201 response carries `authorizationId`, `canonicalPayloadHash`, `issuedAt`, `expiresAt`, `state` (`PENDING_USER`), `verificationPlan`, `protocolVersion` (`"1"`) and `domain`. Store `canonicalPayloadHash` with the bank's transaction before the authorization is delivered: it is the SHA-256 of the exact bytes the customer will see and sign, and the bank compares it again before commit (step 9).

## 7. Deliver the authorization to the device

How the authorization reaches the phone depends on the bank client's push mode (step 1).

**Push mode `BANK`.** Delivery is the bank's own channel. A typical integration sends `authorizationId` in a push message; the app calls `fetchAuthorization` and `approve` on the SDK. The SDK verifies the signed bytes, shows the transaction from them, asks for the biometric and submits the signature to `POST /v1/mobile/authorizations/{id}/signature` itself.

**Push mode `NEXUS`.** Auth Core sends the push itself, queued in the same transaction as the authorization. The create request may set the text, which only invites the customer to open the app:

```json
"pushNotification": { "title": "Confirm payment", "body": "Open the app to review and confirm." }
```

Without it, `PUSH_AUTHORIZATION_TITLE` and `PUSH_AUTHORIZATION_BODY` are used. The 201 response carries `push.messageId` and `push.status`. `push.status` is `FAILED` when the push cannot be sent (`lastError` `NO_PUSH_REGISTRATION` when the app has not registered for push, `PUSH_KEY_UNAVAILABLE`, `PUSH_DELIVERY_DISABLED`); the authorization is created all the same and the bank then uses another channel to invite the customer, or the offline code at a branch (step 10). The app opens the push, reads `authorizationId` and continues with `fetchAuthorization` and `approve` as above. The outcome arrives as webhooks (step 8): `push.delivered` when the phone has decrypted the push, `push.failed`, and `push.timeout` when the phone has not confirmed receipt within `verificationPolicy.pushTimeoutSeconds`. On `push.timeout` the bank decides whether to escalate with `PUSH_TIMEOUT` (step 11), offer the offline code or cancel.

`approve` returns `VERIFIED` or `FAILED` to the app, or throws the SDK's expiry error. The bank backend reads the authoritative state from Auth Core (step 8) and does not rely on a value the app reports.

A bank that receives the signature from the app over its own channel can submit it with `POST /v1/authorizations/{id}/signature` and the body `{"signature": "<base64>", "signatureFormat": "der"}`. A `VERIFIED` result carries `evidence`, the chain position of the sealed record:

```json
{ "status": "VERIFIED", "evidence": { "evidenceId": "...", "chainSequence": 7, "evidenceHash": "3f9a...e1" } }
```

`FAILED` with `reason: credential_integrity` means that the credential's keys in the database differ from its sealed enrolment; Auth Core refused to use them and recorded `integrity_violation`. Treat it as a security incident, not as a customer error.

In push mode `BANK`, `verificationPolicy.pushTimeoutSeconds` is informational. When the bank's push service sees no delivery or no answer in time, the bank backend escalates with `PUSH_NOT_DELIVERED` or `PUSH_TIMEOUT` (step 11).

### Messages to the customer (push mode `NEXUS`)

The bank sends its own notifications through the same channel: incoming and outgoing payments, card spending, account and security notices.

```bash
curl -s -X POST "$BASE/v1/push-messages" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "nexusId": "482915306",
  "category": "INCOMING_PAYMENT",
  "title": "Incoming payment",
  "body": "+ 1 200,00 PLN from Anna Nowak",
  "data": { "accountId": "PL-MAIN-01" },
  "messageReference": "credit-2026-10-01-000431"
}'
```

| Field | Rule |
|---|---|
| `category` | `INCOMING_PAYMENT`, `OUTGOING_PAYMENT`, `CARD_TRANSACTION`, `ACCOUNT`, `SECURITY` or `GENERAL` |
| `title` | 1 to 120 characters |
| `body` | Up to 600 characters; line breaks allowed |
| `data` | Up to 16 string fields passed to the app, keys `^[A-Za-z][A-Za-z0-9_]{0,31}$`, values up to 256 characters |
| `ttlSeconds` | 60 to 2 419 200, capped by `PUSH_MESSAGE_TTL_SECONDS` (default 24 h) |
| `messageReference` | Optional, up to 128 characters, unique per bank client; a retry with the same reference returns the original message with 200 |

No control, format or separator characters are allowed in `title` and `body` (line breaks in `body` excepted), and the whole message must stay under 2048 bytes. The answer is 202 with `messageId` and `status: QUEUED`; 409 when the customer's device has not registered for push or `PUSH_DELIVERY_ENABLED` is off; 403 for a bank client in push mode `BANK`.

Auth Core seals the message for the device before storing it; neither its database nor Apple nor Google can read it. `GET /v1/push-messages/{messageId}` returns the status (`QUEUED`, `SENT`, `DELIVERED`, `FAILED`, `EXPIRED`), never the content.

## 8. Read status and receive webhooks

```bash
curl -s "$BASE/v1/authorizations/$AUTHORIZATION_ID" -H "Authorization: Bearer $TOKEN"
```

| `state` | Meaning |
|---|---|
| `PENDING_USER` | Waiting for the customer's confirmation |
| `VERIFIED` | Confirmed, consumed and sealed in the evidence chain |
| `EXPIRED` | A confirmation arrived at or after `expiresAt` |
| `REJECTED` | Five invalid signatures or codes, or the last available verification factor failed |
| `CANCELLED` | The credential was revoked or replaced, the identity was suspended or revoked, or a recovery completed |

For a `VERIFIED` authorization the response also carries `evidence` (`evidenceId`, `chainSequence`, `evidenceHash`); store it as described in step 12.

The transition to `EXPIRED` is recorded when a confirmation is attempted. Until then `GET` returns `PENDING_USER` after `expiresAt` has passed, so the bank backend compares `expiresAt` with the current time. Auth Core sends no webhook for authorization state changes; the bank backend polls this endpoint or acts on the app's report and then confirms here.

### Webhooks

Webhooks report the outcome of each authorization, bank transaction state changes (step 9), device and recovery changes, and, in push mode `NEXUS`, push delivery. Auth Core sends `POST` requests with a JSON body to the registered URL. A receiver must accept event types it does not process; answering them with an error makes the delivery fail and be retried:

| `eventType` | Body fields besides `eventId`, `eventType` |
|---|---|
| `authorization.verified` | `authorizationId`, `nexusId`, `transactionReference`, `confirmationMethod`, `evidence` (`evidenceId`, `chainSequence`, `evidenceHash`), `evidenceHead`. Keep `evidenceHead`: a verifier given the latest head the bank holds (`verify-evidence.mjs --expect-head`) detects records removed from the end of the chain |
| `authorization.rejected` | `authorizationId`, `nexusId`, `transactionReference`, `reason` (`signature_attempt_limit`, `verification_failed`, `REJECTED`) |
| `authorization.expired` | `authorizationId`, `nexusId`, `transactionReference`, `expiresAt`. Sent once, when the authorization is moved to `EXPIRED` by a late confirmation attempt or by the periodic sweep (`AUTHORIZATION_EXPIRY_SWEEP_MS`). `GET /v1/authorizations/{id}` reports `EXPIRED` as soon as `expiresAt` has passed |
| `authorization.bank_transaction.commit_requested` | `authorizationId`, `bankTransactionReference` |
| `authorization.bank_transaction.committed` | `authorizationId`, `state`, `error` |
| `authorization.bank_transaction.failed` | `authorizationId`, `state`, `error` |
| `authorization.bank_transaction.cancelled` | `authorizationId`, `state`, `error` |
| `push.delivered` | `messageId`, `nexusId`, `category`, `authorizationId`, `deliveredAt` |
| `push.failed` | `messageId`, `nexusId`, `category`, `authorizationId`, `reason` (`NO_PUSH_REGISTRATION`, `NO_ACTIVE_REGISTRATION`, `PUSH_KEY_REPLACED`, `PUSH_KEY_UNAVAILABLE`, `PUSH_DELIVERY_DISABLED`, `DEVICE_TOKEN_INVALID`, `REJECTED`, `RETRIES_EXHAUSTED`, `PROVIDER_NOT_CONFIGURED`, `EXPIRED`) |
| `push.timeout` | `messageId`, `nexusId`, `authorizationId`, `sentAt` |
| `credential.replaced` | `nexusId`, `newCredentialId`, `replacedCredentialIds`, `method`, `reference`, `enrolmentEvidenceHash` |
| `recovery.configured` | `nexusId`, `credentialId`, `configuredAt` |
| `identity.recovered` | `nexusId`, `newCredentialId`, `revokedCredentialIds` |

`credential.replaced` that the bank cannot match with one of its own replacement cases, and `identity.recovered` for a recovery session the bank did not open, are security events for the bank.

Headers:

| Header | Value |
|---|---|
| `X-NEXUS-SIGN-Event-Id` | Event ID, equal to `eventId` in the body |
| `X-NEXUS-SIGN-Timestamp` | Unix time in seconds of this delivery attempt |
| `X-NEXUS-SIGN-Signature` | `v1=` followed by the hex HMAC-SHA256 of `<timestamp>.<raw body>` with the webhook secret as key |

Events are written in the same database transaction as the state change. A 2xx answer within 10 seconds counts as delivered. Otherwise Auth Core retries after 1 s, 5 s, 30 s, 5 min and 30 min, then marks the delivery `FAILED`. Redirects are not followed. The receiver deduplicates on `eventId`, because a delivery can arrive more than once.

The receiver verifies the signature over the exact bytes received, compares in constant time and rejects timestamps outside a window set by the bank. The secret is the `webhook_secret` string printed by `register-client`, used as printed (UTF-8), not base64-decoded.

```js
const crypto = require('node:crypto');
const express = require('express');

const WEBHOOK_SECRET = process.env.NEXUS_SIGN_WEBHOOK_SECRET;
const TOLERANCE_SECONDS = 300; // set by the bank

function verifyNexusSignWebhook(rawBody, timestamp, signatureHeader) {
  if (!/^\d{1,12}$/.test(timestamp ?? '')) return false;
  if (typeof signatureHeader !== 'string' || !signatureHeader.startsWith('v1=')) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp)) > TOLERANCE_SECONDS) return false;
  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET)
    .update(Buffer.concat([Buffer.from(`${timestamp}.`, 'utf8'), rawBody]))
    .digest();
  const given = Buffer.from(signatureHeader.slice(3), 'hex');
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

const app = express();
app.post('/nexus-sign', express.raw({ type: 'application/json', limit: '64kb' }), (req, res) => {
  if (!verifyNexusSignWebhook(req.body, req.get('X-NEXUS-SIGN-Timestamp'), req.get('X-NEXUS-SIGN-Signature'))) {
    return res.status(401).end();
  }
  const event = JSON.parse(req.body.toString('utf8'));
  // Store event.eventId with a unique constraint; skip the event if it is already stored.
  res.status(204).end();
});
```

The delivery worker polls every 2 seconds. `/admin/api/webhook-deliveries` in the admin interface lists deliveries by status.

## 9. Commit after VERIFIED

The bank remains the system of record for the transaction. Auth Core records what the bank reports.

Before requesting the commit, the bank backend reads the authorization (`GET /v1/authorizations/{id}`) and checks that `state` is `VERIFIED` and that `canonicalPayloadHash` equals the value it stored from the 201 creation response (step 6). The hash covers the transaction terms the customer signed; a different value means the authorization is not the one the bank created, and the bank does not commit. The database also refuses any change to the bound transaction fields of an authorization.

```bash
curl -s -X POST "$BASE/v1/authorizations/$AUTHORIZATION_ID/bank-commit-request" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"bankTransactionReference":"CORE-88231"}'

# after core banking has answered
curl -s -X POST "$BASE/v1/authorizations/$AUTHORIZATION_ID/bank-commit-result" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"state":"COMMITTED"}'
```

| Call | Accepted when | Repeat |
|---|---|---|
| `bank-commit-request` (202) | `state` is `VERIFIED`, the bank transaction is `PENDING`, the identity and the credential that confirmed are `ACTIVE`, and the confirmation is at most `BANK_COMMIT_MAX_AGE_SECONDS` old (default 3600) | Same `bankTransactionReference` returns the current state; a different one returns 409 |
| `bank-commit-result` (200), `state` `COMMITTED`, `FAILED` or `CANCELLED`, optional `error` up to 256 characters | The bank transaction is `COMMIT_REQUESTED` | Same `state` returns the current state; a different one returns 409 |

A refused commit request returns 409 with a `code`:

| `code` | Meaning | Bank action |
|---|---|---|
| `IDENTITY_NOT_ACTIVE` | The NEXUS ID was suspended or revoked after the confirmation | Do not commit; resolve the identity first |
| `CREDENTIAL_NOT_ACTIVE` | The device that confirmed was revoked or replaced after the confirmation | Do not commit; ask the customer again on the current device |
| `CONFIRMATION_TOO_OLD` | `verified_at` is more than `BANK_COMMIT_MAX_AGE_SECONDS` ago | Create a new authorization |

`GET /v1/authorizations/{id}/bank-transaction` returns `authorizationState`, `bankTransactionState`, `bankTransactionReference`, `bankCommitAt` and `bankCommitError`, for reconciliation against the core banking ledger.

## 10. Offline confirmation at a branch or ATM

The customer confirms with a phone that has no network. Requirements: `OFFLINE_CONFIRMATION_ENABLED=true` and `DEVICE_SECRET_ENCRYPTION_KEY` on Auth Core, and a device enrolled while offline confirmation was enabled. The SDK reports this to the app with `isOfflineConfirmationAvailable()`; for any other device `offline-challenge` returns 409.

1. Create the authorization as in step 6.
2. Fetch the QR content and show `qrPayload` as a QR code on the bank's screen:

   ```bash
   curl -s "$BASE/v1/authorizations/$AUTHORIZATION_ID/offline-challenge" -H "Authorization: Bearer $TOKEN"
   ```

   ```json
   { "authorizationId": "...", "qrPayload": "NXS1.eyJhbW91bnRfbWlub3Ii...", "codeDigits": 8, "expiresAt": "..." }
   ```

3. The customer scans it in the bank app, sees the transaction, passes the biometric prompt and reads an 8-digit code.
4. The customer types the code on the bank's screen, and the bank backend submits it:

   ```bash
   curl -s -X POST "$BASE/v1/authorizations/$AUTHORIZATION_ID/offline-confirmation" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"code":"40718266"}'
   ```

The result has the same form as a signature submission: `{"status":"VERIFIED","evidence":{...}}`, or `FAILED` with `reason` and `attempts`, or 410 with `EXPIRED`. Wrong codes count toward the same five-attempt limit as wrong signatures. A correct code runs the same checks as a signature, including the verification plan, and seals evidence with `confirmationMethod: OFFLINE_CODE`.

An offline code is computed with a key that Auth Core also holds. Auth Core can verify it; a third party cannot. The bank decides per payment type whether offline confirmation is acceptable ([what an offline code proves](../protocol/device-authentication-and-offline-confirmation.md#what-an-offline-code-proves)).

## 11. Adaptive verification

`verificationPolicy` in step 6 sets the minimum factor:

| Field | Effect |
|---|---|
| `requireAudio`, `requireVideo` | Minimum factor AUDIO or VIDEO |
| `highAmountThresholdMinor` | `amountMinor` at or above this value requires AUDIO |
| `audioAvailable`, `videoAvailable` | Whether the bank operates the channel (default `true`); a required channel is always enabled |
| `clientEscalationAllowed` | Whether the customer may request a stronger check from the app (default `true`) |
| `pushTimeoutSeconds` | 10-300, default 30, informational |

The plan is returned in the creation response and by `GET /v1/authorizations/{id}/verification-plan`. A signature is accepted only after the plan reaches `requiredStep`; a PUSH-level plan is satisfied by the signature itself.

Raise the requirement:

```bash
curl -s -X POST "$BASE/v1/authorizations/$AUTHORIZATION_ID/verification/escalate" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"reason":"PUSH_TIMEOUT"}'
```

`reason` is one of `PUSH_NOT_DELIVERED`, `PUSH_TIMEOUT`, `HIGH_AMOUNT`, `RISK_POLICY`, `CLIENT_REQUEST`, `CHANNEL_FAILURE`. Without `requestedStep` the next enabled factor is used. A request for the same or a weaker step returns 409.

Open a session for `currentStep` and pass `sessionId` and `nonce` to the verification provider. Sessions expire after five minutes; opening a new one cancels the open one.

```bash
curl -s -X POST "$BASE/v1/authorizations/$AUTHORIZATION_ID/verification-sessions" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"channel":"AUDIO"}'
```

The bank's verification gateway reports the provider's result. With `REQUIRE_MTLS_HEADER=true` this call requires gateway mTLS like every bank endpoint.

```bash
curl -s -X POST "$BASE/v1/authorizations/$AUTHORIZATION_ID/verification-sessions/$SESSION_ID/complete" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"sessionNonce":"'"$SESSION_NONCE"'","result":"VERIFIED","providerReference":"prov-5521","assertion":"<provider JWS>"}'
```

Auth Core stores the SHA-256 of `assertion` and includes the factor in the evidence. Auth Core does not verify the assertion: the AUDIO or VIDEO factor in the evidence is the bank's (or its provider's) statement, bound to the session nonce, not a cryptographic proof that Auth Core checked (NXS-019, open). Validating the provider's assertion is the gateway's task. A failed AUDIO check escalates to VIDEO when VIDEO is enabled; a failed last factor sets the plan to `FAILED` and the authorization to `REJECTED`. The model is specified in [adaptive verification](../architecture/adaptive-verification.md).

## 12. Retrieve and verify evidence

Each NEXUS ID has one evidence chain. It holds `AUTHORIZATION` records (a confirmed transaction), `CREDENTIAL_ENROLLED` records (the keys and attestation of each enrolled device) and `RECOVERY_CONFIGURED` records (the recovery key a device registered), numbered from 1 (`chainSequence`), hash-linked and sealed by the HSM. Record format and rules: [evidence format](../protocol/evidence-format.md).

### Store the chain head

Auth Core returns chain positions, `{evidenceId, chainSequence, evidenceHash}`, in:

| Response | Field |
|---|---|
| `POST .../signature`, `POST .../offline-confirmation` with `VERIFIED` | `evidence` |
| `GET /v1/authorizations/{id}` of a `VERIFIED` authorization | `evidence`: the position of that authorization's record, not necessarily the latest |
| `GET /v1/nexus-identities/{nexusId}` | `evidenceHead`: the latest record |
| `GET /v1/nexus-identities/{nexusId}/evidence` | `head`: the latest record |

The bank stores, per NEXUS ID, the position with the highest `chainSequence` it has received, in its own systems and never only in Auth Core, and keeps the earlier ones with the transactions they belong to. A stored head lets the bank detect later that records were removed or replaced, including by someone with access to the Auth Core database. The `credential.replaced` webhook carries the `enrolmentEvidenceHash` of the new device's record.

### Retrieve

```bash
curl -s "$BASE/v1/authorizations/$AUTHORIZATION_ID/evidence" -H "Authorization: Bearer $TOKEN" > record.json
curl -s "$BASE/v1/nexus-identities/418273650/evidence?after=0&limit=1000" -H "Authorization: Bearer $TOKEN" > chain.json
```

The first call returns the record of one `VERIFIED` authorization (404 for any other state) together with the `CREDENTIAL_ENROLLED` record of its credential, so it verifies on its own. The second returns the chain in `chainSequence` order, at most `limit` records (1 to 1000, default 1000) after `after`, and `head`. A longer chain is read page by page with `after` set to the last `chainSequence` received; the verifier needs all records from 1 in one file ([how to combine the pages](../operations/runbooks/evidence-verification-failure.md#running-the-offline-check)). Both responses include `evidencePublicKeyPem` (the current evidence key) and `evidencePublicKeys` (every evidence key the deployment accepts, by key ID).

### Verify

```bash
node scripts/verify-evidence.mjs chain.json --public-keys=evidence-keys.pem --expect-head=7:3f9a...e1
node scripts/verify-evidence.mjs record.json --public-keys=evidence-keys.pem
```

| Option | Use |
|---|---|
| `--public-keys=<file>` | PEM file with every evidence public key, obtained out of band from the deployment's key ceremony record. Without it the script trusts the keys in the export, which Auth Core supplied |
| `--expect-head=<chainSequence>:<evidenceHash>` | A head the bank stored. The check fails with `records missing at the end of the chain` when the chain ends before it, and with `differs from the head the bank received` when the record at that position was replaced |

The verifier checks each record's hash and HSM seal, the chain numbering and links, that every authorization was signed with the key sealed at its credential's enrolment, and the customer's signature over the signed bytes. It runs from a checkout of the release (`auth-core/scripts/`), needs Node.js only and makes no network calls. A failure is handled with the [evidence verification runbook](../operations/runbooks/evidence-verification-failure.md).

Records sealed by Auth Core 1.4 or earlier verify, but carry no sealed key provenance; the summary counts them as `legacy_records`. The keys of credentials enrolled before 2.0 were sealed once during the upgrade (reason `BASELINE`); such a record states the keys the database held at that time.

## 13. Recovery

The protocol is specified in [recovery protocol 2](../protocol/recovery-protocol-v2.md).

The customer has a new phone and the recovery phrase. The phrase must have been set up with SDK 2.0 on an earlier device (`generateRecoveryPhrase` in the SDK); otherwise Auth Core returns 409 `Recovery has not been configured for this NEXUS ID`.

1. The bank re-identifies the customer through its own controls.
2. The bank backend opens a recovery session:

   ```bash
   curl -s -X POST "$BASE/v1/recovery/sessions" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"bankCustomerRef":"CUST-0042"}'
   ```

   The 201 response carries:

   | Field | Content |
   |---|---|
   | `sessionId`, `nexusId` | The session and the identity |
   | `nonce` | One-time challenge the device signs |
   | `accessToken` | `rc_...`, authorizes the device to complete this session |
   | `parameters` | `protocol` (2), `kdf` (`PBKDF2-HMAC-SHA256`), `iterations`, `keyLength`, `salt` |
   | `recoveryPublicKeyPem` | The identity's recovery public key |
   | `wrappedRecoveryKey` | The recovery private key, encrypted under a key derived from the phrase (base64) |
   | `expiresAt` | 600 seconds after creation |

3. The bank backend hands the whole response to the app, unchanged, and the app calls `recoverIdentity` with it and the phrase. The device opens `wrappedRecoveryKey` with the phrase and signs the session, the nonce, the identity and its new signing key. A wrong phrase fails on the device and uses no attempt on the server.
4. On success Auth Core revokes all credentials of the NEXUS ID, cancels its `PENDING_USER` authorizations, registers the new key, seals its enrolment with reason `RECOVERY` and sends the `identity.recovered` webhook. The app sends the new credential ID to the bank backend, which checks it as in step 5.

Five failed proofs lock the session; the bank opens a new one. A session is single use. Opening a session is refused with 409 and a `code` when:

| `code` | Meaning |
|---|---|
| `RECOVERY_LOCKED` | 10 failed proofs for this customer in sessions opened during the last 24 hours. The lock ends as those sessions age out; replacement (step 5) remains possible |
| `RECOVERY_PROTOCOL_RETIRED` | The phrase was set up with recovery protocol 1 (SDK 1.4 or earlier), which Auth Core no longer accepts. The customer sets up a new phrase on an enrolled device, or the bank uses device replacement |
| `RECOVERY_INTEGRITY` | The stored recovery configuration is not the identity's latest sealed one, or its key, salt or iteration count differ from what was sealed at setup. Treat as a security incident |

Recovery completion also answers 409 `RECOVERY_INTEGRITY` when the stored recovery key no longer matches the latest sealed record; the bank treats it as a security incident.

What the bank takes into account:

- The bank's decision to open a recovery session (step 1) is the control that a stolen phrase alone cannot pass. Auth Core stores only the recovery public key and the wrapped private key; neither is enough to complete a recovery without the phrase.
- Setting up or replacing the recovery phrase (`POST /v1/mobile/recovery/setup`) is signed with the device's biometric signing key and uses a salt issued for that device; the bank receives `recovery.configured`.

## 14. Revoke a lost device

```bash
curl -s -X POST "$BASE/v1/credentials/$CREDENTIAL_ID/revoke" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"reason":"DEVICE_LOST"}'
```

The credential becomes `REVOKED` at once. Its `PENDING_USER` authorizations are `CANCELLED`, device-signed requests of that credential are refused, offline codes for it are rejected, and commit requests for authorizations it confirmed are refused with 409 `CREDENTIAL_NOT_ACTIVE`. A second revoke of the same credential returns 404.

The customer then enrols a new device with a `BOOTSTRAP` token (step 4), which no longer needs `replacement` because no enrolled credential is left, or through recovery (step 13) when the bank requires the phrase.

Actions on a whole NEXUS ID are taken by operators in the admin console, not by the bank API:

| Action | Approval | Effect |
|---|---|---|
| Suspend (`/admin/api/identities/{nexusId}/suspend`) | One operator | Cancels open authorizations; refuses mobile requests, new authorizations, confirmations, enrolment and recovery until reactivated |
| Reactivate (`.../reactivate`) | A second admin with access to the bank approves | Restores the identity with its existing credential |
| Revoke (`.../revoke`) | A second admin with access to the bank approves | Final: the identity and its credentials are revoked |

Reactivation and revocation are answered with 202 and an approval request that expires after `ADMIN_APPROVAL_TTL_HOURS` (default 24); they take effect when the second admin approves. Admin accounts can be limited to one bank's identities.
