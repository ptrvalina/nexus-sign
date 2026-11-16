# Offline confirmation v2: deferred device signature

Status: implemented in Auth Core and the Android SDK (JVM tests), written for the iOS SDK (not compiled in this environment). Decision record: [ADR 0018](../adr/0018-deferred-device-signature.md). Threat model: [offline confirmation threat model](../security/offline-confirmation-threat-model.md). Version 1 (code only) is described in [device authentication and offline confirmation](device-authentication-and-offline-confirmation.md) and remains available outside production.

## Why

An offline code (v1) is an HMAC under a key `K` that Auth Core also holds. Whoever controls a running Auth Core, or holds the database together with the device master key (and, with `MASTER_KEY_SOURCE=hsm`, reach to the HSM), can compute a code that Auth Core accepts. In v2 Auth Core does not report a payment as `VERIFIED` on the code alone: it also needs an ECDSA signature by the device's signing key, which never leaves the phone's secure hardware. The phone makes that signature during the same confirmation, keeps it, and uploads it when it has a network connection.

## What is signed

The **existing canonical authorization bytes** of [protocol v1](authorization-protocol-v1.md), unchanged, with the **existing device signing key and algorithm** (ECDSA P-256, SHA-256, `der` or `raw`). There is no second format. The bytes already bind:

| Requirement | Field in the signed bytes |
|---|---|
| Protocol version | `protocol_version: "1"` |
| Purpose of the signature | `domain: "NEXUS-SIGN/TRANSACTION-AUTH"` |
| NEXUS ID and registered key | `nexus_id`, `credential_id` (the credential whose signing key must sign) |
| Unique operation | `authorization_id`, `transaction_reference` |
| Amount and currency | `amount_minor`, `currency` |
| Payee and other critical terms | `beneficiary`, `operation_type` |
| Validity | `issued_at`, `expires_at` |
| One-time value | `nonce` (32 random bytes) |
| Policy context and version | `policy_reference`, `policy_version` |

Consequence: a deferred signature is cryptographically the same statement as an online signature of the same authorization — "the enrolled device, after local user authentication, approved these exact bytes". Using it online would confirm the same immutable terms; an authorization is consumed once, so it cannot be confirmed twice.

## QR prefix

| Prefix | Meaning | Old SDKs (≤ 2.0.0) | SDK with v2 |
|---|---|---|---|
| `NXS1.` | v1: code only | code | code (no signature) |
| `NXS2.` | v2: signature and code | **refuse the QR** (`invalid_qr`) | signature, then code |

The bytes after the prefix are the same base64url canonical bytes. Auth Core issues `NXS2.` when `OFFLINE_CONFIRMATION_MODE=deferred_signature` (the default). Old SDKs fail closed: they cannot produce a code that would leave a payment provisional forever.

## Device steps (NXS2)

1. Parse the QR exactly as for v1 (strict canonical check, own `credential_id`, not expired by the phone's clock).
2. Show the terms from the bytes. Authenticate the user and **sign the bytes with the signing key**.
   - iOS: one `LAContext` evaluation authorizes the signing key and the offline key (one prompt).
   - Android: the signing key and the offline HMAC key each need their own `CryptoObject`, so there are **two prompts**, both showing the terms.
3. **Store** `{authorizationId, signature, signatureFormat, createdAt}` in the SDK's pending store. Only after the store succeeded:
4. Compute the 8-digit code as in v1 and show it. Without step 3 there is no code.
5. When online — the host app calls `submitPendingOfflineSignatures()` at start-up and whenever the connection returns — upload each pending item. Items older than 30 days (the longest possible deadline) are dropped without upload.

## Upload

`POST /v1/mobile/authorizations/{id}/deferred-signature`, device-signed (device request protocol v1), body `{ "signature": "<base64>", "signatureFormat": "der" | "raw" }`.

| Response | Meaning | SDK keeps the item? |
|---|---|---|
| `200 {status: "VERIFIED", evidence}` | The code had been accepted; the authorization is now `VERIFIED` | no |
| `202 {status: "RECEIVED"}` | Signature valid and stored; the code has not been submitted yet. The code, when it arrives, finalizes at once | no |
| `200 {status: "ALREADY_RECORDED"}` | This exact signature is already stored or used (repeat delivery) | no |
| `409 NOT_AWAITING_SIGNATURE` | The authorization is final (expired, rejected, cancelled, confirmed otherwise, missing signature recorded), or the deployment runs v1 | no |
| `422 INVALID_DEFERRED_SIGNATURE` | The signature does not verify over the stored bytes with the credential's sealed key | no (reported to the host app) |
| `403` | The request is signed by another credential than the one the authorization names | no |
| network error, `429`, `5xx` | Not processed | **yes**, retried |

Owner decision: `OFFLINE_PROVISIONAL` is not an authorization to execute; there is no configuration or API that lets an integration treat it as `VERIFIED`. The bank's `GET` carries `confirmed: true` only for `VERIFIED`, and `bank-commit-request` re-verifies the sealed evidence before it accepts.

Auth Core never decides on the signature alone: a valid signature for a `PENDING_USER` authorization is stored, not used to confirm it. The authorization becomes `VERIFIED` only when **both** the code (through the bank) and the signature (from the device) have been accepted.

## Authorization states

```text
                 online signature / v1 code / v2 code with stored signature
 PENDING_USER ───────────────────────────────────────────────────────────────▶ VERIFIED
     │  │ │                                                                       ▲
     │  │ └─ expiry ─▶ EXPIRED      bank cancel ─▶ CANCELLED      5 failures ─▶ REJECTED
     │  │                                                                       │
     │  └─ v2 code accepted, no signature yet ─▶ OFFLINE_PROVISIONAL ── signature ┘
     │                                                │
     │                                                └─ deadline passed, or credential no longer ACTIVE
     │                                                          ─▶ OFFLINE_UNSIGNED (final)
```

- `OFFLINE_PROVISIONAL` is neither open nor final. No further code, signature or cancellation applies to it, except the deferred signature. The bank cannot request a commit through Auth Core (`bank-commit-request` needs `VERIFIED`).
- The authorization's `expires_at` governs only `PENDING_USER`. A provisional authorization is finalized by the signature until `offline_signature_deadline` (`OFFLINE_SIGNATURE_DEADLINE_HOURS` after the code, default 72, 1 to 720).
- `OFFLINE_UNSIGNED` is final: a code was accepted and no valid device signature arrived. It is a security event (audit `offline_signature_missing`, webhook `authorization.offline_unsigned`). A signature arriving later is answered with 409 and recorded in the audit log (`deferred_signature_late`, with whether it verified), never used.
- The database trigger permits exactly these transitions; the offline columns are written once.

## Server checks

On upload, in one transaction holding the verification plan lock and the authorization row lock:

1. The request is device-signed by the credential the authorization names (`credential_id`), which is `ACTIVE`, whose identity is `ACTIVE`, and whose keys match its sealed enrolment record.
2. The stored terms still hash to `canonical_payload_hash`.
3. The signature verifies over the canonical bytes with the credential's signing key.
4. State `PENDING_USER` (v2 deployment, not past `expires_at`): store the signature (`offline_deferred_signatures`, one per authorization); answer `RECEIVED`.
5. State `OFFLINE_PROVISIONAL`, before the deadline: store it, move to `VERIFIED` with `confirmation_method = OFFLINE_SIGNED`, seal evidence, queue `authorization.verified`.
6. A repeat of a stored signature: `ALREADY_RECORDED`; a different one for an authorization that already has one: 409.

On the code (bank `POST /v1/authorizations/{id}/offline-confirmation`, v2 deployment): the v1 checks (state, expiry, identity, credential, plan, amount cap, daily ceiling, constant-time comparison, attempt limit), then, under the same locks, either a stored signature that verifies again → `VERIFIED`, or → `OFFLINE_PROVISIONAL` and the result `{status: "PROVISIONAL", signatureDeadline}` with webhook `authorization.offline_provisional`.

The daily ceiling per credential counts accepted codes (`offline_code_accepted_at`), provisional or not.

## Evidence

The `AUTHORIZATION` record of an authorization confirmed with v2 has:

| Field | Value |
|---|---|
| `confirmationMethod` | `OFFLINE_SIGNED` |
| `signature`, `signatureFormat`, `signatureAlgorithm` | the device's ECDSA signature, `der`/`raw`, `ES256` — verifiable by anyone with the enrolment record |
| `offlineCodeTag` | base64 HMAC tag of the accepted code (as in v1 records; not verifiable by a third party) |
| `offlineCodeAcceptedAt` | when Auth Core accepted the code |
| `deferredSignatureReceivedAt` | when the device's signature arrived |
| `verifiedAt` | when the authorization became `VERIFIED` |

Nothing is sealed for `OFFLINE_PROVISIONAL` or `OFFLINE_UNSIGNED`: the chain holds confirmed transactions only; both states are in the audit log and the webhooks.

`scripts/verify-evidence.mjs` verifies the ECDSA signature of `OFFLINE_SIGNED` records exactly as for `DEVICE_SIGNATURE`. Verifiers older than this change report `unknown confirmation method OFFLINE_SIGNED` and fail the record: **update the verifier before relying on v2 records.** `--reject-offline-code` makes the verifier fail every `OFFLINE_CODE` (v1) record, for banks that have moved to v2 and must not accept a code-only confirmation from any date on.

## What the signature proves, and what it does not

Proves (given the enrolment record and a verifier):

- The signing key enrolled for this credential signed these exact terms (amount, currency, payee, reference, policy, expiry, nonce). Auth Core, the database and the bank cannot produce it.
- With the platform's key policy (biometric on every use, ADR 0011), the key was used after a successful local user authentication on that phone.

Does not prove:

- **When** it was signed. The phone checks `expires_at` with its own clock; nothing proves the phone's time.
- That the customer read the terms or understood them; only that the phone displayed them from the signed bytes before the prompt.
- That the operation was still current: offline, the phone cannot learn that the authorization was cancelled, already confirmed, or that the credential was revoked. Auth Core enforces those at upload.
- That the phone was not compromised at signing time (malware with a biometric bypass, Integrity is attested only at enrolment).
- That the payment may be executed. The signature authorizes nothing by itself: **the bank remains the source of truth** for the account, limits, risk and execution.

## Compatibility

| Party | Effect | Boundary |
|---|---|---|
| Bank backend | `POST …/offline-confirmation` may answer `status: PROVISIONAL`; new states `OFFLINE_PROVISIONAL`, `OFFLINE_UNSIGNED`; new webhooks `authorization.offline_provisional`, `authorization.offline_unsigned`; `confirmationMethod: OFFLINE_SIGNED` in `authorization.verified` | A bank that only proceeds on `VERIFIED` is safe without changes. A bank that treats "not FAILED" as success is not: it must handle `PROVISIONAL` |
| Bank screen | QR prefix `NXS2.` | Opaque to the bank |
| SDK ≤ 2.0.0 on a v2 deployment | Refuses the `NXS2.` QR | Offline confirmation unavailable for these customers until the app ships the new SDK; online confirmation unaffected |
| SDK with v2 on a v1 deployment | `NXS1.`: code only, as before | none |
| Evidence verifiers | `OFFLINE_SIGNED` unknown to old verifiers | update first |
| Existing data | `VERIFIED`/`OFFLINE_CODE` rows and records unchanged | migration 022 is additive |
| Production | `OFFLINE_CONFIRMATION_ENABLED=true` requires `OFFLINE_CONFIRMATION_MODE=deferred_signature` | v1 only outside production |

Migration: apply `022_offline_deferred_signature.sql` (additive: wider state column, new columns, new table, new trigger function), deploy Auth Core, update evidence verifiers at the banks, ship the SDK in the bank apps, then switch `OFFLINE_CONFIRMATION_MODE` (already the default for new configurations). Rolling back Auth Core to 2.0.0-rc.2 after `OFFLINE_PROVISIONAL` rows exist is not supported: the old code does not know the states; finalize or let them reach `OFFLINE_UNSIGNED` first.

## Failure and ordering cases

| Case | Behaviour |
|---|---|
| Signature uploaded before the code | Stored (`RECEIVED`); the code finalizes directly to `VERIFIED` |
| Code first, phone online days later | `OFFLINE_PROVISIONAL` until the upload or the deadline |
| Upload lost (no response) | The SDK keeps the item and retries; a repeat is `ALREADY_RECORDED` |
| Two uploads at once | Serialized by the row lock; one transition, the other `ALREADY_RECORDED` |
| Auth Core stops between receipt and commit | Nothing is committed; the SDK retries; state unchanged |
| Database restored to a point before the upload | The SDK already deleted the item; the authorization ends `OFFLINE_UNSIGNED` (a false alarm, never a false `VERIFIED`); the bank's retained chain heads show records that disappeared (`verify-evidence --heads`) |
| Credential revoked or replaced while provisional | The phone can no longer sign requests; the sweep moves the authorization to `OFFLINE_UNSIGNED` (`reason: credential_not_active`) |
| Identity suspended while provisional | Upload refused (409); the sweep records `OFFLINE_UNSIGNED` (`identity_not_active`), also if the identity is reactivated later: the bank re-confirms the payment online |
| Signature for other terms, another authorization, another key, unknown format | 422 or 403; state unchanged; audit `deferred_signature_invalid` |
| Signature after the deadline | 409; audit `deferred_signature_late` (verified true/false) |
| Bank unreachable | Webhooks are queued in the outbox and retried; the bank can poll `GET /v1/authorizations/{id}` |
| Uncertain state (row missing, integrity check fails, key differs from enrolment) | Refused; nothing changes |

## Test matrix

`auth-core/test/integration/offline-deferred-signature.test.mjs` (19 tests). 13 server-side mutations, each removing one protection, were run against it; the results are in the phase 8 report.

| # | Case | Expected |
|---|---|---|
| 1 | Code then signature | `PROVISIONAL` → `VERIFIED`, evidence `OFFLINE_SIGNED`, ECDSA verifies offline |
| 2 | Signature then code | `RECEIVED` → code → `VERIFIED` |
| 3 | Signature over changed amount / changed payee / another authorization | 422, state unchanged |
| 4 | Signature by another device's key; request signed by another credential | 422 / 403 |
| 5 | Revoked credential while provisional | upload refused, sweep → `OFFLINE_UNSIGNED` |
| 6 | Unknown signature format, malformed base64 | 400 |
| 7 | Expired `PENDING_USER` | 409 |
| 8 | Deadline passed | sweep → `OFFLINE_UNSIGNED`; late signature 409 and audited |
| 8b | Deadline passed, sweep not yet run | upload 409; the sweep, not the upload, records `OFFLINE_UNSIGNED` |
| 9 | Repeat delivery | `ALREADY_RECORDED`; one evidence record |
| 10 | Two concurrent uploads, two concurrent codes | exactly one transition, one evidence record |
| 11 | Server killed while the upload waits for the row lock; restart; retry | no change before, `VERIFIED` after |
| 12 | Already `VERIFIED` online | 409 |
| 13 | Evidence substitution (`OFFLINE_SIGNED` record with the signature replaced) | verifier fails the record |
| 14 | Stored terms changed / policy version changed | refused by the trigger; no finalization |
| 15 | Database-only attacker inserts a signature row | finalization re-verifies and refuses |
| 16 | Forged code with `K` (insider) | only `PROVISIONAL`, never `VERIFIED`; ends `OFFLINE_UNSIGNED` |
| 17 | v1 deployment | `NXS1.`, code → `VERIFIED` (`OFFLINE_CODE`), upload 409 |
| 18 | Production posture with v1 | startup refused |
| 19 | Daily ceiling counts provisional confirmations | limit applies |
| 20 | `--reject-offline-code` | v1 records fail |
