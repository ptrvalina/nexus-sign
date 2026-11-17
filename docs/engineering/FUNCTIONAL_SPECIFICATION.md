# Functional specification

What NEXUS-SIGN does, for whom, through which interface, under which rules. It describes the code on branch `engineering/production-readiness`; the API contract is [`auth-core/openapi.yaml`](../../auth-core/openapi.yaml) (92 routes), the protocols are in [docs/protocol](../protocol/README.md), and the status of each function against the product presentation is in the [functional coverage matrix](FUNCTIONAL_COMPLETENESS_MATRIX.md).

## 1. Purpose and actors

NEXUS-SIGN is a security layer a bank runs inside its perimeter. The customer confirms payments and other operations in the bank's own app with a key that never leaves the phone's secure hardware; the bank gets a signature it verifies itself and a sealed record of every outcome.

| Actor | Interface | Authenticated by |
|---|---|---|
| Customer | The bank's app with the NEXUS-SIGN SDK (iOS, Android) | Device keys in secure hardware, biometric per signature |
| Bank backend | Bank API `/v1/…` | OAuth client credentials + mTLS through the bank's gateway |
| Bank database | `bank.*` functions (bank integration kit) | The bank's own roles |
| Bank staff | Admin console `/admin` and `/admin/api/…` | Password + TOTP; roles `auditor`, `operator`, `administrator`; scoped to one bank |
| Platform operator | Console (no bank), CLIs | As above; read-only towards banks' customers |
| Bank's bot | Webhooks and `/v1/conversations/{id}/bot-messages` | Bank client |

## 2. Functions

### 2.1 Identity and devices

| Function | Rules | Interface |
|---|---|---|
| Create a NEXUS ID | Nine digits, unique, independent of phone and SIM; a retried creation returns the same ID (200, `replayed`) | `POST /v1/nexus-identities` |
| Enrol a device | One-time bootstrap token from the bank; attestation (App Attest, Key Attestation + Play Integrity) bound to the challenge and to all keys; enrolment sealed as evidence | Bank `POST /v1/mobile/sessions`, SDK `bootstrap` (`/v1/mobile/bootstrap`) |
| Several devices | Up to the bank's `max_devices_per_identity` (default 1), enforced by the database; a new device is added by a bank request approved from an enrolled device or after the hold | Bank `POST /v1/mobile/sessions` with `addition`; SDK `devices()`, `/v1/mobile/device-replacements` |
| Replace a device | Request with a hold (default 24 h); the enrolled device approves or cancels; staff may stop an open request | as above; console |
| Remove a device | Customer from another device, the bank, or staff in the console; open payments to it are cancelled; revocation sealed | SDK `removeDevice`, `POST /v1/credentials/{id}/revoke`, console |
| Biometric change | Keys become invalid; the SDK deletes them and the registration on both platforms; re-enrolment by replacement or recovery | [biometric behaviour](../architecture/biometric-behaviour.md) |
| Recovery | Phrase-protected recovery key, single use; old devices revoked and told | [recovery v2](../protocol/recovery-protocol-v2.md) |
| Suspend / reactivate | Customer suspends; bank suspends and reactivates with a re-identification reference; console revocation and reactivation need two staff members | SDK `suspendIdentity`, bank API, console |

### 2.2 Payment authorization

| Function | Rules | Interface |
|---|---|---|
| Create | Bank sends amount, currency, payee, reference, validity, device; Auth Core builds the 15-field canonical payload, checks the display rules and the customer's limits, plans verification (push, audio, video) | `POST /v1/authorizations` |
| Confirm | The SDK shows the labelled prompt built from the signed bytes and signs with the biometric-bound key; Auth Core verifies and seals | SDK `approve`, `/v1/mobile/authorizations/{id}/signature` |
| Decline ("it wasn't me") | Outcome `REJECTED` with reason, sealed, bank told by webhook | SDK `decline` |
| Withdraw, expire | Bank withdraws; expiry at `expiresAt`; both sealed | `POST /v1/authorizations/{id}/cancel`, expiry worker |
| Offline | QR → 8-digit code (v2: plus deferred device signature); production accepts only v2 | [offline protocol](../protocol/device-authentication-and-offline-confirmation.md) |
| Bank commit | Only a `VERIFIED` authorization; the bank database verifies the signature, its own approval of the key, the terms and the window independently | `bank-commit-request`, `bank.approve` |
| Verification calls | Audio/video with an operator or provider as a step of one authorization; result signed and bound; never replaces the signature | [adaptive verification](../architecture/adaptive-verification.md) |

### 2.3 Mandates (recurring payments)

Terms (payee, currency, per-payment and total limits, frequency, validity) in their own signing domain, signed on the device after the SDK checks them; immutable; every debit checked by Auth Core and by the bank database; the customer suspends, resumes or revokes; the bank withdraws; staff hold (only a second staff member lifts it) or withdraw; every event sealed. [Payment mandates v1](../protocol/payment-mandates-v1.md).

### 2.4 Customer section

History (confirmed, declined, open), evidence of each payment, devices, security log (no staff names or addresses), notification feed, settings (channels, per-payment and daily limits, video threshold; relaxing waits `CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS`, tightening is immediate).

### 2.5 Conversations, bot and operators

Conversations per customer and bank; messages append-only and hash-chained; the bank's bot answers through webhooks and the API; the customer or the bot hands over to an operator, who answers from the console queue. [Customer conversations](../architecture/customer-conversations.md).

### 2.6 Calls the customer starts

Audio or video on channels the bank enables; one open call per NEXUS ID; queue in the console; one operator answers; WebRTC signalling relayed, media never through Auth Core; `MISSED` after `CUSTOMER_CALL_WAIT_SECONDS`, ended after `CUSTOMER_CALL_MAX_SECONDS` or on revocation; webhooks at each step. [Customer calls](../architecture/customer-calls.md).

### 2.7 Bank console

Statistics, audit log, webhooks, verification-call queue, customer-call queue, conversation queue, identity lookup with the customer's payments, mandates (detail, debits, event log, sealed records; hold, release, withdraw) and devices (trust, history, limit, events; revoke, stop a request), four-eyes approvals. [Bank console](../operations/bank-console.md).

### 2.8 Evidence, audit, monitoring

Sealed, chained evidence for every outcome, verifiable offline with the HSM public key ([evidence](../protocol/evidence-format.md)); append-only audit log, exportable as ECS JSON or CEF; Prometheus metrics for requests, push and webhook delivery, confirmations, sealed outcomes, the unsealed backlog and the HSM breaker ([monitoring](../operations/monitoring.md)).

## 3. Non-functional requirements met in code

| Area | Requirement | Where |
|---|---|---|
| Deployment | Inside the bank's perimeter; container; Kubernetes manifests | [deployment](../operations/deployment.md), [manifests](../../deploy/kubernetes/README.md) |
| HSM | Any PKCS#11 HSM; operations bounded in time; fail closed | [HSM acceptance](../operations/hsm-acceptance.md) |
| Availability | Stateless instances; PostgreSQL and Redis HA are the bank's | [disaster recovery](../operations/disaster-recovery.md) |
| Startup | Refuses to start in production without the required controls | [configuration](../operations/configuration.md#production-blockers) |
| Data | Migrations with a ledger; backup and restore keep the evidence verifiable | [migrations](../operations/database-migrations.md) |

## 4. Outside NEXUS-SIGN

Verification of the payee against the bank's records (Verification of Payee), identity proofing for recovery, the bank's anti-fraud decisions, push delivery infrastructure, PostgreSQL, Redis, the HSM, the API gateway, and the bank's own app screens around the SDK.
