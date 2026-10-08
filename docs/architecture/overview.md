# Architecture overview

## Customer-facing boundary

The customer uses the bank's existing mobile application. NEXUS-SIGN is an embedded native SDK (iOS, Android). It is not presented to the customer as a separate product, and the customer never installs a separate application.

## Components

| Component | Runs in | Responsibility |
|---|---|---|
| Auth Core | Bank data centre or private cloud | Authorization objects, credential registry, mobile tokens, attestation verification, signature verification, adaptive verification, evidence and its export, bank commit tracking, webhooks, secure push delivery (push mode `NEXUS`) |
| iOS SDK | Bank app | Secure Enclave keys (signing, request authentication, offline), App Attest, payload verification, biometric-gated signing, offline confirmation, recovery, opening secure push messages (also in the notification service extension) |
| Android SDK | Bank app | Keystore keys (StrongBox first, TEE fallback) with Keystore key attestation, Play Integrity, payload verification, biometric-gated signing, offline confirmation, recovery, opening secure push messages |
| APNs, FCM | Apple, Google | Transport of sealed push envelopes in push mode `NEXUS`; they cannot read them |
| HSM / KMS | Bank | Evidence sealing through PKCS#11 |
| API gateway | Bank | TLS termination, client mTLS for bank systems, WAF, rate limiting |

## Authorization flow

```text
Bank backend ──(OAuth2 + mTLS)──► Auth Core: POST /v1/authorizations
                                     │ canonical authorization object v1
                                     │ + verification plan (same transaction)
                                     ▼
Bank app + SDK ◄─(device-signed)─── GET /v1/mobile/authorizations/{id}
   │  1. parse and verify the canonical bytes
   │  2. show the transaction from those bytes
   │  3. biometric prompt, sign the bytes (ECDSA P-256)
   ▼
Auth Core: POST /v1/mobile/authorizations/{id}/signature
   │  verify signature against the registered credential
   │  check adaptive verification plan (PUSH / AUDIO / VIDEO)
   │  consume authorization atomically, seal evidence in the HSM
   ▼
Bank backend: bank-commit-request → core banking → bank-commit-result
              (webhooks for every state change; GET …/bank-transaction for polling)
```

The wire format is specified in [authorization-protocol-v1.md](../protocol/authorization-protocol-v1.md), step-up verification in [adaptive-verification.md](adaptive-verification.md), and the evidence record and its offline verification in [evidence-format.md](../protocol/evidence-format.md).

## Push delivery

How the authorization request reaches the phone depends on the bank client's push mode. In `BANK` mode the bank's own push system sends it and the app fetches the authorization. In `NEXUS` mode Auth Core sends it, and the bank's other notifications, through APNs and FCM, each sealed for one device ([secure push](../protocol/secure-push.md)):

```text
Bank backend ── POST /v1/authorizations or /v1/push-messages ──► Auth Core: seal for the device, queue
Auth Core ── envelope ──► APNs / FCM ──► bank app: decrypt, show, receipt ──► Auth Core ── push.delivered ──► bank
```

## Enrolment

The bank backend creates a NEXUS ID, then requests a single-use `BOOTSTRAP` token for it (`POST /v1/mobile/sessions`) and hands it to its app. The SDK generates its signing, authentication and offline keys in the Secure Enclave or Keystore, obtains App Attest or Play Integrity and Keystore key attestation evidence bound to the token and all three keys, and calls `POST /v1/mobile/bootstrap`. Auth Core verifies the attestation, takes the credential's security level from it, registers the credential and seals its keys in the identity's evidence chain. A `BOOTSTRAP` token for an identity that already has an enrolled device is refused (409 `ACTIVE_CREDENTIAL_EXISTS`) unless the bank authorizes a [device replacement](device-replacement.md); otherwise the customer moves to a new device by [recovery](../protocol/recovery-protocol-v2.md). From then on the phone signs its own requests and needs no token ([device authentication and offline confirmation](../protocol/device-authentication-and-offline-confirmation.md)).

## Offline confirmation

```text
Bank screen ── GET /v1/authorizations/{id}/offline-challenge ──► QR code (canonical bytes)
Phone, no network: verify bytes → show transaction → biometric → 8-digit code
Bank screen ── POST /v1/authorizations/{id}/offline-confirmation {code} ──► VERIFIED, evidence sealed
```

## Identity continuity

A NEXUS ID is a stable nine-digit identity anchor. Credential IDs are lifecycle objects: they are revoked, or replaced by device replacement or recovery, without changing the NEXUS ID. Neither telecom identifiers (MSISDN, SIM) nor device identifiers are used as the identity root.

## Responsibility split

The bank remains authoritative for the customer relationship, account state, fraud and risk policy, and transaction execution. NEXUS-SIGN provides cryptographic authorization and verifiable evidence. It does not replace core banking, fraud systems, IAM, HSM/KMS or scheme-specific controls.
