# 0018. Offline confirmation v2: deferred device signature

## Status

Accepted for implementation on 2026-10-18 (phase 8). Implemented in Auth Core and the Android SDK (JVM tests); written for the iOS SDK, not compiled in this environment. Amends [ADR 0003](0003-offline-confirmation-hmac-codes.md). Production use additionally depends on the SDK builds and device checks in [RELEASE_GATES.md](../engineering/RELEASE_GATES.md).

## Date

2026-10-18

## Context

ADR 0003 confirms an offline payment with an 8-digit HMAC code under a key `K` shared by the phone and Auth Core. Whoever controls a running Auth Core, or holds the database with the device master key (and HSM reach when the key is wrapped), can compute accepted codes (FI-004). Amount caps and a daily ceiling bound the harm but leave the boundary where it was.

## Decision

1. During the offline confirmation the phone also signs the **existing canonical authorization bytes** with its **existing signing key** (ECDSA P-256), stores the signature and uploads it when online (`POST /v1/mobile/authorizations/{id}/deferred-signature`, device-signed). No new signed format: the bytes already bind version, purpose, identity, credential, operation, amount, currency, payee, policy, validity and nonce.
2. With `OFFLINE_CONFIRMATION_MODE=deferred_signature` (default; required in production) an accepted code moves the authorization to `OFFLINE_PROVISIONAL`. Only a valid signature from the bound credential makes it `VERIFIED` (`confirmationMethod: OFFLINE_SIGNED`). Without one by `OFFLINE_SIGNATURE_DEADLINE_HOURS` (default 72), or when the credential or identity stops being `ACTIVE`, it becomes `OFFLINE_UNSIGNED` (final, security event). A signature that arrives before the code is stored and finalizes when the code arrives. A signature alone never confirms.
3. The QR prefix `NXS2.` marks v2. SDKs up to 2.0.0 refuse it (fail closed); new SDKs read `NXS1.` and `NXS2.`.
4. The evidence record of a v2 confirmation carries the ECDSA signature, the accepted code's tag and both times; verifiers check the signature like an online one and can refuse every v1 record (`--reject-offline-code`).
5. Every transition is decided in one transaction on the locked authorization row; the database trigger allows exactly the new transitions and writes the offline fields once; the signature table is append-only.
6. v1 (`immediate`) remains for non-production deployments and existing data.

## Consequences

- A forged code without the phone yields at most `OFFLINE_PROVISIONAL`; Auth Core never reports it as confirmed. The bank still decides whether to wait (recommended) or to execute on `PROVISIONAL` at its own risk.
- New states and webhooks for banks; old evidence verifiers fail `OFFLINE_SIGNED` records (update first).
- Android needs two biometric prompts (one per key); iOS can use one evaluation for both keys.
- A fully offline payment is only provisionally proven until the phone is online again.
- Residual risks (compromised phone, forged v1 or enrolment records by a controlled Auth Core, provisional acted upon) are listed in the [threat model](../security/offline-confirmation-threat-model.md).
