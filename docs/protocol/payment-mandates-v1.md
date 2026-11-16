# Payment mandates v1

Status: unreleased, planned for 2.0.0 (current version 2.0.0-rc.2). Implementation: `auth-core/src/services/mandateService.ts`, migration `028_payment_mandates.sql`. Tests: `auth-core/test/integration/mandates.test.mjs` (PostgreSQL).

A mandate lets the bank debit a customer repeatedly for one payee, within limits the customer signed once on an enrolled device. It covers presentation pages 17 to 19.

## Terms and signature

The bank proposes a mandate with `POST /v1/mandates` for one of the customer's devices (`credentialId`). Auth Core builds the canonical terms object, encodes it with the same canonical JSON as the authorization protocol (keys sorted recursively, UTF-8, no insignificant whitespace) and stores the bytes and their SHA-256 (`termsHash`):

| Field | Content |
|---|---|
| `protocol_version` | `"1"` |
| `domain` | `"NEXUS-SIGN/MANDATE"`. Payment authorizations use `"NEXUS-SIGN/TRANSACTION-AUTH"`: a signature over one can never verify as the other, and the SDK must check the domain before it shows or signs anything |
| `mandate_id`, `nexus_id`, `credential_id` | Who signs what |
| `mandate_reference` | The bank's reference (display text rules apply) |
| `payee` | Same rules as an authorization beneficiary |
| `currency`, `per_payment_limit_minor`, `total_limit_minor` | ISO 4217 code; integer decimal strings; `total_limit_minor` is `null` when there is no total limit |
| `frequency` | `WEEKLY`, `MONTHLY`, `QUARTERLY` or `YEARLY`: at most one allowed debit per UTC calendar period |
| `valid_from`, `valid_until` | RFC 3339 UTC |
| `terms_version` | The version of the bank's mandate conditions the customer accepts |
| `issued_at`, `offer_expires_at`, `nonce` | When the offer was made, until when it may be signed (60 s to 7 days, default 1 day), 32 random bytes in hex |

The device fetches the terms (`GET /v1/mobile/mandates/{id}`, `termsBase64`), shows them from those bytes only and signs them with the signing key (ECDSA P-256, SHA-256, DER or raw) after biometric authentication. `POST /v1/mobile/mandates/{id}/signature` is accepted only from the addressed device, while the offer is open, with an intact credential (its keys match its sealed enrolment) and a signature that verifies over the stored bytes. The mandate then becomes `ACTIVE`.

Signed terms are immutable (trigger `mandates_lifecycle`). The bank cannot change them; changed terms are a new mandate the customer signs.

## States

| From | To | By |
|---|---|---|
| `PENDING_SIGNATURE` | `ACTIVE` | The addressed device's signature |
| `PENDING_SIGNATURE` | `DECLINED` | The customer (any active device) |
| `PENDING_SIGNATURE` | `EXPIRED` | The offer was not signed in time |
| `ACTIVE` | `SUSPENDED` | The customer |
| `SUSPENDED` | `ACTIVE` | The customer resumes under the same signed terms |
| `ACTIVE`, `SUSPENDED` | `REVOKED` | The customer; final |
| any non-final | `WITHDRAWN` | The bank (`POST /v1/mandates/{id}/withdraw`); final |
| `ACTIVE`, `SUSPENDED` | `EXPIRED` | `valid_until` passed (expiry sweep); final |

Every transition is sealed into the identity's evidence chain as a `MANDATE` record and sent to the bank as a webhook (`mandate.signed`, `mandate.declined`, `mandate.suspended`, `mandate.resumed`, `mandate.revoked`, `mandate.withdrawn`, `mandate.expired`).

## Debits

Before each debit the bank calls `POST /v1/mandates/{id}/debits` with its own `debitReference`, the amount and the currency. Auth Core allows the debit only when the mandate is `ACTIVE`, within `valid_from`/`valid_until`, in its currency, not above `per_payment_limit_minor`, with no other debit allowed in the same period and, with the debits allowed so far, not above `total_limit_minor`. Every decision, allowed or refused, is recorded in `mandate_debits` (append-only) with the mandate row locked, so concurrent requests are decided one after the other. The call is idempotent per `debitReference`; the same reference with another amount or currency is refused.

The database repeats the decision: the trigger `mandate_debits_check` refuses an `ALLOWED` row outside the signed terms, whoever writes it. A refused debit answers 409 `MANDATE_DEBIT_REFUSED` with the reason and sends `mandate.debit_refused`.

## Evidence

A `MANDATE` record carries `mandateId`, `credentialId`, `event`, `termsHash`, `mandateReference`, `reason`, `occurredAt` and the `enrolmentEvidenceHash` of the device. A `SIGNED` record also carries the terms bytes (`signedTermsBase64`), the signature, its format and the device public key. `verify-evidence.mjs` checks that the terms hash to `termsHash`, are mandate terms (domain) of this mandate, identity and credential, that the signature verifies, and that the key is the one sealed at the device's enrolment earlier in the chain.

## Limits of this version

- Auth Core decides the debit; the bank's own payment execution (`bank-integration/`) does not yet re-verify the mandate signature in the bank database the way it re-verifies payment signatures.
- Periods are UTC calendar periods; a bank that bills in another time zone sets `valid_from` accordingly.
- The SDK methods to show and sign mandates are written but have not been compiled or run on a device.
