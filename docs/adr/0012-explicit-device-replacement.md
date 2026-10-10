# 0012. Explicit, bank-authorized device replacement

## Status

Accepted

## Date

2026-10-06

## Context

A `BOOTSTRAP` token enrolled a device for a NEXUS ID and revoked any device enrolled before. Anyone who could obtain such a token from the bank backend, through a defect or a weak step in the bank's own flow, could move the customer's identity to another phone. The customer's device stopped working without explanation, and nothing distinguished a takeover from an ordinary first enrolment in the audit log or the evidence.

## Decision

- `POST /v1/mobile/sessions` with purpose `BOOTSTRAP` is refused with 409 `ACTIVE_CREDENTIAL_EXISTS` while the identity has a credential that is not revoked, unless the bank passes `replacement {method, reference}`: how it re-identified the customer (`BRANCH_VISIT`, `VIDEO_IDENTIFICATION`, `IN_APP_STRONG_AUTHENTICATION`, `OTHER`) and its case reference. The check is repeated under the identity row lock at enrolment.
- The replacement is attached to the single-use token and audited when the token is issued (`credential_replacement_authorized`).
- At enrolment, in one transaction: a `SECURITY` push notice is queued for each replaced device in push mode `NEXUS`, delivered although its credential is revoked (`push_messages.replacement_notice`, migration 014, text `PUSH_REPLACEMENT_TITLE` and `PUSH_REPLACEMENT_BODY`); the old credentials are revoked and their pending authorizations cancelled; the new credential's `CREDENTIAL_ENROLLED` record is sealed with reason `REPLACEMENT`, the replaced credentials and the replacement authorization; audit event `credential_replaced`; webhook `credential.replaced`.
- Without a replacement authorization, a customer moves to a new device by recovery with the phrase.

## Consequences

- A silent takeover through a `BOOTSTRAP` token is no longer possible; every replacement names the bank's re-identification and case, in the audit log and in the sealed chain.
- Auth Core records the re-identification method as the bank states it and does not verify it. The bank can still move an identity to a new device without the phrase; the control is now explicit and attributable.
- In push mode `BANK` Auth Core sends no notice to the old device; the bank informs the customer.
- The recovery configuration survives a replacement; the old phrase stays valid until the new device sets up a new one.
- Host apps that re-enrolled by requesting a new `BOOTSTRAP` token, including after a lost enrolment response ([ADR 0005](0005-two-phase-key-replacement.md)), now receive 409 and must use replacement or recovery.
- Specification: [device replacement](../architecture/device-replacement.md). Test: `test/integration/device-replacement.test.mjs`.
