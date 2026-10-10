# Device replacement

A NEXUS ID has one enrolled device. A new device for an identity that already has one is enrolled in one of two ways:

- **Recovery**: the customer proves knowledge of the recovery phrase ([recovery protocol 2](../protocol/recovery-protocol-v2.md)).
- **Replacement**: the bank re-identifies the customer by its own means and authorizes the new device explicitly. This page describes replacement.

Before release 2.0, a `BOOTSTRAP` token for an identity with an enrolled device silently revoked that device when the new one enrolled. Auth Core now refuses that unless the bank states how it re-identified the customer, and every replacement is audited, sealed, reported to the bank and announced on the old device. Decision record: [ADR 0012](../adr/0012-explicit-device-replacement.md).

Implementation: `auth-core/src/routes/mobileV1.ts` (`POST /v1/mobile/sessions`, `POST /v1/mobile/bootstrap`), `src/services/credentialService.ts` (`createCredential`), `src/services/pushService.ts` (`queueReplacementNotice`).

## Replacement authorization

`POST /v1/mobile/sessions` with purpose `BOOTSTRAP` takes an optional `replacement` object:

```json
{
  "nexusId": "123456789",
  "purpose": "BOOTSTRAP",
  "replacement": { "method": "BRANCH_VISIT", "reference": "CASE-2026-10-0042" }
}
```

| Field | Values |
|---|---|
| `method` | `BRANCH_VISIT`, `VIDEO_IDENTIFICATION`, `IN_APP_STRONG_AUTHENTICATION`, `OTHER` |
| `reference` | 1 to 128 characters: the bank's case or ticket reference |

Auth Core records the method and reference as the bank states them. It does not verify the re-identification.

When the identity has an `ACTIVE` credential and no `replacement` is given, the request is refused:

```json
{ "error": "The customer already has an enrolled device. Use recovery with the recovery phrase, or issue a replacement token after re-identifying the customer", "code": "ACTIVE_CREDENTIAL_EXISTS" }
```

with status 409. The same check runs again under the identity row lock when the device enrols, so a device that enrols first with an ordinary token wins and the second enrolment is refused with the same 409. The identity itself must be `ACTIVE` (409 otherwise).

The replacement is attached to the single-use `BOOTSTRAP` token (300 s) and applies only to the identity it was issued for.

## Sequence

1. The customer reports a new or lost phone. The bank re-identifies the customer (branch, video identification, strong authentication in another channel).
2. The bank backend calls `POST /v1/mobile/sessions` with `purpose: BOOTSTRAP` and `replacement {method, reference}`. Audit events `mobile_session_issued` and `credential_replacement_authorized` (method and reference).
3. The bank backend hands the token to its app on the new device. The SDK generates its keys and attestation and calls `POST /v1/mobile/bootstrap`.
4. Auth Core verifies the attestation, consumes the token, and in one transaction, with the identity row locked:
   - queues a `SECURITY` push notice to each replaced device, where possible (below);
   - revokes the identity's `ACTIVE` credential (audit event `credential_revoked`, reason `DEVICE_REPLACED`);
   - cancels the `PENDING_USER` authorizations bound to those credentials;
   - removes their push registrations, except one that still has a replacement notice to deliver;
   - registers the new credential and seals its `CREDENTIAL_ENROLLED` record with reason `REPLACEMENT`;
   - records audit events `credential_replaced` and `credential_created`;
   - queues the webhook `credential.replaced`.
5. The bank receives `credential.replaced` and, in push mode `NEXUS`, the old device receives the notice.

## Effects on the old device

- Its credential is `REVOKED` (final). Device-signed requests of the old device are refused with 401 from then on, and offline codes it computes are refused at confirmation.
- Authorizations waiting for its signature are `CANCELLED`. The bank creates them again for the new device if needed.
- The identity's recovery configuration is not changed: the existing recovery phrase still recovers the identity until the new device sets up a new one.

## Push notice

When `PUSH_DELIVERY_ENABLED` is on, the bank client's push mode is `NEXUS` and the replaced device has an active push registration with a push key, Auth Core seals a `SECURITY` message for it, in the replacement transaction:

| Field | Value |
|---|---|
| `title` | `PUSH_REPLACEMENT_TITLE` (default "Your account was set up on a new device") |
| `body` | `PUSH_REPLACEMENT_BODY` (default "If this was not you, contact your bank immediately.") |
| `data` | `{ "event": "DEVICE_REPLACED" }` |
| Expiry | 24 hours |

The message is marked `push_messages.replacement_notice` (migration 014) and is delivered although its credential is revoked; the registration is removed once the notice has been sent or has failed. Audit event `push_message_queued` with reason `DEVICE_REPLACED`.

In push mode `BANK`, or when the old device has no push registration, no notice is sent by Auth Core.

## Webhook

`credential.replaced`:

```json
{
  "nexusId": "123456789",
  "newCredentialId": "…",
  "replacedCredentialIds": ["…"],
  "method": "BRANCH_VISIT",
  "reference": "CASE-2026-10-0042",
  "enrolmentEvidenceHash": "<evidenceHash of the new CREDENTIAL_ENROLLED record>"
}
```

## Evidence

The new credential's `CREDENTIAL_ENROLLED` record ([evidence format](../protocol/evidence-format.md#credential_enrolled)) seals:

- `reason: REPLACEMENT`;
- `replacedCredentialIds`: the revoked credentials;
- `replacementAuthorization`: `method`, `reference` and the bank `clientId`;
- the new device's keys and attestation material.

A token issued with `replacement` for an identity that turns out to have no enrolled device still enrols with reason `REPLACEMENT`, with no replaced credentials and `replacementAuthorization: null`; no `credential_replaced` event or webhook is produced.

## Audit events

| Event | When | Details |
|---|---|---|
| `mobile_session_issued` | Token issued | Purpose, lifetime; actor `bank:<clientId>` |
| `credential_replacement_authorized` | Token issued with `replacement` | `method`, `reference` |
| `push_message_queued` | Notice queued | Message ID, `SECURITY`, credential, reason `DEVICE_REPLACED` |
| `credential_revoked` | Enrolment | Revoked credential IDs, reason `DEVICE_REPLACED` |
| `credential_replaced` | Enrolment | New and replaced credential IDs, `method`, `reference` |
| `credential_created` | Enrolment | New credential, reason `REPLACEMENT`, enrolment evidence hash |

## Bank responsibilities

- Re-identify the customer before requesting a replacement token, with a method the bank's own policy accepts for the risk, and record the case under the `reference` sent to Auth Core. Recovery with the phrase is the path that does not depend on the bank's re-identification.
- Treat the ability to request replacement tokens as a privileged operation in the bank's own systems; anyone who can request one can move the customer's identity to a new device without the phrase.
- Handle `credential.replaced`: confirm it matches a case the bank opened, and investigate one that does not.
- Inform the customer through a channel other than the old device in push mode `BANK`, where Auth Core sends no notice.
- Recreate any authorizations cancelled by the replacement for the new device.
- Handle 409 `ACTIVE_CREDENTIAL_EXISTS` in its enrolment flow by choosing recovery or replacement, never by retrying the same request.

## Tests

`auth-core/test/integration/device-replacement.test.mjs`: a `BOOTSTRAP` token is refused without a replacement authorization; two concurrent first enrolments enrol exactly one device; an authorized replacement revokes the old device and is audited, sealed, reported and announced on the old device; a replacement token cannot be used for another identity.
