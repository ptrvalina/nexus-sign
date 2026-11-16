# Lost, stolen or replaced device

A NEXUS ID has at most as many `ACTIVE` device credentials as its bank allows (`max_devices_per_identity`, default 1; migration 027). If the customer has another active device, the lost one can be removed from it (`POST /v1/mobile/devices/{credentialId}/revoke`) or by the bank (`POST /v1/credentials/{id}/revoke`). When the customer reports the phone lost, stolen or replaced, the bank stops the old credential and, after re-identifying the customer, enrols the new device. Since 2.0 a new device is never enrolled silently over an existing one: the bank requests the replacement explicitly, and the request is held until the customer approves it on the old device or the hold passes. Design: [device replacement](../../architecture/device-replacement.md). Attestation: [device attestation](../../security/attestation.md); bank API details: [bank backend guide](../../integration/bank-backend-guide.md#device-replacement).

## Symptoms

- The customer reports a lost, stolen or replaced phone.
- Authorizations the customer did not start appear as `PENDING_USER`, or fraud monitoring flags the identity.
- A customer reports a security notice "set up on a new device" (`PUSH_REPLACEMENT_TITLE`) that they did not expect.
- `POST /v1/mobile/sessions` with `purpose: BOOTSTRAP` returns 409 `ACTIVE_CREDENTIAL_EXISTS` or `REPLACEMENT_REQUIRED` for a customer with a new phone.
- The bank receives `credential.replacement_cancelled`: a customer refused a replacement requested in their name.

## Impact

Until the credential is revoked, whoever holds the unlocked device and passes its biometric check can confirm authorizations that the bank creates for this NEXUS ID. Auth Core does not create authorizations on its own; each one starts with a bank backend call.

## Diagnosis

Find the identity's credentials:

```sql
SELECT c.credential_id, c.state, c.platform, c.security_level, c.attestation_status, c.key_version,
       c.activated_at, c.last_used_at, c.revoked_at, c.auth_public_key_pem IS NOT NULL AS signs_requests
FROM credentials c
JOIN nexus_identities n ON n.nexus_id = c.nexus_id
WHERE n.client_id = :'client_id' AND n.bank_customer_ref = :'bank_customer_ref'
ORDER BY c.created_at DESC;
```

Without database access, the bank backend reads `credentialId` from `GET /v1/authorizations/{authorizationId}` of any authorization bound to the device.

Open authorizations, recent use and recent device changes:

```sql
SELECT authorization_id, state, transaction_reference, amount_minor, currency, created_at, verified_at
FROM authorization_requests
WHERE nexus_id = :'nexus_id'
ORDER BY created_at DESC
LIMIT 20;

SELECT "timestamp", event_type, actor, details
FROM audit_logs
WHERE nexus_id = :'nexus_id'
  AND event_type IN ('mobile_session_issued', 'credential_replacement_authorized', 'credential_replaced',
                     'credential_created', 'credential_revoked', 'recovery_completed')
ORDER BY "timestamp" DESC
LIMIT 20;
```

A `credential_replacement_authorized` event records the bank's `method` and `reference` when the replacement token was issued; `credential_replaced` records the enrolment that used it.

## Resolution

### 1. Stop the old device

Choose by urgency:

| Action | Who | Effect |
|---|---|---|
| Revoke the credential: `POST /v1/credentials/{credentialId}/revoke` | Bank backend, one call | Immediate and final for that credential. In one transaction: state `REVOKED` with `revoked_at`, its `PENDING_USER` authorizations `CANCELLED`, its push registration removed, audit event `credential_revoked` with `cancelledAuthorizations`. |
| Revoke one device from the console: `POST /admin/api/identities/{nexusId}/devices/{credentialId}/revoke` with `{"reason":"..."}` ([bank console](../bank-console.md)) | One admin with role `operator` of the bank | As revoking the credential from the bank backend; the reason names the staff member. Other devices of the customer stay active. |
| Suspend the identity: `POST /admin/api/identities/{nexusId}/suspend` with `{"reason":"..."}` | One admin with role `operator` or higher and access to the bank | Immediate. All `PENDING_USER` authorizations of the identity are cancelled; mobile requests receive 403; no authorization, confirmation, enrolment or recovery is possible. The credential is kept. Audit event `identity_suspended`. |
| Revoke the identity: `POST /admin/api/identities/{nexusId}/revoke` | Two admins (four-eyes) | Takes effect only when a second admin approves. Final: the identity and all its credentials are revoked; the customer needs a new NEXUS ID. |

Revoke the credential (bank backend):

```sh
curl -sS -X POST "$AUTH_CORE/v1/credentials/$CREDENTIAL_ID/revoke" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason":"DEVICE_LOST"}'
```

The response is `{"credentialId":"...","state":"REVOKED"}`. A credential that is already revoked, or belongs to another bank client, returns 404. The reason is free text up to 256 characters. From the next request on, device-signed requests of the old phone receive 401, a confirmation of an authorization bound to it fails (`Credential is not valid for this authorization`), and `POST /v1/authorizations` for it is refused with 409. A commit request for an authorization it confirmed earlier is refused with 409 `CREDENTIAL_NOT_ACTIVE`. Verified authorizations and their evidence are not changed.

Suspension is the protective one-person action while the facts are unclear. Lifting it needs two admins:

1. Admin A: `POST /admin/api/identities/{nexusId}/reactivate` with `{"reason":"..."}`. The answer is 202 with the approval request (`approvalId`, `status: PENDING`, `expiresAt` after `ADMIN_APPROVAL_TTL_HOURS`). Audit event `admin_approval_requested`.
2. Admin B, a different account with access to the same bank (or a platform operator): reviews `GET /admin/api/approvals` (the pending approvals panel in the console) and calls `POST /admin/api/approvals/{approvalId}/approve`, or `.../reject`. Approval executes the action in the same transaction (`identity_reactivated`, `admin_approval_granted`).

Identity revocation works the same way with `.../revoke`. Rules enforced by Auth Core and the database:

- The requester cannot approve their own request (403 `A second admin must approve this request`); the database also refuses an `EXECUTED` approval whose `decided_by` equals `requested_by`. The requester may reject (withdraw) it.
- One pending request per identity and action (409 `APPROVAL_PENDING`).
- An expired request cannot be decided (410); it is listed as `EXPIRED`.
- Bank-scoped admins see and decide only their bank's identities and approvals; other identities answer 404.

### 2. Enrol the new device

Always after the bank has re-identified the customer through its own controls. The identity must be `ACTIVE`.

| Path | When | Bank call |
|---|---|---|
| Replacement request | The identity has or had a device (its credential is `ACTIVE`, or was revoked in step 1) | `POST /v1/mobile/sessions` with `purpose: BOOTSTRAP` and `replacement: {method, reference}`; 202 while held, 201 with the token afterwards |
| Recovery | The customer has the recovery phrase and the bank requires it | `POST /v1/recovery/sessions`; see [recovery lockout](recovery-lockout.md) |

```sh
curl -sS -X POST "$AUTH_CORE/v1/mobile/sessions" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"nexusId":"123456789","purpose":"BOOTSTRAP","replacement":{"method":"BRANCH_VISIT","reference":"CASE-2026-1187"}}'
```

`method` is one of `BRANCH_VISIT`, `VIDEO_IDENTIFICATION`, `IN_APP_STRONG_AUTHENTICATION`, `OTHER`; `reference` is the bank's case reference, 1 to 128 characters. Issuing the token writes `credential_replacement_authorized`. The token is single use and valid for 300 s.

Since the A2-01 fix a replacement is held: the first call answers 202 `REPLACEMENT_PENDING` with `replacementId` and `notBefore`. The customer approves it in the bank's app on the old device (if they still have it), or the hold passes (`DEVICE_REPLACEMENT_HOLD_SECONDS`, at least one hour in production, default 24 hours); then the same call returns the token. A cancellation by the customer ends the request: investigate it as a possible takeover attempt. For a stolen phone where the customer needs a device at once, recovery with the phrase is the immediate path. [Hold](../../architecture/device-replacement.md#hold).

When the new device enrols with a replacement token while an old credential is still non-revoked, Auth Core in one transaction:

- queues a `SECURITY` notice to the old device (`PUSH_REPLACEMENT_TITLE`, `PUSH_REPLACEMENT_BODY`), when `PUSH_DELIVERY_ENABLED` is on, the bank client uses push mode `NEXUS` and the old device has an active push registration; it is delivered although the old credential is revoked, and kept for 24 hours;
- revokes the old credentials (`credential_revoked`, reason `DEVICE_REPLACED`) and cancels their `PENDING_USER` authorizations;
- creates the new credential and seals its `CREDENTIAL_ENROLLED` record with reason `REPLACEMENT`, the replaced credential IDs and the bank's `method` and `reference`;
- writes `credential_replaced` and `credential_created`, and sends the webhook `credential.replaced`.

When the old credential was revoked first, the enrolment replaces nothing: there is no notice, no `credential_replaced` event and no `credential.replaced` webhook.

## Follow-up

- Confirm the state:

  ```sql
  SELECT credential_id, state, revoked_at, enrolment_evidence_id FROM credentials WHERE nexus_id = :'nexus_id' ORDER BY created_at DESC;
  SELECT "timestamp", event_type, actor, details FROM audit_logs WHERE nexus_id = :'nexus_id' ORDER BY "timestamp" DESC LIMIT 20;
  ```

- Review authorizations verified between the reported loss and the revocation with the customer. Their evidence shows which credential signed (`GET /v1/authorizations/{authorizationId}/evidence`).
- An unexpected `credential.replaced` webhook or replacement notice: check the `credential_replacement_authorized` event (`actor`, `method`, `reference`, `ip_address`) against the bank's case records; an unknown case is a security incident ([incident response](../incident-response.md#unauthorized-device-replacement)).
- The recovery key configured on the old device stays on the identity after a replacement. The new device replaces it when it sets up recovery (`POST /v1/mobile/recovery/setup`). After a recovery the phrase cannot be used again (409 `RECOVERY_PHRASE_USED`) until the recovered device sets up a new one; make sure the bank's app asks for it.
