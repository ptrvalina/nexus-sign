# Bank console: customers' mandates and devices

The admin console (`/admin`) shows one customer's mandates and devices under the identity lookup. The server side is `auth-core/src/services/bankConsoleService.ts`; the screen is `auth-core/public/admin/customer.js`. Tests: `auth-core/test/integration/bank-console.test.mjs` (PostgreSQL).

## Who sees and does what

| Admin | Reads | Changes |
|---|---|---|
| `auditor` of a bank | That bank's customers | Nothing |
| `operator` or `administrator` of a bank | That bank's customers | Hold, release, withdraw a mandate; revoke a device; stop a device request |
| Platform account (no bank) | Every bank's customers | Nothing: a platform account is not the bank (403) |
| Staff of another bank | Nothing (404, as if the customer did not exist) | Nothing |

Every view writes `admin_mandates_viewed` or `admin_devices_viewed` to the audit log with the staff member's name (`admin:<username>`). Every change is written under the same name.

## Payments

`GET /admin/api/identities/{nexusId}/authorizations?filter=all|confirmed|declined|open` (any role): the customer's authorizations, newest first, with state, the recorded reason (for example `DECLINED_BY_CUSTOMER`), when it was decided and whether evidence is sealed. Audit `admin_authorizations_viewed`.

## Mandates

| Endpoint | Role | Effect |
|---|---|---|
| `GET /admin/api/identities/{nexusId}/mandates` | any | The customer's mandates |
| `GET /admin/api/mandates/{mandateId}` | any | The mandate, its debits (allowed and refused), its sealed evidence records and its event log (state changes with reason and actor) |
| `POST /admin/api/mandates/{mandateId}/hold` `{"reason"}` | operator | `ACTIVE` → `SUSPENDED` with reason `SUSPENDED_BY_BANK:<username>:<reason>`. Debits are refused with `MANDATE_NOT_ACTIVE`. Sealed as `SUSPENDED`; webhook `mandate.suspended` |
| `POST /admin/api/mandates/{mandateId}/release` | operator, **not the one who placed the hold** | Back to `ACTIVE` (or `EXPIRED` after `validUntil`). Sealed as `RESUMED` with reason `BANK_HOLD_RELEASED`; webhook `mandate.resumed` |
| `POST /admin/api/mandates/{mandateId}/withdraw` `{"reason"}` | operator | Final: `WITHDRAWN`, reason `WITHDRAWN_BY_BANK:CONSOLE:<username>:<reason>`. Same as `POST /v1/mandates/{id}/withdraw` |

The customer cannot lift a bank hold: `POST /v1/mobile/mandates/{id}/resume` answers 409 `MANDATE_HELD_BY_BANK`. A suspension by the customer is not a bank hold; staff cannot release it (409 `MANDATE_STATE_CONFLICT`). Staff cannot change the terms of a mandate; changed terms are a new mandate the customer signs.

## Devices

| Endpoint | Role | Effect |
|---|---|---|
| `GET /admin/api/identities/{nexusId}/devices` | any | Devices (platform, key protection, attestation status, added on, why added — enrolment, addition, replacement, recovery — last use, state), the history of device additions and replacements, the bank's `max_devices_per_identity`, and the identity's security events |
| `POST /admin/api/identities/{nexusId}/devices/{credentialId}/revoke` `{"reason"}` | operator | Same effect as `POST /v1/credentials/{credentialId}/revoke`: the credential is `REVOKED`, its open payments are cancelled, and the revocation is sealed as `CREDENTIAL_REVOKED` with reason `REVOKED_BY_BANK:CONSOLE:<username>:<reason>`. A second revoke answers 409 `CREDENTIAL_NOT_ACTIVE` |
| `POST /admin/api/identities/{nexusId}/device-requests/{requestId}/cancel` | operator | Stops an open (`PENDING` or `APPROVED`) addition or replacement the customer did not ask for. Audit `credential_replacement_cancelled` with `by: BANK_STAFF`; webhook `credential.replacement_cancelled`. 409 `REPLACEMENT_NOT_PENDING` if it is no longer open |

The device limit is a setting of the bank client (`bank_clients.max_devices_per_identity`), changed by the platform's administrator, not from this screen. The database refuses a credential above the limit ([multiple devices](../architecture/device-replacement.md)).

## Not verified

The services were checked by the PostgreSQL tests. The screen is rendered in Chromium against a stubbed API by `test/media/console-customer-screen.test.mjs` (escaping, which buttons appear for which state and role; passed here with Playwright); it has not been used against a running Auth Core. The HTTP routes were not run in the review environment (no `express`); CI job `auth-core / integration` and a look at the console on a test system are needed.
