# 0014. Admin console: bank scope, TOTP and four-eyes approvals

## Status

Accepted

## Date

2026-10-06

## Context

Every admin console account saw and acted on the identities of every bank client. Login needed a username and password only. One operator could revoke an identity, which ends its device credential and recovery, or reactivate a suspended one, which lets it sign again, with no second person involved. A session stayed valid for its full lifetime after a password reset.

## Decision

- **Scope.** `admin_users.client_id` limits an account to one bank client; `NULL` is a platform operator with access to all banks. Every listing (statistics, clients, audit log, webhook deliveries, approvals) and every identity action is filtered by it, and identities outside the scope answer 404.
- **TOTP.** Login requires an RFC 6238 code (HMAC-SHA1, 30-second steps, 6 digits, the current step and one either side). A step at or before the last accepted one is refused, so each code is accepted once. `createAdminUser` enrols a new 20-byte secret and prints it and its `otpauth://` URI once (`--client=<bank>`, `--keep-totp` to keep the existing secret); secrets are stored encrypted with `ADMIN_SECRET_ENCRYPTION_KEY`. With `ADMIN_MFA_REQUIRED` (default on; turning it off is a production blocker) an account without a secret cannot log in.
- **Four eyes.** Revoke and reactivate create an approval request (202, `admin_approvals`) that expires after `ADMIN_APPROVAL_TTL_HOURS` (default 24). It is executed, in the approval's transaction, only when a different admin with the operator role and access to that bank approves (`POST /admin/api/approvals/{id}/approve`); the requester or another admin can reject it. A database `CHECK` refuses an executed request whose approver is its requester. One pending request per identity and action.
- **Suspend** stays a one-person action, because it is the protective response to an incident and is reversible only through a four-eyes reactivation.
- **Sessions.** 8 hours absolute, ended after 30 minutes without a request. `session_version` is incremented whenever the account is re-provisioned (password, TOTP, role or scope), which ends existing sessions. The account is re-checked on every request. State-changing requests with an `Origin` that does not match the `Host` are refused.
- **Audit.** Logins, failed logins, logouts, identity and audit log views, and approval requests, grants and rejections are audited with the admin as actor.

## Consequences

- A bank's operators cannot see or act on another bank's customers; platform operators remain able to.
- Revoking or reactivating an identity needs two people with access to that bank. A deployment with a single admin per bank cannot revoke or reactivate until a second admin or a platform operator approves.
- Admin accounts from 1.4 have no TOTP secret and cannot log in with MFA required until they are re-provisioned with `createAdminUser`.
- Losing `ADMIN_SECRET_ENCRYPTION_KEY` makes every TOTP secret unusable; accounts are then re-provisioned.
- Approvals that are not decided expire; they are marked `EXPIRED` when approvals are next listed.
- Tests: `test/admin-totp.test.mjs`, `test/integration/admin-audit-mtls.test.mjs`.
