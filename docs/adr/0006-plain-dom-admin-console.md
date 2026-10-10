# 0006. Plain DOM operator console

## Status

Accepted

## Date

2026-09-26

## Context

Bank operators and auditors need a small console in Auth Core: statistics, bank clients, audit logs, webhook deliveries, and suspend, reactivate or revoke for a NEXUS ID. The console runs inside the bank's network next to a security-critical service. Every dependency it brings is code that the bank's build and review processes must cover, and a JavaScript build pipeline adds tooling to the release.

Auth Core sends the default `helmet()` headers, including a Content Security Policy that allows scripts only from the same origin and no inline script or event-handler attributes.

## Decision

- The console is two static files, `auth-core/public/admin/index.html` and `auth-core/public/admin/admin.js`, served by Auth Core under `/admin`. There is no framework, no package and no build step.
- `admin.js` is loaded with `<script src>`; handlers are attached with `addEventListener`; there is no inline script.
- Values from the API are passed through `escapeHtml` before they are inserted with `innerHTML`, or set with `textContent`.
- The console calls `/admin/api/*` with `fetch` and `credentials: 'same-origin'`. The session is the `nexus_admin_session` cookie: `HttpOnly`, `SameSite=Strict`, `Path=/admin`, `Secure` unless `ADMIN_COOKIE_SECURE=false`.
- Authorization stays on the server: `requireAdminSession` and `requireRole` (auditor, operator, administrator) on every API route; the account status and role are re-checked on every request.

## Consequences

- The console works under the default CSP without exceptions for scripts.
- Reviewing the console means reading two files; nothing is fetched or generated at build time.
- The UI is deliberately limited. Larger features (pagination, charts, forms with client-side validation) cost more code than they would with a framework.
- The console is reachable only through the gateway when `REQUIRE_MTLS_HEADER=true`, as every non-device route is.
- Admin accounts are created with `npm run create-admin-user`; there is no account management over HTTP.
