# 0015. Bank tokens bound to the client certificate fingerprint

## Status

Accepted

## Date

2026-10-06

## Context

Bank backends reach Auth Core through the bank's API gateway, which terminates client mTLS and tells Auth Core, from a trusted proxy address, that a verified certificate was presented. Auth Core did not learn which certificate. A bank client's secret, or an access token issued to it, therefore worked over any verified gateway connection, including one authenticated with another bank's certificate.

## Decision

- The gateway forwards the SHA-256 fingerprint of the verified client certificate in `MTLS_CERT_SHA256_HEADER` (default `x-client-cert-sha256`) and overwrites any inbound value of that header and of `MTLS_VERIFIED_HEADER`.
- `bank_clients.mtls_cert_sha256` holds the fingerprints registered for each bank client (`registerClient <clientId> --mtls-cert-sha256=<hex>[,<hex>]`; several during a certificate rollover; kept when the option is omitted). Added in the same release: `setClientCertificates <clientId> <hex>[,<hex>]` replaces the fingerprints without rotating the client's secrets, for registration and rollover.
- With `REQUIRE_MTLS_HEADER` (a production requirement), a bank request without a well-formed fingerprint from a trusted proxy is refused with 403. `POST /oauth/token` issues a token only when the presented fingerprint is registered for the authenticating client, and every bank API call is accepted only when the presented fingerprint is registered for the token's client. A mismatch answers 401 and is audited as `bank_certificate_mismatch`, with the stage (`token` or `api`) and the fingerprint.
- Device-facing routes are exempt; phones never hold the bank's client certificate.

## Consequences

- A token or client secret taken from one bank cannot be used through a connection authenticated with another bank's certificate.
- Tokens are bound to the client's set of registered fingerprints, not to the single certificate presented at issuance; any registered certificate of the same client can use the token.
- The binding is as strong as the gateway: it must verify the certificate, compute the fingerprint and strip client-supplied headers, and Auth Core must accept these headers only from `TRUSTED_PROXY_IPS`.
- Each bank client must have its certificates registered before upgrade, or its calls fail. Certificate renewal requires registering the new fingerprint first.
- Test: `test/integration/admin-audit-mtls.test.mjs`.
