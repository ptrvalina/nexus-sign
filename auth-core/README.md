# NEXUS-SIGN Auth Core

Backend service for cryptographic transaction authorization, credential lifecycle, evidence sealing and bank transaction orchestration.

## Responsibilities

- OAuth 2.0 client-credentials authentication for bank backends.
- NEXUS ID and credential lifecycle.
- Versioned transaction authorization and canonical signing payloads.
- Device-signed mobile requests (no access token after enrolment) and offline confirmation with a QR code and an 8-digit code.
- Server-side verification of App Attest and Play Integrity evidence.
- Signature verification and atomic authorization consumption.
- Adaptive verification (Push -> Audio -> Video) bound to the signature.
- HSM-sealed, hash-chained evidence that can be verified offline, including the customer's signature.
- Bank commit tracking and webhook delivery through a transactional outbox.
- Administrative controls (suspend, reactivate, revoke) and audit logging.

## Production posture

Production startup is fail-closed unless PKCS#11 HSM, device attestation, database/Redis TLS, gateway mTLS and webhook egress policy are configured (`src/config/productionPosture.ts`). Every setting is described in the [configuration reference](../docs/operations/configuration.md).

## Development

Node.js 22 or later (Node.js 20 has reached end of life, and its test runner does not expand the test file patterns). Auth Core reads only the process environment; `npm run dev` compiles (`tsc`) and starts `node --env-file=.env dist/server.js`. Copy `.env.example` to `.env` first.

## Database setup

- New installation: apply `src/db/schema.sql` only. It is the complete current schema and can be re-applied safely.
- Upgrading an existing deployment: apply the files in `migrations/` in numeric order; see [migrations/README.md](migrations/README.md). The result is the same schema as a new installation. From 1.4.0 follow [upgrade to 2.0](../docs/operations/upgrade-2.0.md).
- In both cases apply `scripts/db/roles.sql` afterwards and connect Auth Core as `nexus_app` ([database roles](../docs/operations/deployment.md#database-roles)).

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f src/db/schema.sql
```

## Mobile authentication

After enrolment the device signs each request with its hardware authentication key and holds no token ([specification](../docs/protocol/device-authentication-and-offline-confirmation.md)). The bank backend issues a token only to enrol a device; the SDK asks the app for it through its token provider.

```http
POST /v1/mobile/sessions
Authorization: Bearer <bank access token>

{ "nexusId": "123456789", "purpose": "BOOTSTRAP" }
```

The only purpose is `BOOTSTRAP` (the default): 300 s, single use, accepted only by `POST /v1/mobile/bootstrap`. `purpose: "SESSION"` returns 400. `POST /v1/mobile/bootstrap` and `POST /v1/recovery/sessions/{id}/complete` require `authPublicKeyPem` and answer `requestAuthentication: "DEVICE_SIGNATURE"`, never an access token. Devices enrolled by SDKs before 1.2, which have no authentication key, are enrolled again through device replacement.

A `BOOTSTRAP` token for an identity that already has an `ACTIVE` credential is refused with 409 `ACTIVE_CREDENTIAL_EXISTS`, unless the bank backend passes a `replacement` authorization; `POST /v1/mobile/bootstrap` then replaces the previous credential ([device replacement](../docs/architecture/device-replacement.md)). Devices enrol only this way; the bank API has no endpoint that registers or rotates a credential. Recovery setup (`/v1/mobile/recovery/setup`) is performed by the device; the bank API has no recovery-setup endpoint.

| Setting | Default | Purpose |
|---|---|---|
| `DEVICE_REQUEST_MAX_SKEW_SECONDS` | 300 | Accepted clock difference for device-signed requests |
| `DEVICE_REQUEST_PATH_PREFIX` | empty | Path prefix the gateway strips before forwarding (devices sign the path they send) |
| `OFFLINE_CONFIRMATION_ENABLED` | false | Enables offline confirmation |
| `DEVICE_SECRET_ENCRYPTION_KEY` | none | 32 random bytes, base64; encrypts per-credential offline keys; required when offline confirmation is enabled |

## Offline confirmation

```http
GET  /v1/authorizations/{id}/offline-challenge      -> { qrPayload: "NXS1.…", codeDigits: 8, expiresAt }
POST /v1/authorizations/{id}/offline-confirmation   { "code": "12345678" } -> { status: "VERIFIED" }
```

Show `qrPayload` as a QR code on the bank's screen; the customer's phone shows the transaction and, after the biometric, an 8-digit code to type in. Five wrong codes reject the authorization.

## Gateway mTLS and device-facing endpoints

With `REQUIRE_MTLS_HEADER=true`, every bank-facing endpoint requires the gateway's verified-client-certificate marker. Endpoints called directly by the embedded mobile SDK (`/v1/mobile/*` except `/v1/mobile/sessions`, which the bank backend calls, and `POST /v1/recovery/sessions/{id}/complete`) are exempt, because a customer's phone never holds the bank's gateway client certificate. They are authenticated by device signatures or by short-lived, customer-scoped tokens instead. Route mobile traffic through a gateway listener that does not demand a client certificate.

## Operator tools

Command-line tools run where an operator has database access, with the deployment's configuration (`DATABASE_URL`, `REDIS_URL` and the keys named below) in the process environment; they load no `.env` file. In development run them as `node --env-file=.env dist/cli/<tool>.js` after `npm run build`. They are not HTTP endpoints.

| Command | `npm run` alias | Purpose |
|---|---|---|
| `node dist/cli/registerClient.js <clientId> [webhookUrl] [--push-mode=BANK\|NEXUS] [--mtls-cert-sha256=<hex>[,<hex>]]` | `register-client` | Registers a bank client, or rotates its secrets: every run prints a new `client_secret` (and `webhook_secret` with a webhook URL) once and revokes the client's access tokens. Sets the webhook URL and push mode to the values given. Needs `WEBHOOK_SECRET_ENCRYPTION_KEY` with a webhook URL |
| `node dist/cli/setClientCertificates.js <clientId> <hex>[,<hex>]` | `set-client-certificates` | Replaces only the client certificate fingerprints (SHA-256 of the DER certificate, hex, colons allowed), without rotating secrets or revoking tokens. Use it to register certificates and for a certificate rollover |
| `node dist/cli/createAdminUser.js <username> <administrator\|operator\|auditor> [--client=<clientId>] [--keep-totp]` | `create-admin-user` | Creates or resets an admin account and its TOTP secret. Needs `ADMIN_SECRET_ENCRYPTION_KEY` |
| `node dist/cli/sealCredentialBaseline.js` | `seal-credential-baseline` | Upgrade step: seals a `CREDENTIAL_ENROLLED` record (reason `BASELINE`) for each credential enrolled before evidence schema 3. Run once after the migrations, before traffic. Needs the HSM |

## Tests and checks

| Command | What it runs | Needs |
|---|---|---|
| `npm test` | Unit tests (`test/*.test.mjs`): signature encodings and strict DER, P-256 key parsing, attestation binding and Android key attestation, mTLS allow-list, SSRF address rules, evidence hashing and offline verification, protocol bytes, recovery protocol 2 vectors, device-signed requests, the BOOTSTRAP-only token store, offline code derivation against the shared vectors, secure push, admin TOTP, error mapping, production startup checks, seeded property and fuzz tests | Node.js only |
| `npm run test:integration` | Integration suites (`test/integration/*.test.mjs`, one at a time) that start real Auth Core processes from `dist/` against a fresh PostgreSQL database per suite: concurrency invariants, tenant isolation, replay, state machines, database roles, evidence integrity, device replacement, recovery, admin, audit and mTLS, attestation policy, production startup, and the PKCS#11 adapter against SoftHSM | `npm run build`; `INTEGRATION_DATABASE_URL` (a role allowed to `CREATE DATABASE`) and `INTEGRATION_REDIS_URL`; for the HSM suites `SOFTHSM2_MODULE` (path of `libsofthsm2.so`) and `SOFTHSM2_UTIL` (path of `softhsm2-util`). Suites whose variables are not set are skipped |
| `npm run check:all` | `npm test`, the shared protocol vectors and their iOS copies (`test-vectors/check-vector-copies.mjs`), routes against `openapi.yaml`, repository hygiene and version consistency | Node.js, bash |
| `npm run smoke-test` | End-to-end flow against a running instance (below) | Running Auth Core, PostgreSQL, Redis |

```bash
npm run build
INTEGRATION_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres \
INTEGRATION_REDIS_URL=redis://127.0.0.1:6379 \
SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so SOFTHSM2_UTIL=/usr/bin/softhsm2-util \
npm run test:integration
```

CI runs `npm run check:all` (job `auth-core`, which also covers repository hygiene), `npm run test:integration` against PostgreSQL 16, Redis 7 and SoftHSM (job `auth-core-integration`) and the end-to-end flow (job `auth-core-e2e`, below). Dependencies are installed with `npm ci` from the committed `package-lock.json`. The dependency audit and the gitleaks secret scan run in `.github/workflows/security.yml` (job `audit`, "Dependency audit and secret scan").

## End-to-end check

`npm run smoke-test` (`scripts/e2e-smoke.mjs`, no dependencies, works in PowerShell) drives a running Auth Core through the whole flow the bank backend and the SDK use: OAuth token -> NEXUS ID -> single-use bootstrap with a real P-256 key -> authorization and idempotent retry -> device-side canonical payload check -> tampered, valid and replayed signatures -> offline evidence verification -> device-signed requests (replay, wrong path, wrong key refused; no token issued) -> adaptive verification scenarios (AUDIO, push timeout -> failed AUDIO -> VIDEO, refused downgrade, rejection) -> offline confirmation with a QR payload and an 8-digit code -> bank commit -> recovery (including the five-attempt lock) -> signing with the recovered key -> verification of the whole evidence chain. The CI job `auth-core-e2e` applies `src/db/schema.sql` twice and the migrations on a fresh PostgreSQL 16 database, applies `scripts/db/roles.sql`, runs the server as `nexus_app` and then runs this flow, with Redis 7.

```bash
node --env-file=.env dist/cli/registerClient.js my-bank
NEXUS_SIGN_SMOKE_CLIENT_ID=my-bank NEXUS_SIGN_SMOKE_CLIENT_SECRET=<secret> npm run smoke-test
```

## Verifying evidence offline

```bash
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/v1/nexus-identities/123456789/evidence" > chain.json
npm run verify-evidence -- chain.json --public-keys=evidence-keys.pem --expect-head=<chainSequence>:<evidenceHash>
```

The verifier (`scripts/verify-evidence.mjs`) uses Node.js only and no Auth Core code. It checks each record's hash and HSM seal, the chain and its numbering, the provenance of every device key (sealed enrolment), and the customer's device signature over the exact signed bytes. `--public-keys` is one PEM file with every current and retired evidence key, obtained out of band; without it the keys inside the export are used, a `WARNING` is printed, the summary reads `EVIDENCE_SELF_CONSISTENT ... hsm_seal=verified_with_export_keys` and the exit code is 3. `--expect-head` is the chain head the bank stored; without it records removed from the end of the chain are not detected. Format and rules: [evidence format](../docs/protocol/evidence-format.md).

## Beneficiary fields

Beneficiary keys must match `^[a-z][a-z0-9_]{0,63}$` (for example `name`, `iban`, `account_number`, `bic`), with at most 16 fields of up to 512 characters. JavaScript lists integer-like keys (`"0"`, `"10"`) before all others, so such a key would make the signed bytes differ from sorted-key order and no independent verifier could reproduce them.

Values, like every other displayed field, may not contain control characters (including line breaks), bidi or zero-width format characters, or line and paragraph separators. Such characters can make the confirmation prompt read differently from the signed value, so Auth Core rejects them with 400 and the SDKs refuse to sign them.
