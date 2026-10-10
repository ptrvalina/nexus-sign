# Deployment

NEXUS-SIGN runs inside the bank's controlled environment or private cloud. The mobile SDK is embedded into the bank's existing application. Configuration is described in the [configuration reference](configuration.md); upgrading from 1.4.0 in [upgrade to 2.0](upgrade-2.0.md).

## Development

- PostgreSQL and Redis run locally through `auth-core/docker-compose.yml`.
- `HSM_ADAPTER=software`, attestation off, gateway mTLS off and admin MFA off are permitted only with `NODE_ENV` `development` or `test` and `ALLOW_INSECURE_DEVELOPMENT=true` ([configuration](configuration.md#allow_insecure_development)).
- Device attestation can be exercised with test credentials before the bank configures its production attestation policy.
- `sandbox/` provides a self-contained environment for demonstrations and integration rehearsals; it needs Python only. To host it for banks and partners, see [sandbox/HOSTING.md](../../sandbox/HOSTING.md).

## Image build

`auth-core/Dockerfile` copies `package.json` and `package-lock.json` and installs with `npm ci`. The build fails when `auth-core/package-lock.json` is missing; it never resolves dependency versions at build time. CI (`.github/workflows/ci.yml`) and the release workflow install the same way and fail without the lockfile.

The repository does not contain a lockfile yet. It must be generated with access to the npm registry, reviewed and committed before an image can be built ([release checklist](release.md)). Until then the CI jobs that install dependencies fail by design.

The base images (`node:22-alpine`) are referenced by tag, not by digest. Pinning them by digest needs registry access and is open (NXS-040).

The runtime image runs as the unprivileged user `nexus`, contains `dist/`, `public/`, `src/db/schema.sql`, `migrations/` and the production dependencies, and checks `/healthz` with `HEALTHCHECK`. It sets `NODE_ENV=production` and `UV_THREADPOOL_SIZE=16`: the asynchronous PKCS#11 calls run on libuv worker threads shared with DNS, file and scrypt work, so keep `UV_THREADPOOL_SIZE` larger than `HSM_SESSION_POOL_SIZE` when changing either. `scripts/` (including `scripts/db/roles.sql` and `scripts/verify-evidence.mjs`) is not in the image; run those from a checkout of the release tag.

## Database

- **New installation:** apply `auth-core/src/db/schema.sql`. It is complete and idempotent. Then apply `auth-core/scripts/db/roles.sql`.
- **Upgrade of an existing deployment:** apply `auth-core/migrations/` in numeric order ([migrations/README.md](../../auth-core/migrations/README.md)), then `scripts/db/roles.sql` again. From 1.4.0, follow [upgrade to 2.0](upgrade-2.0.md).

### Database roles

`auth-core/scripts/db/roles.sql` creates three roles and assigns ownership and privileges. Run it as a superuser or the cloud provider's admin role, after the schema and migrations, and again after every upgrade:

```sh
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -f scripts/db/roles.sql
```

| Role | Login | Privileges | Used by |
|---|---|---|---|
| `nexus_owner` | `NOLOGIN` | Owns every table, sequence and function in `public`; `CREATE` on the schema | Migrations, run by a named DBA account with `SET ROLE nexus_owner` |
| `nexus_app` | Created `NOLOGIN`; the login is enabled by the operator | `SELECT`, `INSERT`, `UPDATE` on all tables except `evidence_records` and `audit_logs`, where it has `SELECT` and `INSERT` only; `DELETE` on `push_registrations` only; sequences `USAGE`, `SELECT`; no `TRUNCATE`; owns nothing | Auth Core (`DATABASE_URL`) and the CLIs |
| `nexus_audit_reader` | Created `NOLOGIN` | `SELECT` on `evidence_records` and `audit_logs` | Export and archival |

The script revokes `CREATE` on schema `public` from `PUBLIC` and sets default privileges, so tables created later by `nexus_owner` get the same grants for `nexus_app`. It sets no passwords. Enable the login with the provider's tooling or:

```sql
ALTER ROLE nexus_app WITH LOGIN PASSWORD '<from the secrets manager>';
```

Point `DATABASE_URL` at `nexus_app`. Because `nexus_app` owns no table, it cannot disable or replace the append-only triggers on `evidence_records` and `audit_logs` or the lifecycle triggers of migration 017, cannot set `session_replication_role`, and cannot create tables (`test/integration/db-roles.test.mjs`).

The DBA account that runs migrations must be a member of `nexus_owner` to `SET ROLE` to it; `roles.sql` does not grant that membership.

Residual risk: a superuser, the provider's admin role and members of `nexus_owner` can still disable triggers and change evidence and audit rows. Limit who holds these roles, and log DDL and trigger changes with `pgaudit` or the provider's database audit log, forwarded to a store the database administrators cannot change. The sealed evidence chain makes a change to evidence detectable; it does not prevent it ([threat model](../security/threat-model.md#residual-risks)).

## Gateway

Bank backends reach Auth Core only through the bank's API gateway, which terminates client mTLS. With `REQUIRE_MTLS_HEADER=true` (required in production) Auth Core relies on the gateway as follows (`src/middleware/mtlsGateway.ts`):

| Requirement | Detail |
|---|---|
| Source address | Auth Core accepts the headers only from the socket address of a `TRUSTED_PROXY_IPS` entry. IPv4-mapped IPv6 forms (`::ffff:a.b.c.d`) are normalised to IPv4 on both sides, so either form may be listed. Auth Core must not be reachable from any other address. |
| `x-client-cert-verified` (`MTLS_VERIFIED_HEADER`) | Set to `SUCCESS` when the client certificate was verified against the bank's client CA. The gateway removes any inbound value and sets the header itself on every request, including requests without a client certificate. |
| `x-client-cert-sha256` (`MTLS_CERT_SHA256_HEADER`) | SHA-256 fingerprint of the verified client certificate (DER), 64 hex digits; colons and upper case are accepted. The gateway removes any inbound value and sets it on every request. |
| `X-Forwarded-For` | Used for the client address in logs, throttling and audit records only when the connecting address is trusted; the gateway sets it. |
| Device routes | The routes listed in `mtlsGateway.ts` are exempt from the check and are reached by phones without a client certificate. |

Requests that fail the check receive 403 (`mTLS gateway required`, `Verified client certificate required`, `Verified client certificate fingerprint required`). Each bank client's fingerprints are registered with `setClientCertificates <clientId> <hex>[,<hex>]`, or with `registerClient --mtls-cert-sha256=<hex>[,<hex>]` at registration ([bank backend guide](../integration/bank-backend-guide.md#1-register-the-bank-client)); a token request or bank API call with an unregistered fingerprint receives 401 and writes the audit event `bank_certificate_mismatch`. A gateway that passes an inbound `x-client-cert-sha256` through lets a caller choose the fingerprint the binding is checked against.

Compute a fingerprint for registration:

```sh
openssl x509 -in client.pem -noout -fingerprint -sha256
```

## Redis

Redis holds short-lived security state: bank access tokens, BOOTSTRAP tokens, device request nonces, admin sessions, login throttle counters and recovery setup salts. Two of these depend on Redis never forgetting a recent write:

- a device request nonce is recorded with `SET NX` and must stay recorded for its TTL (2 x `DEVICE_REQUEST_MAX_SKEW_SECONDS` + 60 s);
- a BOOTSTRAP token is consumed with `GETDEL` and must not reappear, because it enrols a device and, with a `replacement`, replaces the customer's current device.

Requirement for the Redis deployment (NXS-021). Auth Core does not enforce this; it is an operational requirement:

- No failover to an asynchronous replica that may lack recent writes. A promoted replica that missed the latest `SET NX` or `GETDEL` lets a captured device request be replayed or a consumed BOOTSTRAP token be used again.
- Acceptable setups: a single primary with persistence (AOF with `appendfsync always` or `everysec`, accepting the loss window of the chosen setting), or replication where the primary refuses writes it cannot replicate (`min-replicas-to-write` with `min-replicas-max-lag`, or `WAIT` semantics provided by the managed service) and failover promotes only an up-to-date replica.
- Do not restore Redis from a snapshot or backup into a running deployment. A restored snapshot brings back consumed BOOTSTRAP tokens, revoked bank tokens and ended admin sessions. After a Redis loss, start with an empty Redis; the consequences are in [disaster recovery](disaster-recovery.md#redis).
- `rediss://` with certificate verification (`REDIS_TLS_REQUIRED=true`).

## Bank integration environment

Use managed or highly available PostgreSQL and Redis (within the Redis requirement above), TLS, a bank-controlled API gateway, a secrets manager and real certificates. Mobile testing uses signed iOS and Android builds on physical devices.

The environment should exercise:

- bank backend OAuth client authentication with the client certificate binding;
- customer-scoped mobile bootstrap tokens, including device replacement;
- hardware-backed mobile credentials and Android key attestation;
- App Attest and Play Integrity verification;
- PKCS#11 against SoftHSM or the bank's test HSM;
- the bank commit flow (commit request, result, state query) and the bank's own reconciliation against it;
- evidence chain verification against the heads the bank stored;
- webhook retry and deduplication.

`auth-core/scripts/e2e-smoke.mjs` runs the bank and device flow against a deployed instance.

## Production

Production is deployed behind the bank's API gateway and WAF.

| Component | Requirement |
|---|---|
| Compute | HA Kubernetes or VM cluster inside the bank perimeter or private cloud |
| PostgreSQL | HA, encrypted transport, tested backup and restore, roles from `scripts/db/roles.sql`, DDL audit logging |
| Redis | Encrypted transport (`rediss://`); no failover to a replica that may lack recent writes ([Redis](#redis)) |
| HSM | Bank-approved PKCS#11 HSM, a formal key ceremony, the evidence key selected by token label and key label |
| API gateway | mTLS, overwrites `x-client-cert-verified` and `x-client-cert-sha256` on every request, WAF, rate limiting, restricted network access |
| Secrets | Bank-approved secrets manager |
| Android attestation | A job that refreshes `ANDROID_ATTESTATION_STATUS_FILE` ([runbook](runbooks/android-attestation-status-list.md)) |
| Monitoring | Prometheus-compatible metrics, SIEM integration, alerting |
| Evidence | Append-only retention with WORM or SIEM export per bank policy; banks keep the chain heads they receive |

Startup is fail-closed unless the PKCS#11 HSM, device attestation, database and Redis TLS, trusted gateway mTLS, admin MFA and webhook egress controls are all configured ([production blockers](configuration.md#production-blockers)). See the [threat model](../security/threat-model.md).
