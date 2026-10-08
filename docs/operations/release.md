# Release

What was verified for release 2.0.0-rc.2, what CI checks once it can run, and what the release owner and the bank complete before production.

## Verified for 2.0.0-rc.2 in the build environment

Run on 2026-10-07 with Node.js 22 in the environment that produced the release candidate. That environment had no access to the npm registry, Gradle and Maven repositories, container registries or GitHub Actions, and no Swift toolchain.

| Check | Command | Result |
|---|---|---|
| Typecheck and build | `npm run typecheck`, `npm run build` | Passed |
| Auth Core unit tests (including seeded property and fuzz tests) | `npm test` | 88 passed |
| Shared vectors and the iOS copies | `npm run test:vectors` | Passed |
| Routes against `openapi.yaml` | `npm run check:openapi` | Passed, 39 routes |
| Auth Core integration suites against PostgreSQL 16, Redis 7 and SoftHSM 2.7 | `npm run test:integration` | 68 passed |
| End-to-end flow against a running server | `node scripts/e2e-smoke.mjs` | 71 checks passed, with the service connected as a superuser and, after `scripts/db/roles.sql`, as `nexus_app` |
| `schema.sql` (applied twice) against the 1.4.0 schema plus migrations 013 to 018 | `pg_dump --schema-only` of both databases | Same tables, columns, constraints, indexes, functions and triggers (column order differs) |
| Repository hygiene on a clean copy | `bash scripts/check-repository.sh` | Passed |
| Sandbox tests | `python -m unittest discover -s tests` in `sandbox/` | 74 passed |
| Android SDK (Kotlin) | `./gradlew testDebugUnitTest assembleRelease` | **Not run**: no Gradle or Maven access. The sources and tests were compiled with `kotlinc` against hand-written stubs of the Android, AndroidX, OkHttp and serialization APIs; 30 of 34 JVM tests pass, the 4 `SecurePushTest` failures come from the serialization stub, not from the SDK. This is not a substitute for the Gradle build |
| iOS SDK (Swift) | `swift test` | **Not run**: no Swift toolchain |

The integration suites cover the concurrency invariants (100 parallel signatures and offline codes consume an authorization exactly once), replay, expiry, tenant isolation, the PKCS#11 adapter on SoftHSM, evidence and credential integrity against a database writer, device replacement, recovery protocol 2, the removed compatibility paths (no bearer token for enrolled devices, protocol 1 refused, bank provisioning endpoints absent), admin MFA, scope and four-eyes approval, client certificate binding, audit attribution and append-only audit, the database state machines (including a property test and migration 018's refusal on data it cannot migrate), the database roles and the production startup posture.

The Auth Core dependencies used for these runs were installed without a reviewed lockfile; the results do not cover the dependency set a release build will lock.

## Must still be verified outside the build environment

| Item | Where | Why it was not verified here |
|---|---|---|
| `auth-core/package-lock.json` generated, reviewed and committed | Controlled build environment with npm registry access | No registry access. Until it exists every CI job that installs Auth Core dependencies, the container builds and the release workflow fail by design |
| `npm audit --omit=dev --audit-level=high`, gitleaks | `security.yml`, job `audit` | Needs the lockfile, registry access and GitHub |
| iOS SDK build and unit tests, including the CommonCrypto PBKDF2 against `recovery-v2.json` | CI job `ios-sdk / build and unit tests` (macOS) | No Swift toolchain |
| Android SDK build and unit tests | CI job `android-sdk / build and unit tests` | No Gradle or Maven access |
| Device behaviour: biometric enrolment change, passcode and lock screen requirements, Keystore attestation chains, StrongBox and TEE, recovery protocol 2 end to end, the replacement notice, enrolment and requests without any bearer token | Physical devices with signed builds | Needs devices |
| CodeQL, CycloneDX SBOM, Trivy filesystem and image scans | `.github/workflows/security.yml` | Runs only on GitHub |
| Image archive, SBOM and SLSA build provenance for a tag | `.github/workflows/release.yml`; verify with `gh attestation verify` | Runs only on GitHub, for `v*` tags |
| Action pins | Workflows pin third-party actions to commit SHAs | Not exercised; review them when the workflows first run |
| Gradle `distributionSha256Sum` and dependency verification metadata (NXS-039) | Android build environment | Needs services.gradle.org and Maven access |
| Base images pinned by digest (NXS-040) | Dockerfiles | Needs container registry access |
| PKCS#11 against the bank's HSM model | Bank's test HSM with the vendor module | Only SoftHSM 2.7 was available |
| Genuine App Attest and Play Integrity verdicts, Google's live attestation status list | Bank's attestation configuration and devices | Needs Apple and Google accounts and devices |
| Gateway: overwrites `x-client-cert-verified` and `x-client-cert-sha256` on every request; who may reach `/metrics` | Bank's gateway | Deployment control outside Auth Core |
| Redis deployment without failover to a lagging replica (NXS-021) | Bank's Redis | Infrastructure decision |
| Upgrade rehearsal (1.4.0 or 2.0.0-rc.1 to 2.0.0-rc.2) on a copy of production data | Bank's test environment | Needs the bank's data |
| Independent penetration test | External | Not part of the build |

## Continuous integration

[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs on every pull request and on `main` and `release/**`:

| Job | Checks |
|---|---|
| `auth-core / build and unit tests` | Fails when `package-lock.json` is missing; `npm ci`; typecheck and build on Node.js 20 and 22; `npm run check:all` (unit tests, vectors and the iOS copies, routes against `openapi.yaml`, repository hygiene, version consistency) |
| `auth-core / integration (PostgreSQL, Redis, SoftHSM)` | `schema.sql` plus every migration; `npm run test:integration` |
| `auth-core / end-to-end (PostgreSQL, Redis)` | `schema.sql` twice and every migration; `scripts/db/roles.sql`; server as `nexus_app`; `scripts/e2e-smoke.mjs` |
| `containers / build and health check` | Auth Core and sandbox images build; the sandbox passes its health check |
| `ios-sdk / build and unit tests` | `swift test` on macOS |
| `android-sdk / build and unit tests` | Wrapper validation, unit tests (vectors read from `auth-core/test-vectors`) and release build |
| `sandbox / protocol and API tests` | Unit and API tests on Python 3.10 |

[`.github/workflows/security.yml`](../../.github/workflows/security.yml) runs CodeQL, the SBOM, Trivy and the dependency audit and secret scan (`audit`) on the same events and weekly. [`.github/workflows/release.yml`](../../.github/workflows/release.yml) runs for `v*` tags.

## Release checklist

Completed by the release owner for every release, and by the bank before the first production deployment and every upgrade.

### Build

- [ ] Lockfile generated with registry access, reviewed and committed; `npm audit --omit=dev --audit-level=high` reviewed.
- [ ] All `ci.yml` and `security.yml` jobs green on the release commit, including both SDK jobs; CodeQL and Trivy findings reviewed; SBOM archived.
- [ ] Release tag built by `release.yml`; provenance verified; image archive SHA-256 recorded.
- [ ] Gradle checksums (NXS-039) and image digests (NXS-040) added, or the gaps accepted in writing.
- [ ] `CHANGELOG.md` entry and `VERSION` consistent (`npm run check:repository`).
- [ ] `npm run smoke-test` passes against a deployed instance.

### Upgrade

- [ ] Upgrade rehearsed on a restored copy of production ([upgrade](upgrade-2.0.md)), including the checks of migrations 017 and 018 and `sealCredentialBaseline`.
- [ ] Backup taken at the start of the window and restore tested; the rollback decision point agreed.
- [ ] `scripts/db/roles.sql` applied; Auth Core connects as `nexus_app`; the migration account is a member of `nexus_owner`.
- [ ] `pgaudit` or the provider's database audit log records DDL and trigger changes.
- [ ] Client certificate fingerprints registered for every bank client; admin accounts re-provisioned with TOTP and bank scope, at least two approvers per bank.
- [ ] Customers on recovery protocol 1 and devices without an authentication key counted, and the communication agreed with the bank.
- [ ] Apps released with SDK 2.0.0-rc.2; each bank backend uses only `BOOTSTRAP` tokens, handles the replacement flow and the 409 codes, stores chain heads, compares `canonicalPayloadHash` before commit, and accepts the new webhooks.

### Cryptography

- [ ] Production HSM provisioned; `PKCS11_TOKEN_LABEL` selects exactly one token; the evidence key is unique, EC P-256, sensitive, not extractable, sign-capable.
- [ ] `/readyz` passes on every pod; `HSM_SESSION_POOL_SIZE` fits the partition's session limit; `UV_THREADPOOL_SIZE` larger than the pool.
- [ ] HSM failover and restart tested with the vendor module.
- [ ] Evidence public key and key ID recorded in the key ceremony record; key rotation tested ([runbook](runbooks/key-rotation.md)).
- [ ] Master keys generated separately and stored in the secrets manager.
- [ ] Authorization, device protocol, secure push and recovery vectors pass on Auth Core and both SDKs.

### Mobile

- [ ] App Attest App ID and root CA, Play Integrity project and package, `ANDROID_APP_CERT_SHA256` and `ANDROID_KEY_SECURITY_POLICY` configured.
- [ ] `ANDROID_ATTESTATION_STATUS_FILE` refreshed on a schedule, with an age alert ([runbook](runbooks/android-attestation-status-list.md)).
- [ ] Supported device matrix tested, including key attestation, biometric change, passcode and lock screen requirements, recovery, replacement and offline confirmation.
- [ ] Device-signed requests work through the production gateway (`DEVICE_REQUEST_PATH_PREFIX`, clock skew window).

### Network and infrastructure

- [ ] TLS policy, database TLS and `rediss://` verified; Redis does not fail over to a lagging replica ([deployment](deployment.md#redis)).
- [ ] Gateway mTLS from the `TRUSTED_PROXY_IPS` addresses; forged inbound certificate headers refused; an unregistered certificate refused and audited.
- [ ] `/metrics` reachable only by the monitoring system ([monitoring](monitoring.md)).
- [ ] Webhook host allow-list and SSRF controls tested.
- [ ] SIEM and WORM evidence export configured; alerts from [incident response](incident-response.md#detection) and [monitoring](monitoring.md) wired to on-call.

### Assurance

- [ ] Independent penetration test completed.
- [ ] [Threat model](../security/threat-model.md) and its residual risks reviewed by the bank's security architecture team.
- [ ] [Incident response](incident-response.md) and [disaster recovery](disaster-recovery.md) completed for the bank, including a restore test with chain verification against bank-held heads.
- [ ] Regulatory mapping reviewed by the bank's compliance and legal functions.
