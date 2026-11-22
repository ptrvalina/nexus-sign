# NEXUS-SIGN

**Cryptographic Transaction Authorization & Digital Trust Layer**

NEXUS-SIGN is a bank-controlled authorization layer delivered through native iOS and Android SDKs. It binds a specific customer identity, credential and transaction context into a cryptographically verifiable authorization record while remaining inside the bank's existing application and security perimeter.

## Architecture

```text
Bank App
   │
   ▼
NEXUS-SIGN SDK
   │
   ├── NEXUS ID
   ├── Device-bound Credential
   ├── Adaptive Verification
   │      Push → Audio → Video
   │
   ▼
Exact Transaction Binding
   │
   ▼
Cryptographic Signature
   │
   ▼
Independent Verification
   │
   ├── Policy / Risk Context
   ├── HSM / KMS
   └── Authorization Evidence
   │
   ▼
Bank Commit → Core Banking
```

The bank remains the system of record for customers, accounts, balances, risk decisions and transaction execution. NEXUS-SIGN does not replace core banking, fraud systems, IAM, HSM/KMS or scheme-specific controls.

## Key properties

Transaction signing on a phone is established practice. NEXUS-SIGN concentrates on what happens when an approval is disputed or a component is compromised.

- Approval that a third party can verify. Each evidence record carries the exact bytes the customer's device displayed and signed, the device signature and public key, and the bank HSM's seal in a per-customer hash chain. An auditor checks all of it offline with a small script that contains no NEXUS-SIGN server code. The HSM key holder cannot fabricate a customer's device signature, and a device key holder cannot insert a record into the sealed chain. Exception: an offline confirmation under protocol v1 (`OFFLINE_CONFIRMATION_MODE=immediate`, development and old SDKs only) is an HMAC code under a key Auth Core also holds and carries no device signature. ([evidence format](docs/protocol/evidence-format.md))
- The phone refuses to sign what it did not show. The SDK parses the signed bytes strictly, rejects any non-canonical encoding and any disagreement with the displayed fields, and builds the confirmation screen and biometric prompt from those bytes only. The same test vectors are checked by Auth Core, the iOS SDK and the Android SDK test suites (the iOS and Android suites run in CI; they have not been run on physical devices). ([protocol](docs/protocol/authorization-protocol-v1.md))
- Step-up checks that cannot be downgraded or skipped. Audio and video verification can only raise the required level, never replace the signature, and the completed factors are sealed into the evidence of that exact transaction. ([adaptive verification](docs/architecture/adaptive-verification.md)) Audio and video steps are in-app calls with a bank operator (WebRTC, [ADR 0017](docs/adr/0017-in-app-audio-video-calls.md); the call modules build in CI and are tested against Auth Core in Chromium, not yet on devices) or results of an external provider accepted only as signed tokens. Both sides show a six-digit call code derived from the DTLS fingerprints, so a substituted fingerprint in the signalling shows. A call shows a person but does not identify them, and no liveness or deepfake detection is claimed.
- No bearer tokens for everyday use. After enrolment the phone signs every request with its own device key, so there is no access token to steal or replay; the bank backend is needed to enrol the device. Enrolment and recovery each use a single-use, short-lived token. ([device authentication](docs/protocol/device-authentication-and-offline-confirmation.md))
- Confirmation without network on the phone. At a branch, an ATM or in web banking the customer scans a QR code, sees the transaction on the phone and types an 8-digit code bound to exactly those terms. With offline confirmation v2 (the production setting) the authorization stays `OFFLINE_PROVISIONAL` until the phone uploads its device signature over the same bytes, and only then becomes `VERIFIED` ([offline confirmation v2](docs/protocol/offline-confirmation-v2-deferred-signature.md)). On iOS, whose Secure Enclave returns the shared secret to the app, v3 agrees a key of Auth Core's for each authorization, so a captured secret serves one payment only ([device protocols](docs/protocol/device-authentication-and-offline-confirmation.md)).
- Push that nobody in between can read. A bank with its own push system keeps it and adds the signing layer. A bank without one lets Auth Core deliver authorization requests and its notifications (incoming payments, card spending) to its own app; each message is sealed for one device before it is stored, so Apple, Google and the database never see its text, and the phone confirms delivery with a receipt only it can compute. ([secure push](docs/protocol/secure-push.md))
- Deployed per bank. Auth Core runs in the bank's perimeter with the bank's HSM; there is no shared multi-bank service. Who operates the instance and holds the evidence key ceremony (the bank, or NEXUS-SIGN for the bank) is agreed per bank; the pilot responsibility matrix assigns both to NEXUS-SIGN ([pilot execution pack §9](docs/integration/pilot-execution-pack.md#9-responsibility-matrix)). The only outside services are Apple and Google device attestation, at enrolment and recovery, and, in push mode `NEXUS`, APNs and FCM as transport for sealed messages.

## Repository layout

| Path | Contents |
|---|---|
| `auth-core/` | Auth Core service (TypeScript, Node.js 22+, PostgreSQL, Redis): authorization, credential lifecycle, device enrolment, attestation, recovery, adaptive verification, evidence, bank integration. API contracts: `openapi.yaml` (banks and devices), `admin-openapi.yaml` (operator console) |
| `bank-integration/` | Reference bank execution boundary: the bank's own PostgreSQL rules and library that verify the device signature and the evidence before a payment runs, independently of Auth Core |
| `ios-sdk/` | Native iOS SDK (Swift Package): Secure Enclave credential, App Attest, transaction signing, offline confirmation, secure push |
| `ios-sdk-calls/` | Optional iOS module for in-app audio and video verification calls (WebRTC) |
| `android-sdk/` | Native Android SDK (Kotlin library): Keystore / StrongBox credential, Play Integrity, transaction signing, offline confirmation, secure push |
| `android-sdk-calls/` | Optional Android module for in-app audio and video verification calls (WebRTC) |
| `deploy/kubernetes/` | Example Kubernetes manifests for Auth Core (migration job, deployment, network policy) with a posture check |
| `sandbox/` | Isolated demonstration bank: the unchanged Auth Core with a SoftHSM test HSM, a demo bank with ledger, bank app API, operations console and demonstration scenarios ([sandbox/README.md](sandbox/README.md)) |
| `demo/` | iPhone and Android demo apps and a demo bank backend for trying enrolment and signing on a real phone ([demo/README.md](demo/README.md)) |
| `docs/` | Architecture, protocol specification, security and operations documentation |
| `.github/` | Continuous integration, issue and pull request templates, Dependabot |

## Quick start

**Sandbox.** Docker with Compose v2, `openssl`, `git`.

```bash
sandbox/bin/sandbox up                  # prints the console address and passwords
# open http://127.0.0.1:8190
```

**Auth Core.** Node.js 22+; PostgreSQL and Redis via Docker Compose.

```bash
cd auth-core
docker compose up -d postgres redis
cp .env.example .env
npm install --ignore-scripts        # the native PKCS#11 module is only needed with HSM_ADAPTER=pkcs11
docker compose exec -T postgres psql -U nexus -d nexus_sign -v ON_ERROR_STOP=1 < src/db/schema.sql
npm run dev                         # http://localhost:8080/readyz
```

To run everything on one machine in one step (fresh database, roles, a bank client, an admin account, the service): `cd auth-core && bash scripts/run-local.sh`. To try it on a real iPhone or Android phone, see [demo/README.md](demo/README.md).

In Windows PowerShell, which has no `<` redirection, copy the schema into the container instead: `docker compose cp src/db/schema.sql postgres:/tmp/schema.sql`, then `docker compose exec postgres psql -U nexus -d nexus_sign -v ON_ERROR_STOP=1 -f /tmp/schema.sql`. Use `Copy-Item .env.example .env` for the first step.

**Checks.**

```bash
cd auth-core && npm run typecheck && npm run check:all
cd ios-sdk && swift test
cd android-sdk && ./gradlew testDebugUnitTest
cd sandbox/bank && npm test               # sandbox bank; the full stack: sandbox/README.md
```

The integration, end-to-end, SoftHSM and WebRTC suites need PostgreSQL, Redis, SoftHSM and Chromium; CI runs all of them on every change ([CI validation](docs/engineering/CI_VALIDATION.md)). The current engineering status, with what has and has not been verified, is in [engineering readiness](docs/engineering/ENGINEERING_READINESS.md).

## Further controls

- The stable 9-digit NEXUS ID is independent of MSISDN, SIM, device and credential lifecycle.
- Private keys are generated as hardware-backed and non-exportable (Secure Enclave, StrongBox, TEE), and Auth Core checks the platform attestation; the SDK key handling has not yet been accepted on physical devices ([device acceptance checklist](docs/engineering/DEVICE_ACCEPTANCE_CHECKLIST.md)).
- Verification is atomic and single-use; signature attempts are bounded.
- The recovery phrase never leaves the device; recovery replaces the credential.
- Attestation is bound to the single-use bootstrap or recovery session and to the exact public keys.
- Production startup is fail-closed for mandatory cryptographic, attestation, transport and egress controls.

The full model, with its assumptions and limits, is in the [threat model](docs/security/threat-model.md).

## Documentation

Start with [docs/README.md](docs/README.md). The most used pages:

- [Architecture overview](docs/architecture/overview.md), [protocol specifications](docs/protocol/README.md) and [threat model](docs/security/threat-model.md)
- [Bank backend integration guide](docs/integration/bank-backend-guide.md) and the API contract in [auth-core/openapi.yaml](auth-core/openapi.yaml)
- [Configuration reference](docs/operations/configuration.md) and [runbooks](docs/operations/runbooks/README.md)
- [Architecture decision records](docs/adr/README.md)

Release notes are in [CHANGELOG.md](CHANGELOG.md). What is verified automatically, and what the bank verifies before production, is listed in [release verification status](docs/operations/release.md).

## Production readiness

Version `2.0.0-rc.2` plus unreleased changes. Not yet run on physical devices, on a bank HSM or in a bank's infrastructure, and not externally penetration-tested; these open items are listed in [release blockers](docs/engineering/RELEASE_BLOCKERS.md). A production deployment needs the bank's HSM and key ceremony, Apple and Google attestation configuration, validation on the supported devices, HA/DR tests, reconciliation with core banking and an independent penetration test. The [release checklist](docs/operations/release.md) has the complete list.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions and checks, and [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

Proprietary. See [LICENSE](LICENSE).
