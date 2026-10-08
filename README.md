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

- Approval that a third party can verify. Each evidence record carries the exact bytes the customer's device displayed and signed, the device signature and public key, and the bank HSM's seal in a per-customer hash chain. An auditor checks all of it offline with a small script that contains no NEXUS-SIGN server code. The HSM key holder cannot fabricate a customer's signature, and a device key holder cannot insert a record into the sealed chain. ([evidence format](docs/protocol/evidence-format.md))
- The phone refuses to sign what it did not show. The SDK parses the signed bytes strictly, rejects any non-canonical encoding and any disagreement with the displayed fields, and builds the confirmation screen and biometric prompt from those bytes only. The same test vectors run in Auth Core, the iOS SDK, the Android SDK and the sandbox. ([protocol](docs/protocol/authorization-protocol-v1.md))
- Step-up checks that cannot be downgraded or skipped. Audio and video verification can only raise the required level, never replace the signature, and the completed factors are sealed into the evidence of that exact transaction. ([adaptive verification](docs/architecture/adaptive-verification.md))
- No tokens and no cloud after enrolment. The phone signs every request with its own hardware key, so there is no access token to steal or replay, and the bank backend is needed only once, to enrol the device. ([device authentication](docs/protocol/device-authentication-and-offline-confirmation.md))
- Confirmation without network on the phone. At a branch, an ATM or in web banking the customer scans a QR code, sees the transaction on the phone and types an 8-digit code bound to exactly those terms. The same strict checks apply as online.
- Push that nobody in between can read. A bank with its own push system keeps it and adds the signing layer. A bank without one lets Auth Core deliver authorization requests and its notifications (incoming payments, card spending) to its own app; each message is sealed for one device before it is stored, so Apple, Google and the database never see its text, and the phone confirms delivery with a receipt only it can compute. ([secure push](docs/protocol/secure-push.md))
- Entirely inside the bank. Auth Core runs in the bank's perimeter with the bank's HSM; there is no shared service operated by a third party. The only outside services are Apple and Google device attestation, at enrolment and recovery, and, in push mode `NEXUS`, APNs and FCM as transport for sealed messages.

## Repository layout

| Path | Contents |
|---|---|
| `auth-core/` | Auth Core service (TypeScript, Node.js 20.6+, PostgreSQL, Redis): authorization, credential lifecycle, device enrolment, attestation, recovery, adaptive verification, evidence, bank integration. API contract: `openapi.yaml` |
| `ios-sdk/` | Native iOS SDK (Swift Package): Secure Enclave credential, App Attest, transaction signing |
| `android-sdk/` | Native Android SDK (Kotlin library): Keystore / StrongBox credential, Play Integrity, transaction signing |
| `sandbox/` | Sandbox for workshops and integration rehearsals (Python standard library only) |
| `docs/` | Architecture, protocol specification, security and operations documentation |
| `.github/` | Continuous integration, issue and pull request templates, Dependabot |

## Quick start

**Sandbox.** Python 3.10 or newer; no other dependencies.

```bash
cd sandbox && ./scripts/run.sh          # Windows: .\scripts\run.ps1
# open http://127.0.0.1:8787
```

**Auth Core.** Node.js 20.6+; PostgreSQL and Redis via Docker Compose.

```bash
cd auth-core
docker compose up -d postgres redis
cp .env.example .env
npm install --ignore-scripts        # the native PKCS#11 module is only needed with HSM_ADAPTER=pkcs11
docker compose exec -T postgres psql -U nexus -d nexus_sign -v ON_ERROR_STOP=1 < src/db/schema.sql
npm run dev                         # http://localhost:8080/readyz
```

**Checks.**

```bash
cd auth-core && npm run typecheck && npm run check:all
cd ios-sdk && swift test
cd android-sdk && ./gradlew testDebugUnitTest
cd sandbox && ./scripts/test.sh
```

## Further controls

- The stable 9-digit NEXUS ID is independent of MSISDN, SIM, device and credential lifecycle.
- Private keys are hardware-backed and non-exportable (Secure Enclave, StrongBox, TEE).
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

A production deployment needs the bank's HSM and key ceremony, Apple and Google attestation configuration, validation on the supported devices, HA/DR tests, reconciliation with core banking and an independent penetration test. The [release checklist](docs/operations/release.md) has the complete list.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions and checks, and [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

Proprietary. See [LICENSE](LICENSE).
