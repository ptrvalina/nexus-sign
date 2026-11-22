# Contributing

## Engineering standards

- The authorization protocol is deterministic and versioned. A change to the signed bytes is a new protocol version, not a patch.
- Protocol changes update the generators in `auth-core/test-vectors/` and regenerate the vectors (`npm run generate:vectors`, which also writes the iOS copies in `ios-sdk/Tests/NEXUSSignTests/Resources/`; no other copy may exist). Auth Core and both SDKs pass the same vectors.
- Bank systems stay authoritative for customer identity, account state, risk decisions and transaction execution.
- Transaction binding, credential lifecycle, attestation and evidence controls are not bypassed for convenience, including in tests and in `sandbox/` (its fault injection can only make a check fail).
- New security-sensitive behavior comes with tests, an entry in [docs/security/threat-model.md](docs/security/threat-model.md) and, where it can be misconfigured, a production gate in `auth-core/src/config/productionPosture.ts`.
- Significant design decisions are recorded as an ADR in [docs/adr/](docs/adr/README.md).
- Prefer small, explicit modules over framework-heavy abstractions at security boundaries.
- Do not commit secrets, customer data, build output or local environment files.

## Conventions

- Spelling: American English with "-ize", except "enrol", "enrolment", "enrolled". Terms: Auth Core, NEXUS ID, device credential, recovery phrase, sandbox.
- Comments explain why, not what. No change history in comments; that belongs in the commit message and `CHANGELOG.md`.
- Error messages are sentences ending with a period in the SDKs, and short phrases without one in Auth Core responses.
- Commit messages: imperative subject line of at most 72 characters, a blank line, then the reason for the change.
- Database changes add a numbered file to `auth-core/migrations/` and update `src/db/schema.sql` so that a fresh install and an upgraded database have the same schema.
- `VERSION` is the single release number. `auth-core/package.json`, both `openapi.yaml` files and both SDK version constants follow it; `npm run check:repository` fails otherwise.

## Before opening a pull request

```bash
cd auth-core && npm run typecheck && npm run check:all
cd ios-sdk && swift test
cd android-sdk && ./gradlew testDebugUnitTest
cd sandbox/bank && npm test
```

Add the change to `CHANGELOG.md` under `## [Unreleased]`. A security-relevant change also updates the matching page under `docs/security/`.
