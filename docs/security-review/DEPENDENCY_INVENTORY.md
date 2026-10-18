# Dependency inventory (2026-10-18)

**Not authoritative.** Built from the manifests in this repository and, for Auth Core, from the dependency set assembled locally from the packages' GitHub sources (the npm registry was unreachable). The authentic inventory is the SBOM from `npm sbom` over the real `package-lock.json` (`auth-core/scripts/verify-baseline.sh`) and from the release workflow; neither could be produced here (FI-009, FI-029). No vulnerability database was consulted.

## Auth Core (Node.js 22)

| Package | Scope | Declared range | Version used in local tests | Licence (from its package.json) |
|---|---|---|---|---|
| express | runtime | ^4.19.2 | 4.22.3 | MIT |
| pg | runtime | ^8.12.0 | 8.23.1 | MIT |
| ioredis | runtime | ^5.4.1 | 5.11.1 | MIT |
| zod | runtime | ^3.23.8 | 3.25.76 | MIT |
| helmet | runtime | ^7.1.0 | 7.2.0 | MIT |
| pino | runtime | ^9.3.2 | 9.14.0 | MIT |
| pino-http | runtime | ^10.2.0 | 10.5.0 | MIT |
| cbor | runtime | ^9.0.2 | 9.0.2 | MIT |
| pkcs11js | runtime (native addon) | ^2.1.6 | 2.1.7 | MIT |
| prom-client | runtime | ^15.1.3 | 15.1.3 | Apache-2.0 |
| typescript | build | ^5.5.4 | 5.9.3 | Apache-2.0 |
| @types/express, @types/node, @types/pg | build | — | local stubs, not the real packages | — |

Transitive dependencies are not listed: without the lockfile their versions are not known.

## Android

| Artifact | Used by | Version |
|---|---|---|
| androidx.biometric:biometric | SDK | 1.1.0 |
| com.squareup.okhttp3:okhttp | SDK | 4.12.0 |
| org.jetbrains.kotlinx:kotlinx-serialization-json | SDK | 1.6.3 |
| org.jetbrains.kotlinx:kotlinx-coroutines-android | SDK, calls | 1.8.1 |
| com.google.android.play:integrity | SDK | 1.4.0 |
| io.github.webrtc-sdk:android | calls | 150.7871.01 (see THIRD_PARTY_MEDIA.md) |
| androidx.lifecycle:lifecycle-runtime-ktx | calls, demo | 2.7.0 |
| androidx.appcompat:appcompat | demo | 1.6.1 |
| junit:junit | tests | 4.13.2 |

No Gradle dependency verification metadata exists (FI-021).

## iOS

| Package | Used by | Version |
|---|---|---|
| (none) | `ios-sdk` | Apple frameworks only |
| stasel/WebRTC | `ios-sdk-calls` | exact 153.0.0 (existence of the tag not confirmed; THIRD_PARTY_MEDIA.md) |

## Sandbox (Python)

Standard library only, as far as the `sandbox/` sources show; no requirements file is present.

## Bundled data

BIP-39 English word list (`ios-sdk/Sources/NEXUSSign/Resources/english.txt`, Android assets), Apple App Attest and Google attestation root certificates (`auth-core/src/crypto/*Root*.ts`). Notices for distributed artifacts are not yet produced (FI-028).
