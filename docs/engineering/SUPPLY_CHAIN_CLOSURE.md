# Supply chain: what is missing and how to close it (FI-009, R-04, R-09)

Status 2026-10-18 (phase 9): **BLOCKED** in the environment that maintains this branch. Checked in phase 9: the npm registry and PyPI do not resolve (DNS), Maven Central and Google Maven are refused by the egress proxy (403), GitHub release downloads and the GitHub API are not enabled for the session, and the Docker daemon is not running. Nothing below was fabricated or filled in from memory.

## Inventory of manifests and pins in the repository

| Ecosystem | Manifest | Lock / pin present | Missing |
|---|---|---|---|
| npm (Auth Core) | `auth-core/package.json` | **none** | `auth-core/package-lock.json` (the authentic one from the GitHub repository) |
| npm (scripts, demo bank) | none (Node built-ins only) | — | — |
| Gradle (Android SDK) | `android-sdk/build.gradle.kts` | wrapper `gradle-8.9`, `gradle-wrapper.jar` SHA-256 `7d3a4ac4de1c32b59bc6a4eb8ecb8e612ccd0cf1ae1e99f66902da64df296172` (computed here; to be compared with Gradle's published wrapper checksums, which CI's `gradle/actions/setup-gradle` does) | `distributionSha256Sum` in `gradle-wrapper.properties`; `gradle/verification-metadata.xml` |
| Gradle (calls module) | `android-sdk-calls/build.gradle.kts` (`io.github.webrtc-sdk:android:150.7871.01`) | same wrapper jar | `distributionSha256Sum`; `gradle/verification-metadata.xml` with the WebRTC AAR hash |
| Gradle (demo) | `demo/android/build.gradle.kts`, `app/build.gradle.kts` | uses the SDK's wrapper | same |
| SwiftPM (iOS SDK) | `ios-sdk/Package.swift` | no external dependencies | — |
| SwiftPM (calls) | `ios-sdk-calls/Package.swift` (`stasel/WebRTC` `exact: "153.0.0"`) | **no `Package.resolved`** | `Package.resolved` with the resolved revision and binary checksum; confirmation that tag 153.0.0 exists |
| Python (sandbox) | standard library only | — | — |
| Containers | `auth-core/Dockerfile` (`node:22-alpine`), `sandbox/Dockerfile` (`python:3.12-slim`) | **tags only, no digests**: the base image can change between builds | base images pinned by digest (`FROM node:22-alpine@sha256:…`, digest read from the registry on the trusted machine); image scan results |
| CI tools | `.github/workflows/security.yml` downloads gitleaks 8.21.2 and checks a SHA-256 written in the workflow; actions are pinned by commit | the gitleaks checksum was not verified in this environment against the official release |

## Commands for a trusted machine

Requirements: a clean checkout of `ptrvalina/nexus-sign` with the branch of this work (from `nexus-sign-history.bundle`: `git fetch <bundle> remediation/2.0.0:remediation/2.0.0`), Node 22, JDK 17, Android SDK (API 34), Xcode 15 or later, Docker, network access to the official registries.

```bash
# 1. npm lockfile: restore the authentic one from the repository history.
git log --all --format=%H -- auth-core/package-lock.json | head -1     # if it ever existed
# Only if it never existed, create it once, review the diff, commit it separately:
cd auth-core && npm install --package-lock-only --ignore-scripts && git diff --stat package-lock.json
# 2. Deterministic install and baseline (refuses to run without a lockfile):
bash auth-core/scripts/verify-baseline.sh        # writes baseline-report.txt
# 3. Gradle: pin the distribution and generate dependency verification from a trusted resolution
cd android-sdk && ./gradlew wrapper --gradle-version 8.9 --gradle-distribution-sha256-sum <from https://gradle.org/release-checksums/>
./gradlew --write-verification-metadata sha256 help assembleRelease
cd ../android-sdk-calls && ./gradlew --write-verification-metadata sha256 help assembleRelease
# 4. SwiftPM: resolve and keep Package.resolved
cd ios-sdk-calls && swift package resolve && cat Package.resolved
# 5. Scans (as in .github/workflows/security.yml)
npm audit --omit=dev --audit-level=high      # in auth-core
syft dir:. -o cyclonedx-json > sbom.json
trivy fs --scanners vuln,secret,license . ; trivy image <auth-core image>
gitleaks detect --source . --redact
```

Keep: `baseline-report.txt`, the lockfile and its SHA-256, `verification-metadata.xml`, `Package.resolved`, the SBOM, scan reports, tool versions (`node -v`, `npm -v`, `java -version`, `gradle -v`, `swift --version`, `xcodebuild -version`, `trivy -v`). The owner of the repository confirms the lockfile; the release engineer the rest.

## WebRTC artifacts (TPM-1 … TPM-7)

| Field | Android `io.github.webrtc-sdk:android:150.7871.01` | iOS `stasel/WebRTC 153.0.0` |
|---|---|---|
| SHA-256 of the obtained file | not obtained (no download) | not obtained |
| How to obtain | `./gradlew --write-verification-metadata sha256 …` (above), or `sha256sum` of the AAR in `~/.gradle/caches/modules-2/files-2.1/io.github.webrtc-sdk/android/150.7871.01/` | `swift package resolve`; the `binaryTarget` checksum in stasel's `Package.swift` at the tag, compared with `shasum -a 256` of the downloaded zip |
| Signature | Maven `.asc`: `gpg --verify android-150.7871.01.aar.asc`, key fingerprint taken from the project itself | none published |
| Third-party notices | read `LICENSE*`/`NOTICE*` inside the AAR (`unzip -l`) | read the licence files inside `WebRTC.xcframework` |
| Known vulnerabilities | compare the WebRTC milestone (M150) with Chromium/WebRTC security advisories | same for the milestone of 153.0.0 |

Gate G7 stays open until these are recorded in [THIRD_PARTY_MEDIA.md](THIRD_PARTY_MEDIA.md). Versions are not changed until then.
