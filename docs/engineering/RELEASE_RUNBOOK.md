# Release runbook: NEXUS-SIGN 2.0.0

How to take the `remediation/2.0.0` work to a 2.0.0 release. Nothing here has been executed against the owner's GitHub repository, CI or any deployment: this work was done in an isolated copy without GitHub access. Every step that needs a person or a system outside that copy is marked **[owner]**.

## 0. Preconditions

| # | Item | Status |
|---|---|---|
| P1 | The authentic `auth-core/package-lock.json`, or a clone of the GitHub repository at a known commit | Missing (R-09) |
| P2 | Release gates G0–G5 at PASS for a controlled pilot; G6–G10 as the pilot level requires | See [RELEASE_GATES.md](RELEASE_GATES.md) |
| P3 | Owner approval of the WebRTC binaries for production, or a decision to ship 2.0.0 without the call modules | Development approval only (D-015) |

## 1. Bring the work into the repository [owner]

1. Create a branch from the GitHub commit that matches the audited tree (`2.0.0-rc.2`). Compare it with the local baseline commit `885d053` (`git diff --stat` of the two trees); differences other than the lockfile need review before applying anything.
2. Apply the remediation commits as patches (`git format-patch 885d053..remediation/2.0.0`, then `git am`). The local commit IDs will change; the local history is not GitHub history (R-20).
3. Restore the lockfile from GitHub; run `npm ci` in `auth-core/`. Never regenerate the lockfile from a local dependency set.
4. Open a pull request. Required reviewers: CODEOWNERS for `auth-core/src/crypto`, `migrations`, both SDKs.

## 2. CI on the pull request [owner]

All jobs in `.github/workflows/ci.yml` and `security.yml` must pass. Archive the run IDs in the release record.

| Job | What it proves | New in this work |
|---|---|---|
| `auth-core`, `auth-core-integration` (SoftHSM), `auth-core-e2e`, `auth-core-media` | Server, HSM path, end to end, real WebRTC between two browsers | media job, more integration suites |
| `sdk-call-conformance` | Android SDK call state machine against Auth Core (signalling) | yes |
| `ios-sdk`, `ios-sdk-calls`, `ios-demo` | Swift builds and tests; the call package against stasel/WebRTC 153.0.0 | `ios-sdk-calls` |
| `android-sdk`, `android-sdk-calls`, `android-demo` | Gradle builds and unit tests; the call module against the real AAR, SHA-256 recorded | `android-sdk-calls` |
| `demo-bank`, `sandbox` | Demo access control, sandbox | — |
| security workflow | CodeQL gate, dependency audit, secret scan, SBOM | — |

Record from `android-sdk-calls` and `ios-sdk-calls` the WebRTC artifact checksums into [THIRD_PARTY_MEDIA.md](THIRD_PARTY_MEDIA.md) (TPM-2, TPM-3).

## 3. Device acceptance [owner]

Run [DEVICE_ACCEPTANCE_CHECKLIST.md](DEVICE_ACCEPTANCE_CHECKLIST.md) with the demo apps built from the PR head. Record results in its table. Failing items block the release or are accepted in writing with a risk entry.

## 4. Version and changelog

1. Set `2.0.0` in `VERSION`, `auth-core/package.json` (and lockfile), both `openapi.yaml`, `NEXUSSignVersion.swift`, `NEXUSSignVersion.kt`. `scripts/check-repository.sh` checks they agree.
2. Move `[Unreleased]` in `CHANGELOG.md` to `[2.0.0] - <date>`.
3. Check `docs/operations/upgrade-2.0.md` "From 2.0.0-rc.2 to 2.0.0" against the final change set.

## 5. Staging [owner]

1. Restore a copy of production data (or a representative data set) into staging.
2. Follow the upgrade guide: migrations 019–021, `roles.sql`, new configuration (`METRICS_BEARER_TOKEN`, `OFFLINE_CONFIRMATION_MAX_AMOUNT`, `WEBRTC_*`, coturn).
3. `node scripts/e2e-smoke.mjs <staging URL>` with `NEXUS_SIGN_SMOKE_PROVIDER_KEY`.
4. Rotate one master key in staging with `rotateSecretKeys.js` and confirm offline confirmation and admin login afterwards.
5. A verification call from a phone on mobile data to an operator on the bank network, through TURN.
6. Restore drill: restore the staging backup and verify chains with `verify-evidence.mjs --heads` (R-12).

## 6. Tag and publish [owner]

1. Tag `v2.0.0` on the reviewed merge commit. `release.yml` builds the image with SBOM and provenance.
2. SDK distribution is not automated (FI-022): publish the Swift packages by tag and the Android artifacts to the bank's repository manually, with checksums, until release jobs exist.

## 7. Production [owner]

Only after the pilot level's gates pass. Follow the upgrade guide in a maintenance window, keep the backup from the window start as the rollback path, and run the post-upgrade checks. Roll forward after traffic is reopened.

## Never

- Generate or edit a lockfile by hand.
- Disable a CI check, a startup posture check or a test to make a release pass.
- Force-push or rewrite the repository's history.
- Enable call modules in production while TPM items are open, without a written risk acceptance.
