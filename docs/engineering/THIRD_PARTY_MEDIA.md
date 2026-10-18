# Third-party media dependencies (WebRTC)

Status: **development approval only** (product owner, 2026-10-18). Not approved for production. The open items at the end are release blockers (RELEASE_GATES.md, gate G7).

The core SDKs (`ios-sdk`, `android-sdk`) have no WebRTC dependency. Only the optional call modules (`ios-sdk-calls`, `android-sdk-calls`) link libwebrtc, and only bank apps that offer in-app verification calls include them.

## Selected distributions

| | Android | iOS |
|---|---|---|
| Artifact | `io.github.webrtc-sdk:android` (Maven Central, AAR) | `stasel/WebRTC` (Swift package with a prebuilt `WebRTC.xcframework`) |
| Pinned version | `150.7871.01` (exact, `android-sdk-calls/build.gradle.kts`) | `153.0.0` (`exact:`, `ios-sdk-calls/Package.swift`) |
| Newer version seen | none newer on the 150 line (144.7559.15 of 2026-09-06 is a maintenance release of an older line) | `155.0.0` (about 2026-10-06) |
| Why this version | Newest WebRTC milestone published (Maven Central page: "1 month ago"; mvnrepository: 2026-09-01) | The newest release for which a source revision and a checksum were found (below). Moving to 155.0.0 needs the same evidence first |
| Source | Project URL in the POM: github.com/webrtc-sdk/android (not inspected, see below) | WebRTC source from webrtc.googlesource.com/src, built by the repository's `scripts/build.sh` in its GitHub Actions workflow `webrtc-release.yml` (repository README) |
| Source revision of the pinned binary | **Not verified.** The version scheme suggests Chromium milestone 150, branch-head 7871, patch 01. That is an inference, not evidence | Release notes of M153: `branch-heads/8010`, commit `9ea5afcad008b940468c2a15aec339592cf5a935`, as quoted in a third-party pull request, not read on the release page itself |
| Checksum | **Not recorded.** The Maven Central page lists none; the `.sha1`/`.asc` files could not be fetched here (Maven repositories are not reachable from this environment). CI job `android-sdk-calls` records the SHA-256 of the resolved AAR as an artifact | SHA-256 `3e3a8946f27510133e3feed04d05fa23505bbe366e977620503bfc7986c2b78f` for M153, from the same third-party copy of the release notes. SwiftPM verifies the `binaryTarget` checksum in stasel's `Package.swift` on download; CI job `ios-sdk-calls` prints `Package.resolved` |
| Declared licence | POM: "The 3-Clause BSD License" | README: build scripts BSD-3-Clause; WebRTC under the WebRTC licence. Swift Package Index shows the licence as "unknown" |
| Modifications to upstream | **Not verified.** The artifact is published by a project other than Google; whether it carries patches over upstream libwebrtc is not established | README: "no modifications are made to the source code or the output binaries"; VP9, H.264 and AV1 encoders enabled; H.265 at SDP/RTP level only |
| Platforms | minSdk of the AAR not checked; the module uses minSdk 28 like the SDK | iOS 15+, macOS 12+, Catalyst; arm64 device, arm64/x86_64 simulator (README) |
| Rebuildable independently | Not established | In principle: the build script and workflow are public and the source commit is named. Not attempted here (needs macOS, depot_tools and a full WebRTC checkout) |
| Maintenance | Several release lines maintained in 2026 (mvnrepository: releases on 2026-08-13, 08-25, 09-01, 09-06) | 61 releases; repository activity within the last week of 2026-10-12; 40 open issues (Swift Package Index) |
| Known advisories | Not checked against a vulnerability database in this session | Not checked |

Sources: Maven Central and mvnrepository pages for `io.github.webrtc-sdk:android`; the stasel/WebRTC README on GitHub; Swift Package Index; a Dependabot pull request in a third-party repository that quotes the M153 release notes. Each was read on 2026-10-18.

## Licences: what is and is not established

"BSD-licensed" is not an accurate description of either binary as a whole:

- **libwebrtc** is under the BSD-3-Clause licence with Google's *Additional IP Rights Grant (Patents)* (webrtc.org/support/license). That grant covers Google's patents in the WebRTC code. It does not cover third-party codec patents.
- **Third-party code compiled into libwebrtc builds** has its own licences. Typical components are BoringSSL (OpenSSL and ISC style licences), libvpx, libyuv, Opus, libsrtp and usrsctp (BSD-style), and abseil-cpp (Apache-2.0); with some build options also openh264, dav1d, libaom and FFmpeg (LGPL-2.1). **Which of these are in the two pinned binaries has not been established.** WebRTC's `tools_webrtc/libs/generate_licenses.py` produces the licence file for a given build; that file, or the equivalent shipped with each binary, has to be reviewed and included in the bank app's notices.
- **The stasel packaging scripts** are BSD-3-Clause. That licence says nothing about the binary they produce.
- **Codec patents.** H.264 and H.265 are covered by patent pools (Via LA and others) not licensed by the WebRTC grant. Both call modules offer and accept **only VP8 and VP9** (filtered encoder and decoder factories), so these codecs are not negotiated by our calls. The H.264 code may still be present in the binaries (stasel enables the H.264 encoder). Whether shipping it unused is acceptable is a legal question for the owner.

## How the modules limit exposure

- Media codecs: VP8/VP9 for video, Opus for audio (libwebrtc default). No H.264/H.265 negotiation.
- No recording, no screen capture, no data channels.
- Media is end-to-end between the phone and the bank's operator or TURN server, encrypted by DTLS-SRTP. Auth Core never receives media.
- TURN credentials are issued per session by Auth Core (TURN REST, HMAC-SHA1, expiry at most the session end). No TURN secret is in the apps.

## Update process

1. Pick the release. Read its release notes on the project's own release page and record the WebRTC branch-head and commit.
2. Download the binary. Record its SHA-256, compare it with the published checksum (for iOS, with the `binaryTarget` checksum in the package manifest of that tag), and check any signature.
3. Generate or obtain the third-party licence list for that build and review the changes.
4. Check WebRTC and Chromium security notes released since the previous version.
5. Change the pinned version in one commit with this evidence in the commit message. Update this file and the D-015 entry in DECISION_LOG.md.
6. Run the device acceptance checklist (DEVICE_ACCEPTANCE_CHECKLIST.md, section calls) on at least one iPhone and one Android phone.

Floating versions (`latest`, `branch:`, `+`, `upToNextMajor`) are not allowed in either module.

## Open items (release blockers)

| ID | Item |
|---|---|
| TPM-1 | Android: confirm the source revision and any patches of `io.github.webrtc-sdk:android:150.7871.01`, from the project's repository and build scripts |
| TPM-2 | Android: record and verify the AAR checksum and signature from Maven Central. Add Gradle dependency verification (`gradle/verification-metadata.xml`) generated from a trusted resolution |
| TPM-3 | iOS: confirm the M153 release notes, source commit and checksum on the stasel/WebRTC release page, and that the `Package.swift` checksum of tag 153.0.0 matches |
| TPM-4 | Both: third-party licence inventory of the pinned binaries, and notices for the bank apps |
| TPM-5 | Both: legal review of the codec patent position (H.264 code present but not negotiated) |
| TPM-6 | Both: vulnerability review of the pinned WebRTC milestones, and an agreed patch interval |
| TPM-7 | Both: decide whether the bank builds libwebrtc itself from the named source commits instead of using community binaries |
