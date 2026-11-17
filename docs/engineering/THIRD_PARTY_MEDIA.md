# Third-party media dependencies (WebRTC)

Status: **development approval only**. Not approved for production. The open items at the end are release blockers.

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
| Checksum | **Not recorded.** (2026-10-18: still not obtained.) The Maven Central page lists none; the `.sha1`/`.asc` files could not be fetched here (Maven repositories are not reachable from this environment). CI job `android-sdk-calls` records the SHA-256 of the resolved AAR as an artifact | SHA-256 `3e3a8946f27510133e3feed04d05fa23505bbe366e977620503bfc7986c2b78f` for M153, **from third-party texts only; unverified, see the 2026-10-18 section**. SwiftPM verifies the `binaryTarget` checksum in stasel's `Package.swift` on download; CI job `ios-sdk-calls` prints `Package.resolved` |
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

## Verification attempt 2026-10-18

Artifacts could not be downloaded here: Maven Central, Google Maven and the npm registry are unreachable from this environment, and GitHub release downloads are refused (no linked GitHub account). Nothing below was checked against a downloaded artifact. Third-party statements are recorded as claims, not as evidence.

### iOS, stasel/WebRTC 153.0.0

| Question | Finding | Status |
|---|---|---|
| Does release 153.0.0 exist on the official releases page? | The releases page as fetched lists M150 as "Latest" and releases down to M137; 153.0.0 and 155.0.0 do not appear. The README's SPM example names 155.0.0 and the Swift Package Index lists 155.0.0 as the latest of 61 releases. Third-party Dependabot pull requests bump to 153.0.0 | **CONFLICTING EVIDENCE**; existence of the 153.0.0 tag not confirmed from the official page |
| Checksum `3e3a8946…b78f` | Appears in third-party texts only: a Dependabot pull request in another project and issue #168 on stasel/WebRTC (an open request by a third party, citing a GitHub Actions run; no maintainer answer). **Not verified**; it must not be relied on | UNVERIFIED (corrects the earlier wording of this file) |
| Source commit `9ea5afca…` (branch-heads/8010) | Same third-party sources | UNVERIFIED |
| Third-party licence inventory | Issue #168 asks the maintainers for exactly this (LICENSE.md, GN args for `//sdk:framework_objc`); no answer shown | OPEN |

Consequence: the pin `exact: "153.0.0"` is kept, because changing it without evidence would be an unverified upgrade; CI job `ios-sdk-calls` will fail at package resolution if the tag does not exist. **Release blocker TPM-3 stays open**, now including "confirm the tag exists".

### Android, io.github.webrtc-sdk:android 150.7871.01

| Question | Finding | Status |
|---|---|---|
| Release | GitHub release v150.7871.01 of webrtc-sdk/android, tag commit `7b6390fb098303b31af76906bf15f7decaa4ef95`, published by github-actions, notes "release: 150.7871.01 (#53)", 5 assets; no checksums shown | Read from the official page |
| Native source revision | Unlike the 144.x releases, the 150.7871.01 notes carry no "Corresponds to" line to a webrtc-sdk/webrtc commit. A third-party issue (#56, open, no maintainer answer) states a native source `73cb8180…` and a signing key fingerprint `E65BD435…F446`; **claims only** | UNVERIFIED |
| Licence | The packaging repository declares **MIT** (`LICENSE`); the Maven POM declares **BSD-3-Clause**; a `Licenses` folder exists (contents not read). The licences of the packaging and of the native library differ by nature; which applies to which file is not stated | **INCONSISTENT DECLARATIONS** |
| Build process | Repository has `.github/workflows`, `downloadAar*.sh`, `prefixmove*.sh`, `RELEASING.md`; the names suggest the AAR is built elsewhere and re-packaged here. Not read | UNVERIFIED |
| Patches over upstream | Issue #56 asks which upstream WebRTC fixes (SCTP and others) are included; no answer shown | OPEN |
| Checksum and signature | Not obtained | OPEN |

### What closes TPM-1 to TPM-7

Run on a machine with access to Maven Central and GitHub (commands in `docs/engineering/NATIVE_BUILD_GUIDE.md`): download the AAR, `.pom`, `.asc` and the XCFramework zip; compute SHA-256; verify the Maven PGP signature against a key fingerprint published by the project itself (not by a third party); compare the SwiftPM `binaryTarget` checksum in stasel's `Package.swift` at the tag; read the licence and NOTICE files inside each artifact; record everything here.

## Re-check 2026-10-18

Release pages fetched again with the web fetch tool (the shell still cannot reach Maven Central, Google Maven, the npm registry or GitHub downloads: proxy 403 / no DNS; no GitHub account linked). Manifests unchanged: `android-sdk-calls/build.gradle.kts` pins `io.github.webrtc-sdk:android:150.7871.01`; `ios-sdk-calls/Package.swift` pins `stasel/WebRTC` `exact: "153.0.0"`. No version was changed.

| Field | Android: `io.github.webrtc-sdk:android` | iOS: `stasel/WebRTC` |
|---|---|---|
| Exact name and version in the manifest | `io.github.webrtc-sdk:android:150.7871.01` | `https://github.com/stasel/WebRTC.git`, `exact: "153.0.0"` |
| Official source | github.com/webrtc-sdk/android (packaging), Maven Central (artifact) | github.com/stasel/WebRTC (releases, `Package.swift` with `binaryTarget`) |
| Official release / commit | Release v150.7871.01, marked Latest; tag commit `7b6390fb098303b31af76906bf15f7decaa4ef95` | **153.0.0 not on the releases page** (pages show M150 "Latest" back to M137). For comparison, the official M150 (150.0.0) entry states commit `6ed87f05…`, WebRTC commit `1f975dfd…` and an SHA-256 `f9890492…cf6b2` |
| Checksum of a downloaded artifact | **Not obtained** (no download possible) | **Not obtained**. The 153.0.0 checksum known from third-party texts remains unverified; the M150 checksum is the maintainer's statement, not a hash we computed |
| Native source revision | Not stated on the release (third-party claim only) | For 153.0.0: none from the maintainer; for 150.0.0: stated on the release page |
| Licence of the wrapper | Repository: MIT; POM: BSD-3-Clause (inconsistent) | Repository licence not re-read in this phase |
| Licence of WebRTC itself | BSD-3-Clause with the WebRTC patent grant (upstream); applies to the libwebrtc code, not automatically to everything in the binary | same |
| Licences of embedded components | Not inventoried (BoringSSL, libvpx, Opus, libyuv, usrsctp, abseil and others are usual in libwebrtc builds; presence and versions unknown for these binaries) | same |
| Codecs used by our modules | VP8, VP9 (filtered factories), Opus | VP8, VP9 (filtered factories), Opus |
| Codecs present in the binary | **Unknown.** Filtering what our code negotiates does not show what is compiled in; H.264 may be present | **Unknown**; the distribution states the H.264 encoder is enabled |
| Build and reproducibility | Built outside the packaging repository and re-packaged (script names); not reproducible from what is published | Prebuilt XCFramework; the build parameters (GN args) are not published for 153.0.0 |

Options for the owner (not acted on, no automatic upgrade): (a) keep 153.0.0 and obtain the tag, checksum and source commit from the maintainer; (b) move the iOS pin to a release that the official page documents (150.0.0 is the newest such release), after evaluating its changes and security fixes; (c) build libwebrtc for both platforms from a named upstream commit. Each needs the evaluation described under "Update process".

## Re-check 2026-10-18

- Releases page of stasel/WebRTC fetched again: M150 (150.0.0) is "Latest"; 153.0.0 does not appear on the first page (M150 back to M137). The tags page could not be read (the site disallows automated fetching), so the existence of the 153.0.0 tag is **still unconfirmed**; a web search returned only Swift Package Index build pages that could not be opened.
- No artifact was downloaded (Maven Central and Google Maven refused by the proxy; GitHub downloads not enabled), so no SHA-256 was computed for either binary and no licence or NOTICE file inside them was read.
- Versions unchanged.

## Verification in CI 2026-11-17 (finding D-14)

The Security workflow job `WebRTC binaries (checksums, signature, licence files)` (`.github/media/check-webrtc-binaries.sh`) downloads exactly the pinned versions on a GitHub runner, which can reach Maven Central and GitHub. First run: job `133847260552` of run `44026272757`, commit `c0fae11`; the report is kept as the artifact `webrtc-binaries-report`. The job fails on a checksum mismatch or an invalid signature, so every pull request re-checks these facts.

| | Android `io.github.webrtc-sdk:android:150.7871.01` | iOS `stasel/WebRTC` 153.0.0 |
|---|---|---|
| SHA-256 computed from the downloaded artifact | `0a1627b1a48c2bc17d9a40d62fc47bd45166f44a311e95917f147c402de379b0` (AAR) | `3e3a8946f27510133e3feed04d05fa23505bbe366e977620503bfc7986c2b78f` (`WebRTC-M153.xcframework.zip`) |
| Publisher's checksum | Matches Maven Central's `.sha1` and `.sha256` | Matches the `binaryTarget` checksum in `Package.swift` of tag 153.0.0: **the tag exists**, and the checksum known earlier only from third-party texts is now confirmed |
| Signature | Maven Central PGP signature of AAR and POM **valid**, key `E65BD4351D0FF0EF9C0C15FF3CCBD94F6FC0F446`, user ID `dliu1030 <dl@watercooler.fm>`. That this key belongs to the webrtc-sdk project is **not established** (no fingerprint published by the project was found) | None (SwiftPM verifies the checksum on download) |
| Licence files inside the artifact | **None** in the AAR; the POM declares BSD-3-Clause | `WebRTC.xcframework/LICENSE` (contents not reviewed) |

Status of the open items: **TPM-3 closed** (tag, checksum). **TPM-2 in part**: checksums and signature verified on every run; the signer's key is not confirmed as the project's, and Gradle dependency verification metadata is not committed. **TPM-1, TPM-4 to TPM-7 open**: source revision, licence inventory, codec patents, vulnerability review and the build-it-yourself decision remain the owner's, so the binaries stay at development approval (D-015) and the release blocker remains.
