# SDK validation

What has been shown about the native SDKs (iOS in Swift, Android in Kotlin) and their call modules, as of the fourth cycle. Statuses: PASS (a real build or test passed), FAIL, PARTIAL, NOT RUN, BLOCKED (infrastructure or access missing). Runs and jobs: [CI validation](CI_VALIDATION.md).

**No SDK has run on a phone or an emulator.** A green build and unit tests prove that the code compiles for the platform and that its platform-independent logic is right; they do not prove that a key is created in the Secure Enclave or StrongBox, that a biometric prompt appears, or that a push arrives. Those are BLOCKED until devices are available ([release blockers](RELEASE_BLOCKERS.md), B1 and B2).

## Builds

| SDK | Tool and command (CI job) | Target | Status | Notes |
|---|---|---|---|---|
| iOS SDK (`ios-sdk`) | `swift test` on `macos-15` (`ios-sdk / build and unit tests`) | macOS host build of the package (iOS 15 / macOS 12 minimum declared) | PASS at `8de9d41`; NOT RUN at `f8cbc11` | First real compilation of the iOS SDK: it failed (`operator` keyword, finding N-07, job `133528489071`) and was fixed. PASS at `8de9d41` (run `43934636812`, job `133535913952`: 38 tests in 9 suites, 0 failures). The last change, `f8cbc11` (N-13), is **NOT RUN**: its iOS jobs were queued twice and cancelled after 15 minutes without a macOS runner (jobs `133541033907`, `133550486553`) |
| iOS SDK for iPhone | `xcodebuild -sdk iphoneos -destination 'generic/platform=iOS'` of the demo app against the SDK in the repository (`ios demo app / build`) | arm64 iOS device build, unsigned | PASS at `8de9d41` (job `133539501894`); NOT RUN at `f8cbc11` | Compiles the iOS-only paths (Secure Enclave, `LAContext`, Keychain access control, UIKit) for the device SDK |
| iOS call module (`ios-sdk-calls`) | `xcodebuild -scheme NEXUSSignCalls -destination 'generic/platform=iOS'` (`ios-sdk-calls / WebRTC module build`) | arm64 iOS, against `stasel/WebRTC` at an exact version | PASS at `8de9d41` (job `133539501764`) | Unchanged since |
| Android SDK (`android-sdk`) | `./gradlew testDebugUnitTest lintRelease assembleRelease` (`android-sdk / build and unit tests`) | AAR, `minSdk 28` (Android 9), `compileSdk 34`, AGP 8.5.2, Kotlin 1.9.24 | PASS | Real Android Gradle build with the Android SDK, not JVM stubs. Android Lint passed (every API call checked against `minSdk 28`) |
| Android call module (`android-sdk-calls`) | `./gradlew assembleRelease` (`android-sdk-calls / WebRTC module build`) | AAR against `io.github.webrtc-sdk:android` (pinned; SHA-256 of the artifact recorded) | PASS | Lint not possible in this composite build (TD-R2); the one API above 28 is version-guarded |
| Android demo app | `./gradlew assembleDebug` (`android demo app / debug APK`) | APK | PASS | |
| Android call state machine against a running Auth Core | `CallConformanceTest` driven by the Auth Core test (`android-sdk call state machine against Auth Core`) | JVM, real HTTP to Auth Core with PostgreSQL and Redis | PASS | Signalling only, no media |

## Unit and vector tests

| Area | iOS (XCTest) | Android (JUnit) |
|---|---|---|
| Signed payment payload: canonical bytes, display rules, D-02 labels and separators, look-alike scripts, IBAN | `SignedTransactionTests` (shared vectors, 8 valid / 59 invalid) | `SignedTransactionTest` (same vectors) |
| Payment mandate terms | `MandateTermsVectorsTests` (3 valid / 17 invalid, new in this cycle, finding N-13): **not yet run** (no macOS runner) | `MandateTermsVectorsTest` (same vectors) |
| Device protocols (request signing, nonces, offline QR) | `DeviceProtocolTests` | `DeviceProtocolTest` |
| Offline signature queue | `OfflineSignatureQueueTests` | `OfflineSignatureQueueTest` |
| Secure push (sealed per device) | `SecurePushTests` | `SecurePushTest` |
| Recovery protocol 2 | `RecoveryProtocolTests` | `RecoveryProtocolTest`, `RecoveryPhraseTest` |
| Bank trust (key fingerprints the bank checks) | `BankTrustVectorsTests` | `BankTrustVectorsTest` |
| Verification call controller (push → audio → video) | `VerificationCallControllerTests` | `VerificationCallControllerTest`, `CallConformanceTest` |
| Customer call wire format and models | `AccountModelsTests` (new) | `CustomerCallWireTest` |
| Configuration, certificate pins | `ConfigurationTests` | `NEXUSSignConfigTest` |
| Key slots | — (Keychain, device only) | `KeySlotsTest` |

## The directive's checklists

| Property | iOS | Android | Evidence / what is missing |
|---|---|---|---|
| Compilation and package configuration | PASS at `8de9d41`; the N-13 change not yet compiled | PASS | Builds above |
| API compatibility with the minimum OS | PASS (compiled for iOS 15 device SDK) | PASS (Lint, `minSdk 28`) | Run on the oldest supported OS: BLOCKED |
| Serialization | PASS | PASS | Shared vectors; Auth Core JSON decoding (`AccountModelsTests`, `CustomerCallWireTest`) |
| Dependency compatibility | PASS | PASS | Builds against pinned WebRTC artifacts; no other runtime dependency on iOS; Android: `androidx.biometric` 1.1.0, OkHttp 4.12.0, kotlinx-serialization-json 1.6.3, kotlinx-coroutines-android 1.8.1, Play Integrity 1.4.0 |
| Secure Enclave / Android Keystore and StrongBox | BLOCKED | BLOCKED | Code compiles; hardware key creation, StrongBox availability check and TEE fallback need devices |
| Keychain access control, biometric authentication | BLOCKED | BLOCKED | Compiles; `biometryCurrentSet` invalidation (D-07) and BiometricPrompt need devices |
| Transaction signing | PARTIAL | PARTIAL | Bytes to sign and prompt text checked by vectors; signing with the hardware key: BLOCKED |
| Signature verification | PASS | PASS | Vectors; the server and bank database verify in CI (integration and end-to-end) |
| Push handling | PARTIAL | PARTIAL | Sealed envelopes by vectors; delivery through APNs/FCM and the bank contour: BLOCKED |
| Audio / video (WebRTC) | PARTIAL | PARTIAL | Call modules compile against pinned WebRTC; state machines tested; media between phones: BLOCKED (media tested only Chromium ↔ Auth Core) |
| Session security (device-signed requests, nonces, pins) | PASS (logic) | PASS (logic) | Device protocol tests; TLS pinning on a device: BLOCKED |
| Lifecycle, concurrency | PARTIAL | PARTIAL | Call controller tests with concurrent signals; app background/foreground and process death: BLOCKED |
| Error handling | PASS (logic) | PASS (logic) | Every refused vector maps to a reason code |

## Warnings left

The iOS test target compiles with Swift 6 language-mode warnings in `VerificationCallControllerTests.swift` (`NSLock.lock()` from an async context, 6 places). They are in test code, not in the SDK, and are warnings in Swift 5 mode; recorded as technical debt.

## How to reproduce

```sh
# iOS (macOS 15 with Xcode, as on the `macos-15` runner)
cd ios-sdk && swift test
xcodebuild -project demo/ios/NEXUSSignDemo.xcodeproj -scheme NEXUSSignDemo -configuration Debug \
  -sdk iphoneos -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
cd ios-sdk-calls && xcodebuild -scheme NEXUSSignCalls -destination 'generic/platform=iOS' -skipPackagePluginValidation build
# Android (JDK 17, Android SDK)
cd android-sdk && ./gradlew testDebugUnitTest lintRelease assembleRelease
cd android-sdk-calls && ./gradlew assembleRelease
```
