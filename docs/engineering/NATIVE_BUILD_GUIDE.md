# Native builds: commands for a CI runner or development machine

The native builds can only pass on a machine with the platform toolchains and access to Maven Central, Google Maven and GitHub. The environment this work was done in has none of them (checked 2026-10-18: no `swift`/`xcodebuild`, no Android SDK, Gradle cannot reach Maven Central or Google Maven, no Docker daemon, no GitHub access). Nothing in this file has been executed there.

The same steps run in CI: jobs `android-sdk`, `android-sdk-calls`, `android-demo`, `ios-sdk`, `ios-sdk-calls`, `ios-demo` in `.github/workflows/ci.yml`. Record the run IDs and the outputs marked **record** in the release record.

## Android (Linux or macOS; JDK 17, Android SDK platform 34, build-tools 34)

```bash
export ANDROID_HOME=~/Android/Sdk
sdkmanager "platforms;android-34" "build-tools;34.0.0"

# 1. Core SDK: unit tests and release AAR
cd android-sdk
./gradlew --no-daemon testDebugUnitTest assembleRelease
#    record: build/reports/tests/testDebugUnitTest/index.html (expected: all tests incl. VerificationCallControllerTest)

# 2. Call module against the real libwebrtc AAR
cd ../android-sdk-calls
../android-sdk/gradlew --no-daemon assembleRelease
#    record: SHA-256 and signature of the resolved artifact
find ~/.gradle/caches/modules-2/files-2.1/io.github.webrtc-sdk -name '*.aar' -exec sha256sum {} +
#    Maven PGP signature (fingerprint must come from the project, not a third party):
curl -fsSLO https://repo1.maven.org/maven2/io/github/webrtc-sdk/android/150.7871.01/android-150.7871.01.aar.asc
gpg --verify android-150.7871.01.aar.asc <path to the .aar from the cache>
#    dependency conflicts:
../android-sdk/gradlew --no-daemon dependencies --configuration releaseRuntimeClasspath > deps.txt

# 3. Demo app
cd ../demo/android
../../android-sdk/gradlew --no-daemon assembleDebug
APK=app/build/outputs/apk/debug/app-debug.apk
#    record: native ABIs packaged (expect arm64-v8a, armeabi-v7a, x86_64 at least)
unzip -l "$APK" | grep -o 'lib/[^/]*/libjingle_peerconnection_so.so' | sort -u
#    record: permissions after manifest merge (expect INTERNET, RECORD_AUDIO, CAMERA, MODIFY_AUDIO_SETTINGS)
$ANDROID_HOME/build-tools/34.0.0/aapt2 dump permissions "$APK"
#    record: APK size
ls -l "$APK"

# 4. JVM conformance of the call state machine against Auth Core (needs PostgreSQL and Redis)
cd ../../auth-core && npm ci && npm run build
NEXUS_CALL_CONFORMANCE_CMD="cd ../android-sdk && ./gradlew --no-daemon testDebugUnitTest --tests com.nexis.nexussign.CallConformanceTest" \
INTEGRATION_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres INTEGRATION_REDIS_URL=redis://localhost:6379 \
  node --test test/media/sdk-call-conformance.test.mjs
```

Pass criteria: every command exits 0; the AAR checksum and signature are recorded and verified against a project-published key; the APK contains the expected ABIs and only the expected permissions; no duplicate-class or version conflict errors.

## iOS (macOS with Xcode 15 or later)

```bash
# 1. Core Swift package: build and XCTest (includes VerificationCallControllerTests)
cd ios-sdk
swift build -c release
swift test
xcodebuild -scheme NEXUSSign -destination 'generic/platform=iOS' build

# 2. Call package against stasel/WebRTC
cd ../ios-sdk-calls
xcodebuild -resolvePackageDependencies
#    record: resolved version and revision; the build fails here if the 153.0.0 tag does not exist
cat Package.resolved 2>/dev/null || find ~/Library/Developer/Xcode/DerivedData -name Package.resolved -path '*NEXUSSignCalls*' -exec cat {} +
xcodebuild -scheme NEXUSSignCalls -destination 'generic/platform=iOS' build
#    record: slices of the binary (expect ios-arm64, ios-arm64_x86_64-simulator)
find ~/Library/Developer/Xcode/DerivedData -name WebRTC.xcframework -maxdepth 8 -exec ls {} \;
#    record: SHA-256 of the downloaded zip, compared with the binaryTarget checksum in stasel's Package.swift at the tag
find ~/Library/Caches/org.swift.swiftpm -name '*.zip' -exec shasum -a 256 {} +
#    licence inventory inside the framework
find ~/Library/Developer/Xcode/DerivedData -path '*WebRTC.framework*' -iname '*licen*'

# 3. Demo app (unsigned build; for a device, select a team in Xcode: Signing & Capabilities)
cd ..
xcodebuild -project demo/ios/NEXUSSignDemo.xcodeproj -scheme NEXUSSignDemo -configuration Debug \
  -sdk iphoneos -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
#    record: Info.plist usage strings present (NSCameraUsageDescription, NSMicrophoneUsageDescription, NSFaceIDUsageDescription)
plutil -p "$(find ~/Library/Developer/Xcode/DerivedData -path '*Debug-iphoneos/NEXUSSignDemo.app/Info.plist' | head -1)" | grep -E 'Usage'
```

Pass criteria: all builds succeed for device and simulator; XCTest green; the WebRTC tag resolves, its checksum matches the package manifest, and its licence file is recorded; the demo's Info.plist has the three usage descriptions.

## Container (any machine with Docker and registry access)

```bash
cd auth-core && docker build --pull -t nexus-sign/auth-core:rc .
docker run --rm nexus-sign/auth-core:rc node -e "console.log(process.version)"
#    container scan, SBOM (tools not available in this environment)
trivy image --severity HIGH,CRITICAL nexus-sign/auth-core:rc
syft nexus-sign/auth-core:rc -o cyclonedx-json > image-sbom.json
```

## What the environment of this work could and could not do

| Step | Here | Why |
|---|---|---|
| Android Gradle build | No | No Android SDK; Maven Central and Google Maven unreachable (proxy 403) |
| Android JVM tests | Partly | `kotlinc` against hand-written Android stubs plus real kotlinx-serialization and coroutines (not an Android build) |
| Call module type check | Partly | Against hand-written org.webrtc signature stubs, not the AAR |
| Swift build / XCTest | No | No Swift toolchain on Linux here |
| Docker image | No | No Docker daemon; base images not pullable |
