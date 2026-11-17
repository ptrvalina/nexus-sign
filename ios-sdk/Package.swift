// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "NEXUSSign",
    platforms: [
        .iOS(.v15),
        // Host platform for `swift test` on CI. Without it SwiftPM builds for
        // macOS 10.13, where CryptoKit and async/await are unavailable.
        .macOS(.v12)
    ],
    products: [
        .library(name: "NEXUSSign", targets: ["NEXUSSign"])
    ],
    targets: [
        .target(
            name: "NEXUSSign",
            path: "Sources/NEXUSSign",
            resources: [.copy("Resources/english.txt")]
        ),
        .testTarget(
            name: "NEXUSSignTests",
            dependencies: ["NEXUSSign"],
            path: "Tests/NEXUSSignTests",
            // Shared with Auth Core and the Android SDK; regenerate with the
            // generators in auth-core/test-vectors/.
            resources: [
                .copy("Resources/signed-payload-v1.json"),
                .copy("Resources/device-protocols-v1.json"),
                .copy("Resources/secure-push-v1.json"),
                .copy("Resources/recovery-v2.json"),
                .copy("Resources/bank-trust-v1.json"),
                .copy("Resources/mandate-terms-v1.json"),
                .copy("Resources/call-code-v1.json"),
            ]
        )
    ]
)
