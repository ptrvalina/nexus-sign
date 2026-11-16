// swift-tools-version:5.9
//
// Optional WebRTC media module of the NEXUS-SIGN iOS SDK (ADR 0017). The core
// package (../ios-sdk) has no WebRTC dependency; a bank app that offers
// in-app verification calls adds this package as well.
//
// WebRTC binary: stasel/WebRTC, an unofficial distribution of prebuilt
// libwebrtc frameworks. Exact version; DEVELOPMENT APPROVAL ONLY: provenance,
// checksum and licence review are open release blockers, see
// docs/engineering/DECISION_LOG.md D-015 and THIRD_PARTY_MEDIA.md.
import PackageDescription

let package = Package(
    name: "NEXUSSignCalls",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "NEXUSSignCalls", targets: ["NEXUSSignCalls"])
    ],
    dependencies: [
        .package(path: "../ios-sdk"),
        .package(url: "https://github.com/stasel/WebRTC.git", exact: "153.0.0"),
    ],
    targets: [
        .target(
            name: "NEXUSSignCalls",
            dependencies: [
                .product(name: "NEXUSSign", package: "ios-sdk"),
                .product(name: "WebRTC", package: "WebRTC"),
            ],
            path: "Sources/NEXUSSignCalls"
        )
    ]
)
