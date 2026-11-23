import Foundation

/// Build-time settings. The release workflow (.github/workflows/sandbox-apps.yml)
/// replaces `defaultServer` with the public sandbox address before building for
/// TestFlight; the customer can still change the address on the login screen.
enum AppConfig {
    static let defaultServer = "https://192.168.0.118:8191"
}
