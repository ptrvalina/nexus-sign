import Foundation

/// Configuration a host bank app supplies when creating a `NEXUSSignSDK`.
///
/// One SDK instance is scoped to one bank's Auth Core deployment. `bankID`
/// also namespaces the Secure Enclave key tag and the SDK's stored state, so
/// two configurations never collide inside the same app.
public struct NEXUSSignConfig {

    /// Stable identifier of the integrating bank, agreed during onboarding.
    public let bankID: String

    /// Base URL of the bank's Auth Core deployment, e.g.
    /// `https://nexus-sign.mybank.example`. Each bank runs its own instance.
    public let baseURL: URL

    /// Supplies the single-use BOOTSTRAP token issued by the bank backend
    /// (`POST /v1/mobile/sessions`) after it has authenticated the customer.
    /// It is requested only for enrolment; an enrolled device signs its own
    /// requests. A bank OAuth client secret must never be embedded in the app.
    public let sessionToken: SessionTokenProvider

    /// Keychain access group, only needed when the host app shares a keychain
    /// between an app and an extension. Leave `nil` otherwise.
    public let keychainAccessGroup: String?

    /// Keychain access group for the secure push key, shared with the app's
    /// Notification Service Extension. Separate from `keychainAccessGroup` so
    /// that adding push does not move the existing device keys. Defaults to
    /// `keychainAccessGroup`.
    public let pushKeychainAccessGroup: String?

    /// Timeout for each network request.
    public let requestTimeout: TimeInterval

    /// Reason shown in the biometric prompt when the customer sets up a
    /// recovery phrase. Localize it in the host app.
    public let recoverySetupPromptText: String

    /// Optional public-key pins for the host of `baseURL` (FI-006, NXS-028):
    /// `sha256/<base64 SHA-256 of the SubjectPublicKeyInfo>`, the form the
    /// Android SDK (OkHttp) uses. Empty (the default) relies on the system's
    /// certificate validation only. When set, give at least two pins (the
    /// current key and a backup); a connection whose chain matches none of
    /// them fails. The system validation still runs first.
    public let certificatePins: Set<String>

    public init(
        bankID: String,
        baseURL: URL,
        sessionToken: @escaping SessionTokenProvider,
        keychainAccessGroup: String? = nil,
        pushKeychainAccessGroup: String? = nil,
        requestTimeout: TimeInterval = 10,
        recoverySetupPromptText: String = "Confirm to set up your recovery phrase",
        certificatePins: Set<String> = []
    ) {
        // Enrolment tokens and signed requests travel to this URL. Plain HTTP is
        // accepted only for a server on this machine (simulator testing).
        precondition(baseURL.scheme == "https" || (baseURL.scheme == "http" && ["localhost", "127.0.0.1", "::1"].contains(baseURL.host ?? "")),
                     "NEXUSSignConfig.baseURL must be an https URL")
        self.bankID = bankID
        self.baseURL = baseURL
        self.sessionToken = sessionToken
        self.keychainAccessGroup = keychainAccessGroup
        self.pushKeychainAccessGroup = pushKeychainAccessGroup ?? keychainAccessGroup
        self.requestTimeout = requestTimeout
        self.recoverySetupPromptText = recoverySetupPromptText
        precondition(certificatePins.isEmpty || (certificatePins.count >= 2 && certificatePins.allSatisfy(CertificatePinning.isWellFormedPin) && baseURL.scheme == "https"),
                     "NEXUSSignConfig.certificatePins must be empty or at least two sha256/<base64> pins for an https baseURL")
        self.certificatePins = certificatePins
    }
}

/// Which kind of mobile token the SDK needs from the bank backend.
public enum NEXUSTokenPurpose: String {
    /// Single-use, 5 minutes: enrols this device's key (`bootstrap()`).
    /// `SESSION` tokens were removed in 2.0: enrolled devices sign their requests.
    case bootstrap = "BOOTSTRAP"
}

/// Returns a mobile token for the requested purpose. The host app obtains it
/// from its own backend, which calls Auth Core with `{ nexusId, purpose }`.
public typealias SessionTokenProvider = (NEXUSTokenPurpose) async throws -> String
