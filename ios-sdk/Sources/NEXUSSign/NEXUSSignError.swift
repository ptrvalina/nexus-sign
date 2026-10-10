import Foundation

/// Every error the SDK can surface to the host app. One flat enum, so a
/// catch site needs to know only what happened, not which internal
/// component failed.
public enum NEXUSSignError: Error, LocalizedError {

    /// Secure Enclave is not available on this device (e.g. simulator,
    /// or a device without a Secure Enclave coprocessor).
    case secureEnclaveUnavailable

    /// Key generation or retrieval failed. `status` is the underlying
    /// `OSStatus` from Security.framework, kept for support diagnostics.
    case keyOperationFailed(status: OSStatus)

    /// App Attest could not produce an attestation (service unavailable,
    /// network error, unsupported environment). `underlying` carries the
    /// DeviceCheck error.
    case attestationFailed(underlying: Error)

    /// The user cancelled or failed biometric authentication.
    case authenticationDenied

    /// No biometric (Face ID / Touch ID) is enrolled, so the signing key can
    /// never be used. The host app should ask the user to set one up.
    case noAuthenticationMethodEnrolled

    /// Biometry is locked after too many failed attempts; the user must unlock
    /// the device with the passcode first.
    case biometryLockedOut

    /// The device has no usable biometric hardware.
    case biometryUnavailable

    /// Auth Core rejected the request. `statusCode` is the HTTP status,
    /// `message` the error message from the response, when present.
    case serverError(statusCode: Int, message: String?)

    /// The authorization's signed payload is malformed, not in canonical form,
    /// or disagrees with the fields shown to the customer. Signing is refused:
    /// the customer would otherwise approve something other than what is
    /// displayed. `reason` is a stable machine-readable code
    /// (e.g. `response_mismatch`, `not_canonical`, `duplicate_key`).
    case authorizationPayloadInvalid(reason: String, detail: String)

    /// The authorization had already expired by the time the signature was
    /// ready to submit.
    case authorizationExpired

    /// The network request could not be completed (offline, DNS failure,
    /// timeout). Distinct from `serverError` so the host app can fall back to
    /// another channel instead of showing a generic error.
    case networkUnavailable(underlying: Error)

    /// The device is not enrolled: `bootstrap()` must succeed before an
    /// authorization can be signed.
    case notRegistered

    /// The recovery phrase is malformed or does not match the one registered
    /// for this account.
    case invalidRecoveryPhrase

    /// The biometric enrolment on this device changed (a finger or face was
    /// added or removed) since the device was enrolled, so its keys can no
    /// longer be used. Recover with the recovery phrase or ask the bank to
    /// enrol the device again. Matches the Android SDK's `CredentialInvalidated`.
    case credentialInvalidated

    /// The device has no offline key (enrolled before offline confirmation
    /// was enabled, or the bank has not enabled it).
    case offlineConfirmationUnavailable

    /// A secure push message could not be opened: not a NEXUS-SIGN push, no
    /// push key on this device, or the envelope was altered. `reason` is a
    /// stable code (`not_a_secure_push`, `no_push_key`, `decryption_failed`,
    /// `invalid_content`, `unsafe_text`, `malformed_envelope`, `unsupported_version`).
    case pushMessageInvalid(reason: String)

    public var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable:
            return "This device does not support hardware-backed key storage."
        case .keyOperationFailed(let status):
            return "Key operation failed (OSStatus \(status))."
        case .attestationFailed:
            return "Device attestation failed."
        case .authenticationDenied:
            return "Biometric authentication was not completed."
        case .noAuthenticationMethodEnrolled:
            return "Set up Face ID or Touch ID on this device to confirm transactions."
        case .biometryLockedOut:
            return "Biometric authentication is locked. Unlock the device with your passcode and try again."
        case .biometryUnavailable:
            return "Biometric authentication is not available on this device."
        case .serverError(let statusCode, let message):
            return message ?? "Auth Core returned an error (HTTP \(statusCode))."
        case .authorizationPayloadInvalid(let reason, _):
            return "This confirmation request could not be verified (\(reason)) and was not signed."
        case .authorizationExpired:
            return "This confirmation request has expired."
        case .networkUnavailable:
            return "Could not reach Auth Core. Check the connection and try again."
        case .notRegistered:
            return "This device is not enrolled."
        case .invalidRecoveryPhrase:
            return "The recovery phrase is not correct. Check the words and try again."
        case .offlineConfirmationUnavailable:
            return "Offline confirmation is not set up on this device."
        case .credentialInvalidated:
            return "Face ID or Touch ID settings changed on this device. Set up confirmation again with your recovery phrase or your bank."
        case .pushMessageInvalid(let reason):
            return "This notification could not be opened (\(reason))."
        }
    }
}
