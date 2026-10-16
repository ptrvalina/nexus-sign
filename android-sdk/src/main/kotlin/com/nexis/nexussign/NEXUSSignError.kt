package com.nexis.nexussign

/**
 * Every error the SDK throws. The host app only needs to know what happened,
 * not which internal component failed.
 */
sealed class NEXUSSignError(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /** The Android Keystore could not be opened on this device. */
    class KeystoreUnavailable(cause: Throwable? = null) :
        NEXUSSignError("Hardware-backed key storage is unavailable on this device.", cause)

    /** Key generation, lookup or signing failed. */
    class KeyOperationFailed(cause: Throwable) :
        NEXUSSignError("Key operation failed: ${cause.message}", cause)

    /**
     * The signing key was invalidated by the platform, typically because the
     * enrolled biometrics changed. The key has been deleted; the customer
     * must enrol the device again (new bootstrap token) or recover.
     */
    object CredentialInvalidated :
        NEXUSSignError("The signing key is no longer valid on this device. Enrol the device again.")

    /** The customer cancelled or failed biometric authentication. */
    class AuthenticationDenied(reason: String) :
        NEXUSSignError("Authentication was not completed: $reason")

    /** Too many failed biometric attempts; the platform has locked biometrics. */
    object BiometryLockedOut :
        NEXUSSignError("Biometric authentication is locked. Unlock the device with your passcode and try again.")

    /** The device has no usable biometric hardware. */
    object BiometryUnavailable :
        NEXUSSignError("Biometric authentication is not available on this device.")

    /** No strong biometric is enrolled. Ask the customer to set one up in device settings. */
    object NoAuthenticationMethodEnrolled :
        NEXUSSignError("No biometric is enrolled on this device.")

    /** Auth Core rejected the request. [serverMessage] is the `error` field of the response. */
    class ServerError(val statusCode: Int, val serverMessage: String?) :
        NEXUSSignError(serverMessage ?: "Auth Core returned an error (HTTP $statusCode).")

    /**
     * The signed payload is malformed, not canonical, or disagrees with the
     * fields shown to the customer. Nothing is signed. [reason] is a stable
     * machine-readable code (e.g. `response_mismatch`, `not_canonical`).
     */
    class AuthorizationPayloadInvalid(val reason: String, detail: String) :
        NEXUSSignError("The authorization could not be verified for signing ($reason): $detail")

    /** The authorization expired before it was signed. */
    object AuthorizationExpired : NEXUSSignError("This confirmation request has expired.")

    /** The device is locked, so its authentication key cannot sign requests
     * (for example a background fetch after a push). Retry once unlocked. */
    object DeviceLocked :
        NEXUSSignError("Unlock the device to continue.")

    /** The request did not reach Auth Core (offline, DNS failure, timeout). */
    class NetworkUnavailable(cause: Throwable) :
        NEXUSSignError("Could not reach Auth Core: ${cause.message}", cause)

    /** The device has not completed `bootstrap()` or recovery. */
    object NotRegistered :
        NEXUSSignError("This device is not enrolled.")

    /** The device has no offline key: it was enrolled before offline
     * confirmation was enabled, or the bank has not enabled it. */
    object OfflineConfirmationUnavailable :
        NEXUSSignError("Offline confirmation is not set up on this device.")

    /**
     * A secure push message could not be opened: not a NEXUS-SIGN push, no
     * push key on this device, or the envelope was altered. [reason] is a
     * stable code (`not_a_secure_push`, `no_push_key`, `decryption_failed`,
     * `invalid_content`, `unsafe_text`, `malformed_envelope`, `unsupported_version`).
     */
    class PushMessageInvalid(val reason: String) :
        NEXUSSignError("This notification could not be opened ($reason).")

    /** The recovery phrase is malformed or does not match the one on file. */
    object InvalidRecoveryPhrase :
        NEXUSSignError("The recovery phrase is not correct. Check the words and try again.")
}
