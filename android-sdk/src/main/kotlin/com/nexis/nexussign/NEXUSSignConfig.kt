package com.nexis.nexussign

/**
 * Which kind of mobile token the SDK is asking the host app for.
 *
 * The bank backend requests it from Auth Core (`POST /v1/mobile/sessions`)
 * and hands it to the app over its own authenticated channel. `SESSION`
 * tokens were removed in 2.0: an enrolled device signs its own requests.
 */
enum class NEXUSTokenPurpose {
    /** Single use, short lived; only accepted by `bootstrap()`. */
    BOOTSTRAP,
}

/**
 * Configuration a host bank app supplies when creating a [NEXUSSignSDK]
 * instance.
 *
 * One SDK instance is scoped to exactly one bank. Keystore aliases and local
 * state are namespaced with [bankId].
 *
 * @param bankId Stable identifier of the bank's Auth Core deployment, agreed
 *   during onboarding.
 * @param baseUrl Base URL of the bank's own Auth Core deployment
 *   (e.g. `https://verify.mybank.example/api`).
 * @param sessionTokenProvider Returns the single-use BOOTSTRAP token for the
 *   signed-in customer; called only by `bootstrap()`. The host app owns login
 *   and storage; a bank OAuth client secret must never be embedded in the
 *   mobile app. After enrolment the device signs its own requests.
 * @param requestTimeoutMillis Network request timeout.
 * @param playIntegrityCloudProjectNumber The bank's Google Cloud project
 *   number used for Play Integrity. When `null`, no integrity token is sent
 *   and Auth Core applies the bank's attestation policy (production
 *   deployments reject unattested enrolment).
 * @param promptTitle Title of the biometric confirmation dialog.
 * @param promptCancelText Label of the dialog's cancel button.
 * @param recoverySetupPromptText Description of the biometric dialog that
 *   confirms a new recovery phrase.
 * @param allowEmulatorHostHttp Development only: accept `http://10.0.2.2`, the
 *   emulator's alias for the developer's machine. Off by default, so a release
 *   build cannot be pointed at a cleartext server.
 * @param certificatePins Optional public-key pins for the host of [baseUrl]
 *: `sha256/<base64 SHA-256 of the SubjectPublicKeyInfo>`,
 *   as OkHttp's CertificatePinner and the iOS SDK use. Empty (the default)
 *   relies on the platform's certificate validation only. When set, give at
 *   least two pins (the current key and a backup) so a key rollover does not
 *   lock the app out; a connection whose chain matches none of them fails.
 */
data class NEXUSSignConfig(
    val bankId: String,
    val baseUrl: String,
    val sessionTokenProvider: suspend (NEXUSTokenPurpose) -> String,
    val requestTimeoutMillis: Long = 10_000,
    val playIntegrityCloudProjectNumber: Long? = null,
    val promptTitle: String = "Confirm transaction",
    val promptCancelText: String = "Cancel",
    val recoverySetupPromptText: String = "Confirm your new recovery phrase",
    val allowEmulatorHostHttp: Boolean = false,
    val certificatePins: List<String> = emptyList(),
) {
    init {
        require(bankId.isNotBlank()) { "bankId must not be blank" }
        // Enrolment tokens and signed requests travel to this URL. Plain HTTP is
        // accepted only for a server on the device itself, or on the
        // developer's machine when explicitly allowed (emulator testing).
        require(
            baseUrl.startsWith("https://") || LOOPBACK_HTTP.containsMatchIn(baseUrl) ||
                (allowEmulatorHostHttp && EMULATOR_HOST_HTTP.containsMatchIn(baseUrl)),
        ) { "baseUrl must be an https URL" }
        require(requestTimeoutMillis > 0) { "requestTimeoutMillis must be positive" }
        require(certificatePins.isEmpty() || (certificatePins.toSet().size >= 2 && certificatePins.all { PIN.matches(it) })) {
            "certificatePins must be empty or at least two distinct sha256/<base64> pins"
        }
        require(certificatePins.isEmpty() || baseUrl.startsWith("https://")) { "certificatePins need an https baseUrl" }
        require(promptTitle.isNotBlank() && promptCancelText.isNotBlank() && recoverySetupPromptText.isNotBlank()) { "prompt texts must not be blank" }
    }

    /** Keystore alias for this bank's signing key. */
    internal val keyAlias: String get() = "com.nexis.nexussign.$bankId.signingKey"

    private companion object {
        val LOOPBACK_HTTP = Regex("^http://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?(/|$)")
        val EMULATOR_HOST_HTTP = Regex("^http://10\\.0\\.2\\.2(:[0-9]+)?(/|$)")
        val PIN = Regex("^sha256/[A-Za-z0-9+/]{43}=$")
    }
}
