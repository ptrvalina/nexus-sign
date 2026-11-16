package com.nexis.nexussign

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

@Serializable
data class NexusAuthorization(
    val authorizationId: String,
    val nexusId: String,
    val credentialId: String? = null,
    val transactionReference: String,
    val operationType: String,
    val amountMinor: String,
    val currency: String,
    val beneficiary: JsonObject,
    val policyReference: String,
    val policyVersion: String,
    val canonicalPayloadHash: String,
    val canonicalPayloadBase64: String,
    val issuedAt: String,
    val expiresAt: String,
    val state: String,
) {
    /**
     * The transaction exactly as it will be signed, parsed from
     * [canonicalPayloadBase64] and cross-checked against every other field of
     * this response. Build confirmation UI from this, not from the fields above.
     *
     * @throws NEXUSSignError.AuthorizationPayloadInvalid if the signed bytes are
     *   malformed, not canonical, or disagree with the response fields.
     */
    fun signedTransaction(): NexusSignedTransaction {
        val beneficiaryStrings = beneficiary.mapValues { (key, value) ->
            (value as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: throw NEXUSSignError.AuthorizationPayloadInvalid("response_mismatch", "beneficiary.$key")
        }
        val envelope = AuthorizationEnvelope(
            authorizationId = authorizationId, nexusId = nexusId, credentialId = credentialId,
            transactionReference = transactionReference, operationType = operationType,
            amountMinor = amountMinor, currency = currency, beneficiary = beneficiaryStrings,
            policyReference = policyReference, policyVersion = policyVersion,
            issuedAt = issuedAt, expiresAt = expiresAt,
            canonicalPayloadHash = canonicalPayloadHash, canonicalPayloadBase64 = canonicalPayloadBase64,
        )
        return try {
            SignedPayload.verify(envelope)
        } catch (e: SignedPayload.Rejected) {
            throw NEXUSSignError.AuthorizationPayloadInvalid(e.reason, e.message ?: e.reason)
        }
    }
}

@Serializable
data class NexusMobileRegistration(
    val nexusId: String,
    val credentialId: String,
    val credentialState: String,
    val keyAlgorithm: String,
    val keyVersion: Int,
    val attestationStatus: String,
    /** Always DEVICE_SIGNATURE: the device signs its own requests. */
    val requestAuthentication: String = "DEVICE_SIGNATURE",
    val offlineServerPublicKeyPem: String? = null,
)

/** Recovery KDF parameters. `nexusId` and `credentialId` are returned to the
 * enrolled device during setup, so it binds the wrapped key to its identity. */
@Serializable
data class NexusRecoveryParameters(
    val protocol: Int = 1,
    val kdf: String,
    val iterations: Int,
    val keyLength: Int,
    val salt: String,
    val nexusId: String? = null,
    val credentialId: String? = null,
)

@Serializable
data class NexusRecoverySession(
    val sessionId: String,
    val nexusId: String,
    val nonce: String,
    val accessToken: String,
    val parameters: NexusRecoveryParameters,
    /** Recovery protocol 2: the recovery public key and the key wrapped under the phrase. */
    val recoveryPublicKeyPem: String? = null,
    val wrappedRecoveryKey: String? = null,
    val expiresAt: String,
)

@Serializable
data class NexusRecoveryResult(
    val nexusId: String,
    val credentialId: String,
    val keyVersion: Int,
    /** Always DEVICE_SIGNATURE: the device signs its own requests. */
    val requestAuthentication: String = "DEVICE_SIGNATURE",
    val offlineServerPublicKeyPem: String? = null,
)

/** A transaction read from an offline QR code, verified and ready to show. */
class NexusOfflineChallenge internal constructor(
    /** The transaction exactly as it is confirmed; render the screen from this. */
    val transaction: NexusSignedTransaction,
    internal val canonicalPayload: ByteArray,
    /** Offline confirmation v2 (QR `NXS2.`): [NEXUSSignSDK.confirmOffline]
     * also signs the transaction and keeps the signature for upload. */
    val requiresDeviceSignature: Boolean = false,
)

enum class NEXUSVerificationOutcome { VERIFIED, FAILED, EXPIRED }

/**
 * A device replacement the bank requested for this customer's NEXUS ID
 * (audit finding A2-01). Show it on the enrolled device: the customer
 * approves it (the new device can be enrolled at once) or cancels it
 * ("it wasn't me"). Without a decision it becomes usable at [notBefore].
 */
@Serializable
data class NexusDeviceReplacement(
    val replacementId: String,
    val nexusId: String,
    /** BRANCH_VISIT, VIDEO_IDENTIFICATION, IN_APP_STRONG_AUTHENTICATION or OTHER. */
    val method: String,
    val reference: String,
    /** PENDING or APPROVED while open; CANCELLED, USED or EXPIRED afterwards. */
    val state: String,
    val requestedAt: String,
    val notBefore: String,
    val expiresAt: String,
    val usable: Boolean,
)

@Serializable
internal data class DeviceReplacementList(val replacements: List<NexusDeviceReplacement>)

@Serializable
internal data class VerifyResponse(val status: String, val reason: String? = null)

@Serializable
internal data class ErrorResponse(val error: String? = null, val serverTime: Long? = null, val code: String? = null)
