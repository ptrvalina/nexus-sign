package com.nexis.nexussign

import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CertificatePinner
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal class NetworkClient(private val config: NEXUSSignConfig) {
    private val json = Json { ignoreUnknownKeys = true }
    private val client = OkHttpClient.Builder()
        .callTimeout(config.requestTimeoutMillis, TimeUnit.MILLISECONDS)
        .apply {
            if (config.certificatePins.isNotEmpty()) {
                val host = config.baseUrl.toHttpUrl().host
                certificatePinner(CertificatePinner.Builder().add(host, *config.certificatePins.toTypedArray()).build())
            }
        }
        .build()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()
    private val base64 = Base64.getEncoder()

    /** An enrolled device that signs its own requests with its authentication key. */
    class DeviceIdentity(val credentialId: String, val sign: (ByteArray) -> ByteArray)

    /** Set once the device is enrolled; every device request is signed with it. */
    @Volatile var deviceIdentity: DeviceIdentity? = null

    /** Auth Core time minus device time, learned from a rejected timestamp. */
    @Volatile private var clockOffsetSeconds = 0L

    private val random = SecureRandom()

    /** How a request is authenticated. */
    private sealed interface TokenSource {
        /** Signed by the enrolled device's authentication key; retried once
         * on 401 with a corrected clock. */
        object Device : TokenSource
        /** A token bound to this one call (bootstrap, recovery); never retried. */
        class Fixed(val token: String) : TokenSource
        /** No credential: the request authenticates itself (push receipts). */
        object None : TokenSource
    }

    private class Reply(val code: Int, val body: String)

    /** Public keys of one enrolment, as PEM. */
    /** PEM public keys of a new key set, and the Keystore attestation chains
     * (base64 DER, leaf first) of the signing and authentication keys. */
    class EnrolmentKeys(
        val signing: String,
        val authentication: String,
        val offline: String,
        val signingAttestation: List<String>,
        val authenticationAttestation: List<String>,
    )

    suspend fun bootstrap(keys: EnrolmentKeys, securityLevel: String, attestation: JsonObject, bootstrapToken: String): NexusMobileRegistration {
        val body = buildJsonObject {
            put("publicKeyPem", keys.signing)
            put("authPublicKeyPem", keys.authentication)
            put("offlinePublicKeyPem", keys.offline)
            put("platform", "ANDROID")
            put("securityLevel", securityLevel)
            put("deviceAttestation", attestation)
        }
        return decode(send("/v1/mobile/bootstrap", body, TokenSource.Fixed(bootstrapToken)))
    }

    suspend fun fetchAuthorization(authorizationId: String): NexusAuthorization =
        decode(send("/v1/mobile/authorizations/$authorizationId", null, TokenSource.Device))

    suspend fun signAuthorization(authorizationId: String, signatureDer: ByteArray): VerifyResponse {
        val body = buildJsonObject {
            put("signature", base64.encodeToString(signatureDer))
            put("signatureFormat", "der")
        }
        return decode(send("/v1/mobile/authorizations/$authorizationId/signature", body, TokenSource.Device))
    }

    /** Offline confirmation v2: the deferred device signature. Returns the
     * HTTP status; every non-2xx answer is a [NEXUSSignError.ServerError]. */
    suspend fun uploadDeferredSignature(authorizationId: String, signatureBase64: String): Int {
        val body = buildJsonObject {
            put("signature", signatureBase64)
            put("signatureFormat", "der")
        }
        return send("/v1/mobile/authorizations/$authorizationId/deferred-signature", body, TokenSource.Device).code
    }

    @kotlinx.serialization.Serializable
    class PushRegistrationResponse(val status: String, val provider: String, val serverPublicKeyPem: String? = null, val keyId: String)

    @kotlinx.serialization.Serializable
    class PushEnvelopeResponse(val messageId: String, val status: String, val envelope: NexusPushEnvelope)

    /** With [devicePublicKeyPem] a new push key is agreed; otherwise only the token is updated, for the key named by [keyId]. */
    suspend fun registerPush(fcmToken: String, devicePublicKeyPem: String?, keyId: String?): PushRegistrationResponse {
        val body = buildJsonObject {
            put("provider", "FCM")
            put("deviceToken", fcmToken)
            if (devicePublicKeyPem != null) put("devicePublicKeyPem", devicePublicKeyPem)
            if (keyId != null) put("keyId", keyId)
        }
        return decode(send("/v1/mobile/push-registration", body, TokenSource.Device))
    }

    suspend fun unregisterPush() {
        send("/v1/mobile/push-registration", null, TokenSource.Device, method = "DELETE") // 204, no body
    }

    suspend fun fetchPushEnvelope(messageId: String): PushEnvelopeResponse =
        decode(send("/v1/mobile/push-messages/$messageId", null, TokenSource.Device))

    /** Unauthenticated by design: the receipt itself is an HMAC under the push key. */
    suspend fun sendPushReceipt(messageId: String, credentialId: String, receipt: String) {
        val body = buildJsonObject {
            put("credentialId", credentialId)
            put("receipt", receipt)
        }
        send("/v1/push-receipts/$messageId", body, TokenSource.None)
    }

    suspend fun recoveryParameters(): NexusRecoveryParameters =
        decode(send("/v1/mobile/recovery/setup", null, TokenSource.Device))

    /** Recovery protocol 2 setup: the recovery public key, the wrapped
     * private key, and the signing key's signature over both. */
    suspend fun configureRecovery(salt: String, recoveryPublicKeyPem: String, wrappedRecoveryKey: ByteArray, signature: ByteArray) {
        val body = buildJsonObject {
            put("protocol", RecoveryProtocol.PROTOCOL)
            put("salt", salt)
            put("recoveryPublicKeyPem", recoveryPublicKeyPem)
            put("wrappedRecoveryKey", base64.encodeToString(wrappedRecoveryKey))
            put("signature", base64.encodeToString(signature))
        }
        send("/v1/mobile/recovery/setup", body, TokenSource.Device) // 204, no body
    }

    suspend fun recover(session: NexusRecoverySession, proof: ByteArray, keys: EnrolmentKeys, securityLevel: String, attestation: JsonObject): NexusRecoveryResult {
        val body = buildJsonObject {
            put("proof", base64.encodeToString(proof))
            put("newPublicKeyPem", keys.signing)
            put("authPublicKeyPem", keys.authentication)
            put("offlinePublicKeyPem", keys.offline)
            put("platform", "ANDROID")
            put("securityLevel", securityLevel)
            put("deviceAttestation", attestation)
        }
        return decode(send("/v1/recovery/sessions/${session.sessionId}/complete", body, TokenSource.Fixed(session.accessToken)))
    }

    // --- Verification calls (ADR 0017) ---

    suspend fun openVerificationSession(authorizationId: String, channel: VerificationChannel): JsonObject {
        val body = buildJsonObject { put("channel", channel.name) }
        return parseObject(send("/v1/mobile/authorizations/$authorizationId/verification-sessions", body, TokenSource.Device))
    }

    suspend fun joinCall(sessionId: String): JsonObject =
        parseObject(send("/v1/mobile/verification-sessions/$sessionId/call", null, TokenSource.Device))

    suspend fun sendCallSignal(sessionId: String, body: JsonObject) {
        send("/v1/mobile/verification-sessions/$sessionId/signals", body, TokenSource.Device)
    }

    suspend fun receiveCallSignals(sessionId: String, after: Long, waitMillis: Long): JsonObject =
        parseObject(send("/v1/mobile/verification-sessions/$sessionId/signals?after=$after&waitMs=$waitMillis", null, TokenSource.Device))

    suspend fun cancelCall(sessionId: String) {
        send("/v1/mobile/verification-sessions/$sessionId/cancel", JsonObject(emptyMap()), TokenSource.Device) // 204
    }

    // Calls the customer starts ("talk to the bank"): same signalling, own routes.
    suspend fun joinCustomerCall(callId: String): JsonObject =
        parseObject(send("/v1/mobile/customer-calls/$callId", null, TokenSource.Device))

    suspend fun sendCustomerCallSignal(callId: String, body: JsonObject) {
        send("/v1/mobile/customer-calls/$callId/signals", body, TokenSource.Device)
    }

    suspend fun receiveCustomerCallSignals(callId: String, after: Long, waitMillis: Long): JsonObject =
        parseObject(send("/v1/mobile/customer-calls/$callId/signals?after=$after&waitMs=$waitMillis", null, TokenSource.Device))

    suspend fun endCustomerCall(callId: String) {
        send("/v1/mobile/customer-calls/$callId/end", JsonObject(emptyMap()), TokenSource.Device)
    }

    suspend fun declineAuthorization(authorizationId: String, reason: NexusDeclineReason) {
        send("/v1/mobile/authorizations/$authorizationId/decline", buildJsonObject { put("reason", reason.name) }, TokenSource.Device)
    }

    // Device replacement hold (A2-01)

    suspend fun deviceReplacements(): List<NexusDeviceReplacement> =
        decode<DeviceReplacementList>(send("/v1/mobile/device-replacements", null, TokenSource.Device)).replacements

    suspend fun decideDeviceReplacement(replacementId: String, approve: Boolean): NexusDeviceReplacement =
        decode(send("/v1/mobile/device-replacements/$replacementId/${if (approve) "approve" else "cancel"}", JsonObject(emptyMap()), TokenSource.Device))

    // Customer section, payment mandates, conversations (device-signed)

    /** A device-signed call returning the raw JSON body, for the account features. */
    internal suspend fun deviceCall(method: String, path: String, body: JsonObject? = null): String =
        send(path, body ?: if (method == "GET") null else JsonObject(emptyMap()), TokenSource.Device, method).body

    /** Longest long-poll wait that still fits in the request timeout. */
    val callPollWaitMillis: Long get() = (config.requestTimeoutMillis - 2_000).coerceIn(0, 15_000)

    private fun parseObject(reply: Reply): JsonObject =
        try {
            json.parseToJsonElement(reply.body) as JsonObject
        } catch (e: Exception) {
            throw NEXUSSignError.ServerError(reply.code, "Unexpected response format")
        }

    private inline fun <reified T> decode(reply: Reply): T =
        try {
            json.decodeFromString<T>(reply.body)
        } catch (e: Exception) {
            throw NEXUSSignError.ServerError(reply.code, "Unexpected response format")
        }

    private suspend fun send(path: String, body: JsonObject?, source: TokenSource, method: String = if (body == null) "GET" else "POST"): Reply {
        val bodyBytes = body?.let { json.encodeToString(it).toByteArray(Charsets.UTF_8) }
        val first = await(buildRequest(method, path, bodyBytes, source))
        val response = if (first.code == 401 && source is TokenSource.Device) {
            // A rejected timestamp carries Auth Core's time: correct the clock
            // offset once and sign again with a fresh nonce.
            val serverTime = first.use { r ->
                runCatching { json.decodeFromString<ErrorResponse>(r.body?.string().orEmpty()).serverTime }.getOrNull()
            } ?: throw NEXUSSignError.ServerError(401, "Device signature rejected")
            // The value is unauthenticated, so only plausible offsets are used.
            val offset = serverTime - System.currentTimeMillis() / 1000
            if (kotlin.math.abs(offset) > MAX_CLOCK_OFFSET_SECONDS) throw NEXUSSignError.ServerError(401, "Device clock rejected")
            clockOffsetSeconds = offset
            await(buildRequest(method, path, bodyBytes, source))
        } else {
            first
        }
        response.use { httpResponse ->
            val text = try {
                httpResponse.body?.string().orEmpty()
            } catch (e: IOException) {
                throw NEXUSSignError.NetworkUnavailable(e)
            }
            if (!httpResponse.isSuccessful) {
                val message = runCatching { json.decodeFromString<ErrorResponse>(text).error }.getOrNull()
                throw NEXUSSignError.ServerError(httpResponse.code, message)
            }
            return Reply(httpResponse.code, text)
        }
    }

    private fun buildRequest(method: String, path: String, body: ByteArray?, source: TokenSource): Request {
        val url = (config.baseUrl.trimEnd('/') + path).toHttpUrl()
        val builder = Request.Builder()
            .url(url)
            .header("Accept", "application/json")
            .header("User-Agent", USER_AGENT)
        when (source) {
            is TokenSource.None -> Unit
            is TokenSource.Fixed -> builder.header("Authorization", "Bearer ${source.token}")
            is TokenSource.Device -> {
                val device = deviceIdentity ?: throw NEXUSSignError.NotRegistered
                // Sign the method, path and query exactly as they go on the wire.
                val target = url.encodedPath + (url.encodedQuery?.let { "?$it" } ?: "")
                signRequest(builder, device, method, target, body ?: ByteArray(0))
            }
        }
        return builder.method(method, body?.toRequestBody(jsonMediaType)).build()
    }

    /** Device protocols v1: sign method, path, time, nonce, credential and body hash. */
    private fun signRequest(builder: Request.Builder, device: DeviceIdentity, method: String, path: String, body: ByteArray) {
        val timestamp = (System.currentTimeMillis() / 1000 + clockOffsetSeconds).toString()
        val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16).also(random::nextBytes))
        val input = DeviceProtocol.requestSigningInput(method, path, timestamp, nonce, device.credentialId, body)
        builder
            .header("X-NEXUS-Credential", device.credentialId)
            .header("X-NEXUS-Timestamp", timestamp)
            .header("X-NEXUS-Nonce", nonce)
            .header("X-NEXUS-Signature", base64.encodeToString(device.sign(input)))
    }

    private suspend fun await(request: Request): Response = suspendCancellableCoroutine { continuation ->
        val call = client.newCall(request)
        continuation.invokeOnCancellation { call.cancel() }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) = continuation.resumeWithException(NEXUSSignError.NetworkUnavailable(e))
            override fun onResponse(call: Call, response: Response) = continuation.resume(response)
        })
    }

    private companion object {
        const val USER_AGENT = "NEXUSSign-Android/$NEXUS_SIGN_SDK_VERSION"
        const val MAX_CLOCK_OFFSET_SECONDS = 86_400L
    }
}
