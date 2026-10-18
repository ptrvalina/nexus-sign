package com.nexis.nexussign

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.util.Base64

/**
 * The SDK's call state machine and wire format against a running Auth Core,
 * with the operator played by auth-core/test/media/sdk-call-conformance.test.mjs
 * through the admin API. Media is scripted (no WebRTC on the JVM): this
 * checks that the device side speaks Auth Core's signalling protocol, not
 * that a call carries audio or video.
 *
 * Skipped unless NEXUS_CALL_CONFORMANCE points to the session file the
 * driver writes. Requests are signed as the SDK signs them (device protocol
 * v1), with java.net.http instead of OkHttp.
 */
class CallConformanceTest {
    private val file = System.getenv("NEXUS_CALL_CONFORMANCE")

    private class JdkDeviceSignalling(
        override val sessionId: String,
        private val baseUrl: String,
        private val credentialId: String,
        privateKeyPkcs8: ByteArray,
    ) : CallSignalling {
        private val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(privateKeyPkcs8))
        private val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
        private val random = SecureRandom()

        private suspend fun request(method: String, path: String, body: String?): Pair<Int, String> = withContext(Dispatchers.IO) {
            val bytes = (body ?: "").toByteArray(Charsets.UTF_8)
            val timestamp = (System.currentTimeMillis() / 1000).toString()
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16).also(random::nextBytes))
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(key); update(DeviceProtocol.requestSigningInput(method, path, timestamp, nonce, credentialId, bytes)); sign()
            }
            val builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).timeout(Duration.ofSeconds(25))
                .header("X-NEXUS-Credential", credentialId).header("X-NEXUS-Timestamp", timestamp)
                .header("X-NEXUS-Nonce", nonce).header("X-NEXUS-Signature", Base64.getEncoder().encodeToString(signature))
            if (body != null) builder.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofByteArray(bytes))
            else builder.method(method, HttpRequest.BodyPublishers.noBody())
            val response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
            response.statusCode() to response.body()
        }

        private suspend fun json(method: String, path: String, body: String?): JsonObject {
            val (status, text) = request(method, path, body)
            if (status !in 200..299) {
                val message = runCatching { ((Json.parseToJsonElement(text) as JsonObject)["error"] as JsonPrimitive).content }.getOrNull()
                throw NEXUSSignError.ServerError(status, message)
            }
            return if (text.isBlank()) JsonObject(emptyMap()) else Json.parseToJsonElement(text) as JsonObject
        }

        override suspend fun join() = CallWire.decodeJoin(json("GET", "/v1/mobile/verification-sessions/$sessionId/call", null))
        override suspend fun send(message: CallMessage, messageId: String) {
            json("POST", "/v1/mobile/verification-sessions/$sessionId/signals", CallWire.encode(message, messageId).toString())
        }
        override suspend fun receive(after: Long, waitMillis: Long) =
            CallWire.decodeBatch(json("GET", "/v1/mobile/verification-sessions/$sessionId/signals?after=$after&waitMs=$waitMillis", null), after)
        override suspend fun cancel() { json("POST", "/v1/mobile/verification-sessions/$sessionId/cancel", "{}") }
    }

    /** Scripted media: an offer SDP, one host candidate, CONNECTED once the answer is applied. */
    private class ScriptedEngine : CallMediaEngine {
        lateinit var events: MediaEvents
        val answers = mutableListOf<String>()
        val remoteCandidates = mutableListOf<String>()
        var video: Boolean? = null
        var released = 0
        override suspend fun prepare(iceServers: List<IceServer>, video: Boolean, events: MediaEvents) {
            this.events = events; this.video = video
            require(iceServers.isNotEmpty()) { "Auth Core sent no ICE servers" }
        }
        override suspend fun createOffer(iceRestart: Boolean): String {
            events.onLocalCandidate(IceCandidateInit("candidate:1 1 udp 2122260223 192.0.2.10 50000 typ host", "0", 0))
            return "v=0\r\no=- 1 ${if (iceRestart) 2 else 1} IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
        }
        override suspend fun applyAnswer(sdp: String) { answers += sdp; events.onConnectionState(MediaConnectionState.CONNECTED) }
        override suspend fun addRemoteCandidate(candidate: IceCandidateInit) { remoteCandidates += candidate.candidate }
        override fun setMicrophoneEnabled(enabled: Boolean) = Unit
        override fun setCameraEnabled(enabled: Boolean) = Unit
        override fun release() { released++ }
    }

    @Test fun `the device side runs a call with Auth Core and ends on the operator's decision`() = runBlocking {
        assumeTrue("NEXUS_CALL_CONFORMANCE not set", file != null)
        val session = Json.parseToJsonElement(File(file!!).readText()) as JsonObject
        fun s(k: String) = (session[k] as JsonPrimitive).content
        val signalling = JdkDeviceSignalling(s("sessionId"), s("baseUrl"), s("credentialId"), Base64.getDecoder().decode(s("authKeyPkcs8")))
        val engine = ScriptedEngine()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val call = VerificationCallController(signalling, engine, scope, VerificationCallController.Options(pollWaitMillis = 2_000))
            val seen = mutableListOf<CallState>()
            call.start()
            withTimeout(60_000) {
                while (!call.isEnded) { if (seen.lastOrNull() != call.state.value) seen += call.state.value; delay(20) }
            }
            seen += call.state.value
            assertEquals(CallState.Ended(CallEndReason.Decided(verified = true)), call.state.value)
            assertEquals(true, engine.video)
            assertEquals(listOf("v=0 conformance answer"), engine.answers)
            assertEquals(listOf("candidate:7 1 udp 2122260223 192.0.2.20 50001 typ host"), engine.remoteCandidates)
            assertTrue("passed through Connected: $seen", seen.contains(CallState.Connected))
            assertEquals(1, engine.released)
            File("$file.done").writeText(seen.joinToString(",") { it.javaClass.simpleName })
        } finally {
            scope.cancel()
        }
    }
}
