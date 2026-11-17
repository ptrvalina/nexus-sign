package com.nexis.nexussign

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The call state machine against an in-memory relay that applies Auth
 * Core's signalling rules (one outstanding offer, candidates after the
 * description, messageId deduplication) and a scripted media engine.
 * This tests ordering, buffering, restarts and endings; it is not a media
 * test and says nothing about WebRTC on a device.
 */
/** What every real answer carries: DTLS-SRTP needs the certificate hash. */
private val DTLS_FINGERPRINT = "\r\na=fingerprint:sha-256 " + List(32) { "AB" }.joinToString(":")

class VerificationCallControllerTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    @After fun tearDown() = scope.cancel()

    class Relay(val channel: VerificationChannel = VerificationChannel.VIDEO, var expiresAt: Instant = Instant.now().plusSeconds(300)) : CallSignalling {
        override val sessionId = "00000000-0000-4000-8000-000000000001"
        private val lock = Any()
        private var seq = 0L
        val toOperator = CopyOnWriteArrayList<CallMessage>()
        private val toDevice = mutableListOf<ReceivedSignal>()
        private val ids = mutableSetOf<String>()
        private val replayed = mutableListOf<ReceivedSignal>()
        private var offers = 0; private var answers = 0
        var cancelled = 0
        var failReceives = 0
        var failSendsWith503 = 0
        var receiveError: Throwable? = null

        override suspend fun join() = VerificationCallInfo(sessionId, channel, expiresAt, listOf(IceServer(listOf("stun:turn.bank.example:3478"))), operatorJoined = false)

        override suspend fun send(message: CallMessage, messageId: String) {
            synchronized(lock) {
                if (failSendsWith503 > 0) { failSendsWith503--; ids += messageId; toOperator += message; offers += if (message is CallMessage.Offer) 1 else 0; throw NEXUSSignError.ServerError(503, "lost response") }
                if (!ids.add(messageId)) return
                when (message) {
                    is CallMessage.Offer -> { if (offers > answers) throw NEXUSSignError.ServerError(409, "offer pending"); offers++ }
                    is CallMessage.Candidate -> if (offers == 0) throw NEXUSSignError.ServerError(409, "candidate before offer")
                    is CallMessage.Answer -> throw NEXUSSignError.ServerError(400, "device never answers")
                    is CallMessage.Bye -> Unit
                }
                toOperator += message
            }
        }

        override suspend fun receive(after: Long, waitMillis: Long): SignalBatch {
            receiveError?.let { throw it }
            if (failReceives > 0) { failReceives--; throw NEXUSSignError.NetworkUnavailable(IOException("offline")) }
            val deadline = System.currentTimeMillis() + waitMillis.coerceAtMost(200)
            while (true) {
                val batch = synchronized(lock) { (replayed + toDevice.filter { it.seq > after }).also { replayed.clear() } }
                if (batch.isNotEmpty() || System.currentTimeMillis() >= deadline) return SignalBatch(batch, batch.lastOrNull()?.seq ?: after)
                delay(10)
            }
        }

        override suspend fun cancel() { cancelled++ }

        fun operator(message: CallMessage, from: String = "operator") = synchronized(lock) {
            if (message is CallMessage.Answer) answers++
            toDevice += ReceivedSignal(++seq, from, message)
        }
        /** Delivers an old message again in the next batch, whatever the cursor
         * (a replaying or misbehaving relay). */
        fun replay(index: Int) = synchronized(lock) { replayed += toDevice[index] }
        fun offersSent() = toOperator.filterIsInstance<CallMessage.Offer>()
    }

    class Engine : CallMediaEngine {
        lateinit var events: MediaEvents
        val log = CopyOnWriteArrayList<String>()
        var video: Boolean? = null
        var releases = 0
        var offerCount = 0
        override suspend fun prepare(iceServers: List<IceServer>, video: Boolean, events: MediaEvents) {
            this.events = events; this.video = video; log += "prepare"
            events.onCaptureState(cameraOn = video, microphoneOn = true)
        }
        override suspend fun createOffer(iceRestart: Boolean): String { offerCount++; log += "offer:$iceRestart"; return "v=0 offer $offerCount" }
        // Logs the first SDP line; the rest is the DTLS fingerprint.
        override suspend fun applyAnswer(sdp: String) { log += "answer:${sdp.lines()[0]}" }
        override suspend fun addRemoteCandidate(candidate: IceCandidateInit) { log += "remote:${candidate.candidate}" }
        override fun setMicrophoneEnabled(enabled: Boolean) { log += "mic:$enabled" }
        override fun setCameraEnabled(enabled: Boolean) { log += "camera:$enabled" }
        override fun release() { releases++; log += "release" }
    }

    private val fast = VerificationCallController.Options(pollWaitMillis = 100, reconnectGraceMillis = 100, retryBackoffMillis = 20, maxRetryBackoffMillis = 50)
    private fun candidate(n: Int) = IceCandidateInit("candidate:$n 1 udp 1 10.0.0.$n 9 typ host", "0", 0)

    private suspend fun until(what: String, condition: () -> Boolean) {
        try { withTimeout(5_000) { while (!condition()) delay(10) } } catch (e: Exception) { throw AssertionError("timed out waiting for $what") }
    }

    @Test fun `offer first, local candidates wait for the offer, remote ones for the answer`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        until("offer") { relay.offersSent().isNotEmpty() }
        assertEquals(CallMessage.Offer("v=0 offer 1"), relay.toOperator.first())
        assertEquals(true, engine.video)
        assertEquals(CaptureState(cameraOn = true, microphoneOn = true), call.capture.value)
        engine.events.onLocalCandidate(candidate(1))
        until("local candidate relayed") { relay.toOperator.size == 2 }

        relay.operator(CallMessage.Candidate(candidate(9)))       // before the answer: held
        until("candidate seen") { call.state.value == CallState.WaitingForOperator && relay.toOperator.size == 2 }
        delay(150)
        assertTrue("not applied before the answer", engine.log.none { it.startsWith("remote:") })
        relay.operator(CallMessage.Answer("v=0 answer" + DTLS_FINGERPRINT))
        until("answer applied") { engine.log.contains("remote:candidate:9 1 udp 1 10.0.0.9 9 typ host") }
        assertEquals(listOf("prepare", "offer:false", "answer:v=0 answer", "remote:candidate:9 1 udp 1 10.0.0.9 9 typ host"), engine.log.toList())
        assertEquals(CallState.Connecting, call.state.value)
        engine.events.onConnectionState(MediaConnectionState.CONNECTED)
        until("connected") { call.state.value == CallState.Connected }
    }

    @Test fun `candidates gathered while the offer is being sent are sent after it`() = runBlocking {
        val relay = Relay(); val engine = object : CallMediaEngine by Engine() {
            lateinit var ev: MediaEvents
            override suspend fun prepare(iceServers: List<IceServer>, video: Boolean, events: MediaEvents) { ev = events; ev.onLocalCandidate(candidate(0)); delay(50) }
            override suspend fun createOffer(iceRestart: Boolean): String { ev.onLocalCandidate(candidate(1)); ev.onLocalCandidate(candidate(2)); delay(50); return "v=0 offer" }
        }
        VerificationCallController(relay, engine, scope, fast).start()
        until("offer and the three candidates") { relay.toOperator.size == 4 }
        assertTrue(relay.toOperator[0] is CallMessage.Offer)
        assertTrue(relay.toOperator.drop(1).all { it is CallMessage.Candidate })
    }

    @Test fun `audio-only calls do not start the camera`() = runBlocking {
        val relay = Relay(VerificationChannel.AUDIO); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        until("prepared") { engine.video != null }
        assertEquals(false, engine.video)
        assertEquals(CaptureState(cameraOn = false, microphoneOn = true), call.capture.value)
    }

    @Test fun `duplicate and stale messages are ignored, an unsolicited answer and an operator offer too`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        until("offer") { relay.offersSent().isNotEmpty() }
        relay.operator(CallMessage.Answer("v=0 a1" + DTLS_FINGERPRINT))
        until("answer") { engine.log.contains("answer:v=0 a1") }
        relay.operator(CallMessage.Candidate(candidate(4)))
        until("candidate") { engine.log.any { it.contains("10.0.0.4") } }
        relay.replay(0)                                           // same seq again
        relay.replay(1)
        relay.operator(CallMessage.Answer("v=0 a2" + DTLS_FINGERPRINT))              // no outstanding offer
        relay.operator(CallMessage.Offer("v=0 from operator"))     // the device always offers
        relay.operator(CallMessage.Candidate(candidate(3)), from = "device")
        until("all seen") { call.ignoredMessages >= 3 }
        delay(100)
        assertEquals(1, engine.log.count { it.startsWith("answer:") })
        assertEquals("a repeated candidate is applied once", 1, engine.log.count { it.contains("10.0.0.4") })
        assertTrue(engine.log.none { it.contains("10.0.0.3") })
    }

    @Test fun `a dropped connection is restored with an ICE restart`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        until("offer") { relay.offersSent().size == 1 }
        relay.operator(CallMessage.Answer("v=0 a1" + DTLS_FINGERPRINT))
        until("answer") { engine.log.contains("answer:v=0 a1") }
        engine.events.onConnectionState(MediaConnectionState.CONNECTED)
        until("connected") { call.state.value == CallState.Connected }
        engine.events.onConnectionState(MediaConnectionState.DISCONNECTED)
        until("reconnecting") { call.state.value is CallState.Reconnecting }
        until("restart offer") { relay.offersSent().size == 2 }
        assertTrue(engine.log.contains("offer:true"))
        engine.events.onLocalCandidate(candidate(5))
        until("candidate of the new offer") { relay.toOperator.last() is CallMessage.Candidate }
        relay.operator(CallMessage.Answer("v=0 a2" + DTLS_FINGERPRINT))
        until("second answer") { engine.log.contains("answer:v=0 a2") }
        engine.events.onConnectionState(MediaConnectionState.CONNECTED)
        until("connected again") { call.state.value == CallState.Connected }
    }

    @Test fun `a disconnect that recovers by itself does not restart`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast.copy(reconnectGraceMillis = 300))
        call.start()
        until("offer") { relay.offersSent().size == 1 }
        relay.operator(CallMessage.Answer("v=0 a1" + DTLS_FINGERPRINT))
        until("answer") { engine.log.contains("answer:v=0 a1") }
        engine.events.onConnectionState(MediaConnectionState.CONNECTED)
        until("connected") { call.state.value == CallState.Connected }
        engine.events.onConnectionState(MediaConnectionState.DISCONNECTED)
        delay(50)
        engine.events.onConnectionState(MediaConnectionState.CONNECTED)
        delay(500)
        assertEquals(1, relay.offersSent().size)
        assertEquals(CallState.Connected, call.state.value)
    }

    @Test fun `after the restart limit the call ends and the session is closed`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast.copy(maxIceRestarts = 1))
        call.start()
        until("offer") { relay.offersSent().size == 1 }
        relay.operator(CallMessage.Answer("v=0 a1" + DTLS_FINGERPRINT))
        until("answer") { engine.log.contains("answer:v=0 a1") }
        engine.events.onConnectionState(MediaConnectionState.FAILED)
        until("restart") { relay.offersSent().size == 2 }
        relay.operator(CallMessage.Answer("v=0 a2" + DTLS_FINGERPRINT))
        until("answer 2") { engine.log.contains("answer:v=0 a2") }
        engine.events.onConnectionState(MediaConnectionState.FAILED)
        until("ended") { call.isEnded }
        assertEquals(CallState.Ended(CallEndReason.ConnectionLost), call.state.value)
        until("cancelled") { relay.cancelled == 1 }
        assertEquals(1, engine.releases)
    }

    @Test fun `a negotiation that never connects ends without restarts`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        until("offer") { relay.offersSent().size == 1 }
        engine.events.onConnectionState(MediaConnectionState.FAILED)
        until("ended") { call.isEnded }
        assertEquals(CallState.Ended(CallEndReason.ConnectionLost), call.state.value)
        assertEquals(1, relay.offersSent().size)
    }

    @Test fun `the operator's decision ends the call and releases media once`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        until("offer") { relay.offersSent().isNotEmpty() }
        relay.operator(CallMessage.Bye("decided:VERIFIED"))
        relay.operator(CallMessage.Bye("session_verified"), from = "server")
        until("ended") { call.isEnded }
        assertEquals(CallState.Ended(CallEndReason.Decided(verified = true)), call.state.value)
        delay(100)
        assertEquals(1, engine.releases)
        assertEquals(CaptureState(cameraOn = false, microphoneOn = false), call.capture.value)
        call.hangUp()
        assertEquals(0, relay.cancelled)
    }

    @Test fun `media is released before the call is reported ended`() = runBlocking {
        // Whoever observes Ended (the app closing its screen, a test, a new
        // call) must find the camera and microphone already released.
        for (endCall in listOf<suspend (Relay, VerificationCallController) -> Unit>(
            { relay, _ -> relay.operator(CallMessage.Bye("decided:VERIFIED")) },
            { _, call -> call.hangUp() },
        )) {
            val relay = Relay()
            var controller: VerificationCallController? = null
            val statesAtRelease = CopyOnWriteArrayList<CallState>()
            val engine = object : CallMediaEngine by Engine() {
                override fun release() { statesAtRelease += controller!!.state.value }
            }
            val call = VerificationCallController(relay, engine, scope, fast)
            controller = call
            call.start()
            until("offer") { relay.offersSent().isNotEmpty() }
            endCall(relay, call)
            until("ended") { call.isEnded }
            assertEquals("released exactly once, before Ended was published", 1, statesAtRelease.size)
            assertFalse("state at release: ${statesAtRelease.single()}", statesAtRelease.single() is CallState.Ended)
        }
    }

    @Test fun `media connecting while the answer is applied is not overwritten by Connecting`() = runBlocking {
        // A media engine may report CONNECTED from inside applyAnswer; the
        // controller handles that on another thread. The answer handler must
        // not move the state back from Connected to Connecting. Repeated,
        // because the two run concurrently.
        repeat(1000) { round ->
            val relay = Relay()
            val engine = object : CallMediaEngine by Engine() {
                lateinit var ev: MediaEvents
                override suspend fun prepare(iceServers: List<IceServer>, video: Boolean, events: MediaEvents) { ev = events }
                override suspend fun createOffer(iceRestart: Boolean) = "v=0 offer"
                override suspend fun applyAnswer(sdp: String) { ev.onConnectionState(MediaConnectionState.CONNECTED) }
                override fun release() = Unit
            }
            val call = VerificationCallController(relay, engine, scope, fast)
            call.start()
            until("offer") { relay.offersSent().isNotEmpty() }
            relay.operator(CallMessage.Answer("v=0 answer" + DTLS_FINGERPRINT))
            until("answer handled") { call.state.value != CallState.WaitingForOperator }
            delay(30)
            assertEquals("round $round", CallState.Connected, call.state.value)
            call.hangUp()
        }
    }

    @Test fun `byes are mapped to their reasons`() = runBlocking {
        for ((reason, expected) in listOf(
            "decided:FAILED" to CallEndReason.Decided(verified = false),
            "operator_left" to CallEndReason.OperatorLeft,
            "session_expired" to CallEndReason.Expired,
            "credential_revoked" to CallEndReason.Closed("credential_revoked"),
            "authorization_closed" to CallEndReason.Closed("authorization_closed"),
        )) {
            val relay = Relay(); val engine = Engine()
            val call = VerificationCallController(relay, engine, scope, fast)
            call.start()
            until("offer") { relay.offersSent().isNotEmpty() }
            relay.operator(CallMessage.Bye(reason), from = if (reason.startsWith("decided") || reason == "operator_left") "operator" else "server")
            until("ended $reason") { call.isEnded }
            assertEquals(CallState.Ended(expected), call.state.value)
        }
    }

    @Test fun `the session expiry ends the call locally`() = runBlocking {
        val relay = Relay(expiresAt = Instant.now().plusMillis(400)); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        relay.receiveError = NEXUSSignError.NetworkUnavailable(IOException("offline"))
        until("ended") { call.isEnded }
        assertEquals(CallState.Ended(CallEndReason.Expired), call.state.value)
        assertEquals(1, engine.releases)
    }

    @Test fun `an answer without a DTLS fingerprint ends the call (finding D-14)`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        until("offer") { relay.offersSent().isNotEmpty() }
        relay.operator(CallMessage.Answer("v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc"))
        until("ended") { call.isEnded }
        val reason = (call.state.value as CallState.Ended).reason
        assertTrue("failed: $reason", reason is CallEndReason.Failed && (reason.error as SecurityException).message == "the operator's answer has no DTLS fingerprint")
        assertTrue("the answer is not applied", engine.log.none { it.startsWith("answer:") })
        until("cancelled") { relay.cancelled == 1 }
        assertEquals(1, engine.releases)
    }

    @Test fun `DTLS fingerprint check`() {
        fun hash(n: Int) = List(n) { "0f" }.joinToString(":")
        assertTrue(hasDtlsFingerprint("v=0\r\na=fingerprint:sha-256 ${hash(32)}\r\n"))
        assertTrue(hasDtlsFingerprint("v=0\na=fingerprint:SHA-384 ${hash(48)}"))
        assertTrue(hasDtlsFingerprint("a=fingerprint:sha-512 ${hash(64)}"))
        assertFalse(hasDtlsFingerprint("v=0\r\n"))
        assertFalse(hasDtlsFingerprint("a=fingerprint:sha-256 ${hash(31)}"))
        assertFalse(hasDtlsFingerprint("a=fingerprint:sha-1 ${hash(20)}"))
        assertFalse(hasDtlsFingerprint("a=fingerprint:sha-256 ${hash(31)}:zz"))
        assertFalse(hasDtlsFingerprint("a=fingerprint:sha-256"))
    }

    @Test fun `hanging up cancels the session once and releases media`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        until("offer") { relay.offersSent().isNotEmpty() }
        call.hangUp()
        call.hangUp()
        assertEquals(CallState.Ended(CallEndReason.CancelledByCustomer), call.state.value)
        assertEquals(1, relay.cancelled)
        assertEquals(1, engine.releases)
        call.setCameraEnabled(true)
        assertTrue("no media calls after the end", engine.log.none { it.startsWith("camera") })
    }

    @Test fun `a short network outage while polling does not end the call`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        relay.failReceives = 3
        call.start()
        until("offer") { relay.offersSent().isNotEmpty() }
        relay.operator(CallMessage.Answer("v=0 a1" + DTLS_FINGERPRINT))
        until("answer after the outage") { engine.log.contains("answer:v=0 a1") }
        assertTrue(!call.isEnded)
    }

    @Test fun `a lost response is retried with the same messageId and relayed once`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        relay.failSendsWith503 = 1
        VerificationCallController(relay, engine, scope, fast).start()
        until("offer") { relay.offersSent().isNotEmpty() }
        delay(200)
        assertEquals(1, relay.offersSent().size)
    }

    @Test fun `a session closed on the server ends the call`() = runBlocking {
        val relay = Relay(); val engine = Engine()
        val call = VerificationCallController(relay, engine, scope, fast)
        call.start()
        until("offer") { relay.offersSent().isNotEmpty() }
        relay.receiveError = NEXUSSignError.ServerError(409, "Verification session is CANCELLED")
        until("ended") { call.isEnded }
        assertEquals(CallState.Ended(CallEndReason.Closed("Verification session is CANCELLED")), call.state.value)
    }

    @Test fun `wire format matches Auth Core's call routes`() {
        val offer = CallWire.encode(CallMessage.Offer("v=0"), "11111111-1111-4111-8111-111111111111").toString()
        assertEquals("""{"type":"offer","payload":{"sdp":"v=0"},"messageId":"11111111-1111-4111-8111-111111111111"}""", offer)
        val cand = CallWire.encode(CallMessage.Candidate(IceCandidateInit("candidate:1", "0", 0)), "m").toString()
        assertEquals("""{"type":"candidate","payload":{"candidate":"candidate:1","sdpMid":"0","sdpMLineIndex":0},"messageId":"m"}""", cand)
        val body = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"signals":[{"seq":3,"from":"operator","type":"answer","payload":{"sdp":"v=0 a"},"at":"x"},
               {"seq":4,"from":"operator","type":"candidate","payload":{"candidate":"candidate:2","sdpMid":"0","sdpMLineIndex":1}},
               {"seq":5,"from":"server","type":"bye","payload":{"reason":"session_expired"}},
               {"seq":6,"from":"operator","type":"future-type","payload":{}}],"next":6}""") as kotlinx.serialization.json.JsonObject
        val batch = CallWire.decodeBatch(body, 2)
        assertEquals(6L, batch.next)
        assertEquals(listOf(
            ReceivedSignal(3, "operator", CallMessage.Answer("v=0 a")),
            ReceivedSignal(4, "operator", CallMessage.Candidate(IceCandidateInit("candidate:2", "0", 1))),
            ReceivedSignal(5, "server", CallMessage.Bye("session_expired")),
            ReceivedSignal(6, "operator", null),
        ), batch.signals)
        val join = CallWire.decodeJoin(kotlinx.serialization.json.Json.parseToJsonElement(
            """{"sessionId":"s","channel":"AUDIO","expiresAt":"2026-10-18T10:00:00.000Z","operatorJoined":false,
                "iceServers":[{"urls":["stun:a:3478"]},{"urls":["turn:a:3478?transport=udp"],"username":"1:s","credential":"c"}]}""") as kotlinx.serialization.json.JsonObject)
        assertEquals(VerificationChannel.AUDIO, join.channel)
        assertEquals(listOf(IceServer(listOf("stun:a:3478")), IceServer(listOf("turn:a:3478?transport=udp"), "1:s", "c")), join.iceServers)
    }
}
