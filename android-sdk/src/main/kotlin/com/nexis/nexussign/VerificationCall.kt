package com.nexis.nexussign

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Instant
import java.util.UUID

// In-app audio and video verification calls (ADR 0017).
//
// This file holds everything that does not need a WebRTC library: the
// session and signalling models, the signalling transport interface (the SDK
// implements it with device-signed requests to Auth Core) and the call state
// machine. Media is done by a CallMediaEngine; the WebRTC implementation is
// in the optional module nexus-sign-android-calls, so a bank app that does
// not use calls does not carry a WebRTC binary.
//
// A call never authorizes a transaction. The operator's decision is recorded
// by Auth Core; the customer still confirms by signing the transaction bytes
// with approve().

/** Verification channels that are calls. */
enum class VerificationChannel { AUDIO, VIDEO }

data class IceServer(val urls: List<String>, val username: String? = null, val credential: String? = null) {
    companion object {
        /**
         * For a relay-only call (finding D-14): the TURN URLs only (`turn:` or
         * `turns:`), so neither the customer's local nor public address reaches
         * the operator side. Throws when Auth Core supplied no TURN server: the
         * call is refused rather than made with direct candidates.
         */
        fun relayOnly(servers: List<IceServer>): List<IceServer> {
            val relays = servers.mapNotNull { server ->
                val urls = server.urls.filter { it.lowercase().startsWith("turn:") || it.lowercase().startsWith("turns:") }
                if (urls.isEmpty()) null else server.copy(urls = urls)
            }
            if (relays.isEmpty()) throw NEXUSSignError.InvalidArgument("relay-only call without a TURN server")
            return relays
        }
    }
}

/** An open verification session of one authorization, as returned by Auth Core. */
data class VerificationSession(val sessionId: String, val authorizationId: String, val channel: VerificationChannel, val expiresAt: Instant)

/** What the device needs to place the call: the bank's STUN/TURN servers
 * with TURN credentials valid for this session only. */
data class VerificationCallInfo(
    val sessionId: String,
    val channel: VerificationChannel,
    val expiresAt: Instant,
    val iceServers: List<IceServer>,
    val operatorJoined: Boolean,
)

data class IceCandidateInit(val candidate: String, val sdpMid: String?, val sdpMLineIndex: Int?)

/** One signalling message (the payloads of Auth Core's /signals). */
sealed class CallMessage {
    data class Offer(val sdp: String) : CallMessage()
    data class Answer(val sdp: String) : CallMessage()
    data class Candidate(val candidate: IceCandidateInit) : CallMessage()
    data class Bye(val reason: String) : CallMessage()
}

/** A message from the other party (`operator`) or from Auth Core (`server`).
 * [message] is null for a type this SDK version does not know. */
data class ReceivedSignal(val seq: Long, val from: String, val message: CallMessage?)

data class SignalBatch(val signals: List<ReceivedSignal>, val next: Long)

/** Signalling transport of one session. Implemented by the SDK
 * ([NEXUSSignSDK.callSignalling]); errors are [NEXUSSignError]. */
interface CallSignalling {
    val sessionId: String
    suspend fun join(): VerificationCallInfo
    /** Sends one message; a retry with the same [messageId] is accepted once. */
    suspend fun send(message: CallMessage, messageId: String)
    /** Messages with seq > [after], waiting up to [waitMillis] for the first. */
    suspend fun receive(after: Long, waitMillis: Long): SignalBatch
    /** Ends or declines the call: nothing is verified or failed. */
    suspend fun cancel()
}

enum class MediaConnectionState { NEW, CONNECTING, CONNECTED, DISCONNECTED, FAILED, CLOSED }

/** Callbacks of a media engine; may arrive on any thread. */
interface MediaEvents {
    fun onLocalCandidate(candidate: IceCandidateInit)
    fun onConnectionState(state: MediaConnectionState)
    /** What is actually capturing right now, for the on-screen indicators. */
    fun onCaptureState(cameraOn: Boolean, microphoneOn: Boolean)
}

/**
 * The media side of a call: one peer connection with the local microphone
 * (and camera for VIDEO). The device always makes the offer.
 */
interface CallMediaEngine {
    /** Creates the peer connection and starts capture. */
    suspend fun prepare(iceServers: List<IceServer>, video: Boolean, events: MediaEvents)
    /** Creates an offer, sets it as the local description and returns its SDP. */
    suspend fun createOffer(iceRestart: Boolean): String
    suspend fun applyAnswer(sdp: String)
    suspend fun addRemoteCandidate(candidate: IceCandidateInit)
    fun setMicrophoneEnabled(enabled: Boolean)
    fun setCameraEnabled(enabled: Boolean)
    /** Stops capture and closes the connection. Called exactly once. */
    fun release()
}

/** Why a call ended. */
sealed class CallEndReason {
    /** The operator recorded a result. VERIFIED still needs approve(). */
    data class Decided(val verified: Boolean) : CallEndReason()
    object CancelledByCustomer : CallEndReason()
    /** The operator hung up without a result; the customer may call again. */
    object OperatorLeft : CallEndReason()
    /** Nobody answered in time, or the session ran out. */
    object Expired : CallEndReason()
    /** The connection could not be restored. */
    object ConnectionLost : CallEndReason()
    /** Closed by Auth Core: authorization confirmed elsewhere, rejected,
     * credential revoked, session superseded. */
    data class Closed(val reason: String) : CallEndReason()
    data class Failed(val error: Throwable) : CallEndReason()
}

sealed class CallState {
    object Idle : CallState()
    object Joining : CallState()
    /** Offer sent; waiting for an operator to answer. */
    object WaitingForOperator : CallState()
    object Connecting : CallState()
    object Connected : CallState()
    data class Reconnecting(val attempt: Int) : CallState()
    data class Ended(val reason: CallEndReason) : CallState()
}

data class CaptureState(val cameraOn: Boolean, val microphoneOn: Boolean)

/**
 * The device side of one call. Runs signalling against Auth Core and drives
 * the media engine:
 *
 *  - offer first, then candidates: local candidates wait until their offer
 *    is sent, remote ones until the answer is applied;
 *  - duplicate and stale messages (seq not above the last one seen) and
 *    answers without an outstanding offer are ignored;
 *  - a dropped connection is restored with an ICE restart (a new offer),
 *    at most [Options.maxIceRestarts] times, then the call ends;
 *  - a bye from the operator or Auth Core ends the call with its reason;
 *  - the session's expiry ends the call locally even without network;
 *  - the media engine is released exactly once, whatever ends the call.
 */
class VerificationCallController(
    private val signalling: CallSignalling,
    private val engine: CallMediaEngine,
    private val scope: CoroutineScope,
    private val options: Options = Options(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    data class Options(
        /** Long-poll wait; keep it below the network client's call timeout. */
        val pollWaitMillis: Long = 8_000,
        /** How long a DISCONNECTED connection may recover by itself. */
        val reconnectGraceMillis: Long = 4_000,
        val maxIceRestarts: Int = 2,
        val sendAttempts: Int = 3,
        val retryBackoffMillis: Long = 1_000,
        val maxRetryBackoffMillis: Long = 5_000,
    )

    private val _state = MutableStateFlow<CallState>(CallState.Idle)
    val state: StateFlow<CallState> = _state.asStateFlow()
    private val _capture = MutableStateFlow(CaptureState(cameraOn = false, microphoneOn = false))
    /** Camera and microphone activity, for indicators that must stay visible. */
    val capture: StateFlow<CaptureState> = _capture.asStateFlow()
    private val _callCode = MutableStateFlow<String?>(null)
    /**
     * The call code to compare with the one the operator reads out (finding
     * A2-11, [CallCode]); set when the operator's answer arrives, before the
     * state changes.
     */
    val callCode: StateFlow<String?> = _callCode.asStateFlow()
    private var lastOffer: String? = null

    private val lock = Mutex()
    private var info: VerificationCallInfo? = null
    private var lastSeq = 0L
    private var offerSent = false
    private var awaitingAnswer = false
    private var remoteDescription = false
    private val pendingLocal = mutableListOf<IceCandidateInit>()
    private val pendingRemote = mutableListOf<IceCandidateInit>()
    private var restarts = 0
    private var mediaConnected = false
    private var reconnectJob: Job? = null
    private var pollJob: Job? = null
    private var expiryJob: Job? = null
    @Volatile private var released = false
    /** Set once when the call starts ending; Ended is published after cleanup. */
    @Volatile private var ending = false

    /** Number of messages ignored as duplicates or out of order (diagnostics). */
    @Volatile var ignoredMessages = 0
        private set

    val isEnded: Boolean get() = _state.value is CallState.Ended

    /** Joins the session, starts capture and sends the offer. */
    fun start(): Job = scope.launch {
        if (_state.value != CallState.Idle) return@launch
        _state.value = CallState.Joining
        try {
            val joined = signalling.join()
            info = joined
            expiryJob = scope.launch {
                delay((joined.expiresAt.toEpochMilli() - clock()).coerceAtLeast(0))
                end(CallEndReason.Expired)
            }
            engine.prepare(joined.iceServers, joined.channel == VerificationChannel.VIDEO, events)
            lock.withLock { if (!ending) sendOffer(iceRestart = false) }
            if (!ending) {
                _state.value = CallState.WaitingForOperator
                pollJob = scope.launch { pollLoop() }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            end(closedOrFailed(e))
        }
    }

    /** The customer ends or declines the call. */
    suspend fun hangUp() {
        if (ending) return
        end(CallEndReason.CancelledByCustomer)
        try {
            signalling.cancel()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            // Already closed on the server, or no network: the session
            // expires on its own and verifies nothing.
        }
    }

    fun setMicrophoneEnabled(enabled: Boolean) { if (!ending) engine.setMicrophoneEnabled(enabled) }
    fun setCameraEnabled(enabled: Boolean) { if (!ending) engine.setCameraEnabled(enabled) }

    private val events = object : MediaEvents {
        override fun onLocalCandidate(candidate: IceCandidateInit) {
            scope.launch {
                lock.withLock {
                    if (ending) return@withLock
                    if (offerSent) sendReliably(CallMessage.Candidate(candidate)) else pendingLocal += candidate
                }
            }
        }

        override fun onConnectionState(state: MediaConnectionState) {
            scope.launch { onMediaState(state) }
        }

        override fun onCaptureState(cameraOn: Boolean, microphoneOn: Boolean) {
            _capture.value = if (released) CaptureState(false, false) else CaptureState(cameraOn, microphoneOn)
        }
    }

    /** Caller holds [lock]. */
    private suspend fun sendOffer(iceRestart: Boolean) {
        offerSent = false
        remoteDescription = false
        val sdp = engine.createOffer(iceRestart)
        lastOffer = sdp
        sendReliably(CallMessage.Offer(sdp))
        offerSent = true
        awaitingAnswer = true
        for (candidate in pendingLocal.toList()) sendReliably(CallMessage.Candidate(candidate))
        pendingLocal.clear()
    }

    /** Sends with one messageId, retrying only failures that may not have
     * reached Auth Core. A refusal (4xx) is final. */
    private suspend fun sendReliably(message: CallMessage) {
        val messageId = UUID.randomUUID().toString()
        var backoff = options.retryBackoffMillis
        for (attempt in 1..options.sendAttempts) {
            try {
                signalling.send(message, messageId)
                return
            } catch (e: NEXUSSignError.NetworkUnavailable) {
                if (attempt == options.sendAttempts) throw e
            } catch (e: NEXUSSignError.ServerError) {
                if (e.statusCode < 500 || attempt == options.sendAttempts) throw e
            }
            delay(backoff)
            backoff = (backoff * 2).coerceAtMost(options.maxRetryBackoffMillis)
        }
    }

    private suspend fun pollLoop() {
        var backoff = options.retryBackoffMillis
        while (!ending) {
            val batch = try {
                signalling.receive(lastSeq, options.pollWaitMillis).also { backoff = options.retryBackoffMillis }
            } catch (e: CancellationException) {
                throw e
            } catch (e: NEXUSSignError.NetworkUnavailable) {
                // Offline for a moment: keep the call, try again. The session
                // expiry ends it if the network does not come back.
                delay(backoff)
                backoff = (backoff * 2).coerceAtMost(options.maxRetryBackoffMillis)
                continue
            } catch (e: Throwable) {
                if (e is NEXUSSignError.ServerError && e.statusCode >= 500) {
                    delay(backoff)
                    backoff = (backoff * 2).coerceAtMost(options.maxRetryBackoffMillis)
                    continue
                }
                end(closedOrFailed(e))
                return
            }
            try {
                lock.withLock { for (signal in batch.signals) handle(signal) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                end(closedOrFailed(e))
                return
            }
        }
    }

    /** Caller holds [lock]. */
    private suspend fun handle(signal: ReceivedSignal) {
        if (ending) return
        if (signal.seq <= lastSeq) { ignoredMessages++; return }
        lastSeq = signal.seq
        when (val message = signal.message) {
            is CallMessage.Answer -> {
                if (!awaitingAnswer || signal.from != "operator") { ignoredMessages++; return }
                // Media without a DTLS fingerprint would not be DTLS-SRTP
                // (finding D-14): the call ends instead of connecting.
                if (!hasDtlsFingerprint(message.sdp)) {
                    end(CallEndReason.Failed(SecurityException("the operator's answer has no DTLS fingerprint")))
                    runCatching { signalling.cancel() }
                    return
                }
                engine.applyAnswer(message.sdp)
                lastOffer?.let { offer -> _callCode.value = CallCode.code(offer, message.sdp) }
                awaitingAnswer = false
                remoteDescription = true
                for (candidate in pendingRemote.toList()) engine.addRemoteCandidate(candidate)
                pendingRemote.clear()
                // Atomic: a CONNECTED event handled meanwhile on another thread
                // must not be overwritten.
                _state.compareAndSet(CallState.WaitingForOperator, CallState.Connecting)
            }
            is CallMessage.Candidate -> {
                if (signal.from != "operator") { ignoredMessages++; return }
                if (remoteDescription) engine.addRemoteCandidate(message.candidate) else pendingRemote += message.candidate
            }
            is CallMessage.Bye -> end(byeReason(message.reason))
            is CallMessage.Offer, null -> ignoredMessages++ // the device always offers; unknown types are skipped
        }
    }

    private suspend fun onMediaState(state: MediaConnectionState) {
        if (ending) return
        when (state) {
            MediaConnectionState.CONNECTED -> {
                mediaConnected = true
                reconnectJob?.cancel()
                reconnectJob = null
                _state.value = CallState.Connected
            }
            MediaConnectionState.DISCONNECTED -> {
                if (!mediaConnected || reconnectJob != null) return
                _state.value = CallState.Reconnecting(restarts + 1)
                reconnectJob = scope.launch {
                    delay(options.reconnectGraceMillis)
                    reconnectJob = null
                    if (_state.value !is CallState.Connected) restartIce()
                }
            }
            MediaConnectionState.FAILED -> {
                reconnectJob?.cancel()
                reconnectJob = null
                if (mediaConnected || remoteDescription) restartIce() else end(CallEndReason.ConnectionLost)
            }
            MediaConnectionState.CLOSED -> if (!released) end(CallEndReason.ConnectionLost)
            MediaConnectionState.NEW, MediaConnectionState.CONNECTING -> Unit
        }
    }

    private suspend fun restartIce() {
        val giveUp = lock.withLock {
            if (ending || awaitingAnswer) return
            if (restarts >= options.maxIceRestarts) return@withLock true
            restarts++
            _state.value = CallState.Reconnecting(restarts)
            try {
                sendOffer(iceRestart = true)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                end(closedOrFailed(e))
            }
            false
        }
        if (giveUp) {
            end(CallEndReason.ConnectionLost)
            // Close the session so the customer can call again at once.
            runCatching { signalling.cancel() }
        }
    }

    private fun byeReason(reason: String): CallEndReason = when {
        reason == "decided:VERIFIED" || reason == "session_verified" -> CallEndReason.Decided(verified = true)
        reason == "decided:FAILED" || reason == "session_failed" -> CallEndReason.Decided(verified = false)
        reason == "operator_left" -> CallEndReason.OperatorLeft
        reason == "session_expired" -> CallEndReason.Expired
        reason == "cancelled" || reason == "session_cancelled" -> CallEndReason.CancelledByCustomer
        else -> CallEndReason.Closed(reason)
    }

    private fun closedOrFailed(e: Throwable): CallEndReason = when {
        e is NEXUSSignError.ServerError && e.statusCode == 410 -> CallEndReason.Expired
        e is NEXUSSignError.ServerError && (e.statusCode == 409 || e.statusCode == 404) -> CallEndReason.Closed(e.serverMessage ?: "closed")
        else -> CallEndReason.Failed(e)
    }

    /**
     * Ends the call once: timers, polling and the media engine, and only then
     * the state. Whoever observes [CallState.Ended] finds the media released.
     */
    private fun end(reason: CallEndReason) {
        synchronized(this) {
            if (ending) return
            ending = true
        }
        reconnectJob?.cancel()
        expiryJob?.cancel()
        pollJob?.cancel()
        if (!released) {
            released = true
            runCatching { engine.release() }
        }
        _capture.value = CaptureState(cameraOn = false, microphoneOn = false)
        _state.value = CallState.Ended(reason)
    }
}

/**
 * True when the SDP carries an `a=fingerprint` line with a SHA-256, SHA-384
 * or SHA-512 certificate hash of the right length (RFC 8122), which DTLS-SRTP
 * needs (finding D-14).
 */
internal fun hasDtlsFingerprint(sdp: String): Boolean {
    val lengths = mapOf("sha-256" to 32, "sha-384" to 48, "sha-512" to 64)
    return sdp.split('\n', '\r').map { it.trim() }.any { line ->
        if (!line.startsWith("a=fingerprint:", ignoreCase = true)) return@any false
        val parts = line.substring("a=fingerprint:".length).trim().split(' ').filter { it.isNotEmpty() }
        val expected = parts.takeIf { it.size == 2 }?.let { lengths[it[0].lowercase()] } ?: return@any false
        val bytes = parts[1].split(':')
        bytes.size == expected && bytes.all { b -> b.length == 2 && b.all { it in '0'..'9' || it.lowercaseChar() in 'a'..'f' } }
    }
}

/**
 * The call code (finding A2-11): six digits from the DTLS certificate
 * fingerprints of the phone's offer and the operator's answer. The operator
 * console shows the same code and the operator reads it out; if anyone in the
 * signalling path substituted a fingerprint to sit in the middle of the
 * media, the codes differ. Vectors: auth-core/test-vectors/call-code-v1.json.
 */
object CallCode {
    /** "<hash> <HEX>" from the first `a=fingerprint` line, or null. */
    fun fingerprint(sdp: String): String? {
        for (raw in sdp.split("\r\n", "\n", "\r")) {
            val line = raw.trim()
            if (!line.startsWith("a=fingerprint:", ignoreCase = true)) continue
            val parts = line.substring("a=fingerprint:".length).trim().split(' ').filter { it.isNotEmpty() }
            if (parts.size != 2 || parts[1].isEmpty() || !parts[1].all { it == ':' || it in '0'..'9' || it.lowercaseChar() in 'a'..'f' }) continue
            return "${parts[0].lowercase()} ${parts[1].uppercase()}"
        }
        return null
    }

    /** The six-digit code, or null when either description has no fingerprint. */
    fun code(offer: String, answer: String): String? {
        val offerPrint = fingerprint(offer) ?: return null
        val answerPrint = fingerprint(answer) ?: return null
        val digest = java.security.MessageDigest.getInstance("SHA-256").run {
            update("NEXUS-SIGN/CALL-CODE/v1".toByteArray(Charsets.UTF_8)); update(0.toByte())
            update(offerPrint.toByteArray(Charsets.UTF_8)); update(0.toByte())
            update(answerPrint.toByteArray(Charsets.UTF_8))
            digest()
        }
        val value = ((digest[0].toLong() and 0xff) shl 24) or ((digest[1].toLong() and 0xff) shl 16) or
            ((digest[2].toLong() and 0xff) shl 8) or (digest[3].toLong() and 0xff)
        return (value % 1_000_000).toString().padStart(6, '0')
    }
}
