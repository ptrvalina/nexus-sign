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

data class IceServer(val urls: List<String>, val username: String? = null, val credential: String? = null)

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
            lock.withLock { if (!isEnded) sendOffer(iceRestart = false) }
            if (!isEnded) {
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
        if (isEnded) return
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

    fun setMicrophoneEnabled(enabled: Boolean) { if (!isEnded) engine.setMicrophoneEnabled(enabled) }
    fun setCameraEnabled(enabled: Boolean) { if (!isEnded) engine.setCameraEnabled(enabled) }

    private val events = object : MediaEvents {
        override fun onLocalCandidate(candidate: IceCandidateInit) {
            scope.launch {
                lock.withLock {
                    if (isEnded) return@withLock
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
        while (!isEnded) {
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
        if (isEnded) return
        if (signal.seq <= lastSeq) { ignoredMessages++; return }
        lastSeq = signal.seq
        when (val message = signal.message) {
            is CallMessage.Answer -> {
                if (!awaitingAnswer || signal.from != "operator") { ignoredMessages++; return }
                engine.applyAnswer(message.sdp)
                awaitingAnswer = false
                remoteDescription = true
                for (candidate in pendingRemote.toList()) engine.addRemoteCandidate(candidate)
                pendingRemote.clear()
                if (_state.value == CallState.WaitingForOperator) _state.value = CallState.Connecting
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
        if (isEnded) return
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
            if (isEnded || awaitingAnswer) return
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

    /** Ends the call once: state, timers, polling and the media engine. */
    private fun end(reason: CallEndReason) {
        synchronized(this) {
            if (_state.value is CallState.Ended) return
            _state.value = CallState.Ended(reason)
        }
        reconnectJob?.cancel()
        expiryJob?.cancel()
        pollJob?.cancel()
        if (!released) {
            released = true
            runCatching { engine.release() }
        }
        _capture.value = CaptureState(cameraOn = false, microphoneOn = false)
    }
}
