package com.nexis.nexussign.calls

import android.content.Context
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.os.Build
import com.nexis.nexussign.CallMediaEngine
import com.nexis.nexussign.IceCandidateInit
import com.nexis.nexussign.IceServer
import com.nexis.nexussign.MediaConnectionState
import com.nexis.nexussign.MediaEvents
import kotlinx.coroutines.suspendCancellableCoroutine
import org.webrtc.AudioSource
import org.webrtc.AudioTrack
import org.webrtc.Camera2Enumerator
import org.webrtc.CameraVideoCapturer
import org.webrtc.DataChannel
import org.webrtc.DefaultVideoDecoderFactory
import org.webrtc.DefaultVideoEncoderFactory
import org.webrtc.EglBase
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpTransceiver
import org.webrtc.VideoCodecInfo
import org.webrtc.VideoDecoder
import org.webrtc.VideoDecoderFactory
import org.webrtc.VideoEncoder
import org.webrtc.VideoEncoderFactory
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import org.webrtc.SurfaceTextureHelper
import org.webrtc.VideoSink
import org.webrtc.VideoSource
import org.webrtc.VideoTrack
import org.webrtc.audio.JavaAudioDeviceModule
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * [CallMediaEngine] on libwebrtc (org.webrtc). One peer connection, the
 * microphone, and for VIDEO the front camera. Media is encrypted by
 * DTLS-SRTP as negotiated by libwebrtc; nothing is recorded.
 *
 * Renderers: attach [localSink] and [remoteSink] (for example the
 * SurfaceViewRenderers of [VerificationCallView]); they may be attached
 * before or after the call starts.
 *
 * Video codecs are limited to VP8 and VP9 (no H.264/H.265), see
 * docs/engineering/THIRD_PARTY_MEDIA.md.
 */
class WebRtcCallEngine(context: Context, val eglBase: EglBase = EglBase.create()) : CallMediaEngine {
    private val appContext = context.applicationContext
    private val audioManager = appContext.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    private var factory: PeerConnectionFactory? = null
    private var peer: PeerConnection? = null
    private var audioSource: AudioSource? = null
    private var audioTrack: AudioTrack? = null
    private var videoSource: VideoSource? = null
    private var videoTrack: VideoTrack? = null
    private var capturer: CameraVideoCapturer? = null
    private var textureHelper: SurfaceTextureHelper? = null
    private var events: MediaEvents? = null
    private var cameraOn = false
    private var microphoneOn = false
    private var previousAudioMode = AudioManager.MODE_NORMAL
    @Volatile private var released = false

    var localSink: VideoSink? = null
        set(value) { field?.let { videoTrack?.removeSink(it) }; field = value; value?.let { videoTrack?.addSink(it) } }
    var remoteSink: VideoSink? = null
        set(value) { field?.let { remoteTrack?.removeSink(it) }; field = value; value?.let { remoteTrack?.addSink(it) } }
    private var remoteTrack: VideoTrack? = null

    override suspend fun prepare(iceServers: List<IceServer>, video: Boolean, events: MediaEvents) {
        this.events = events
        ensureInitialized(appContext)
        val audioDevice = JavaAudioDeviceModule.builder(appContext)
            .setUseHardwareAcousticEchoCanceler(true)
            .setUseHardwareNoiseSuppressor(true)
            .createAudioDeviceModule()
        val f = PeerConnectionFactory.builder()
            .setAudioDeviceModule(audioDevice)
            .setVideoEncoderFactory(RoyaltyFreeEncoderFactory(DefaultVideoEncoderFactory(eglBase.eglBaseContext, true, false)))
            .setVideoDecoderFactory(RoyaltyFreeDecoderFactory(DefaultVideoDecoderFactory(eglBase.eglBaseContext)))
            .createPeerConnectionFactory()
        audioDevice.release() // the factory holds its own reference
        factory = f

        val configuration = PeerConnection.RTCConfiguration(iceServers.map { server ->
            PeerConnection.IceServer.builder(server.urls)
                .apply {
                    server.username?.let { setUsername(it) }
                    server.credential?.let { setPassword(it) }
                }
                .createIceServer()
        }).apply {
            sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
            continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            bundlePolicy = PeerConnection.BundlePolicy.MAXBUNDLE
            rtcpMuxPolicy = PeerConnection.RtcpMuxPolicy.REQUIRE
        }
        val pc = f.createPeerConnection(configuration, observer) ?: error("libwebrtc could not create a peer connection")
        peer = pc

        startAudioRouting(speaker = video)
        val microphone = f.createAudioSource(MediaConstraints())
        audioSource = microphone
        audioTrack = f.createAudioTrack("nexus-microphone", microphone).also { pc.addTrack(it, listOf(STREAM_ID)) }
        microphoneOn = true

        if (video) {
            val enumerator = Camera2Enumerator(appContext)
            val name = enumerator.deviceNames.firstOrNull(enumerator::isFrontFacing) ?: enumerator.deviceNames.firstOrNull()
                ?: error("no camera")
            val source = f.createVideoSource(false)
            val helper = SurfaceTextureHelper.create("nexus-camera", eglBase.eglBaseContext)
            val camera = enumerator.createCapturer(name, null)
            camera.initialize(helper, appContext, source.capturerObserver)
            camera.startCapture(CAPTURE_WIDTH, CAPTURE_HEIGHT, CAPTURE_FPS)
            videoSource = source; textureHelper = helper; capturer = camera
            videoTrack = f.createVideoTrack("nexus-camera", source).also { track ->
                pc.addTrack(track, listOf(STREAM_ID))
                localSink?.let(track::addSink)
            }
            cameraOn = true
        }
        reportCapture()
    }

    override suspend fun createOffer(iceRestart: Boolean): String {
        val pc = peer ?: error("not prepared")
        if (iceRestart) pc.restartIce()
        val offer = suspendCancellableCoroutine<SessionDescription> { continuation ->
            pc.createOffer(object : SdpObserverAdapter() {
                override fun onCreateSuccess(description: SessionDescription) = continuation.resume(description)
                override fun onCreateFailure(error: String?) = continuation.resumeWithException(IllegalStateException("createOffer: $error"))
            }, MediaConstraints())
        }
        setDescription(local = true, offer)
        return offer.description
    }

    override suspend fun applyAnswer(sdp: String) = setDescription(local = false, SessionDescription(SessionDescription.Type.ANSWER, sdp))

    override suspend fun addRemoteCandidate(candidate: IceCandidateInit) {
        peer?.addIceCandidate(IceCandidate(candidate.sdpMid ?: "0", candidate.sdpMLineIndex ?: 0, candidate.candidate))
    }

    override fun setMicrophoneEnabled(enabled: Boolean) {
        audioTrack?.setEnabled(enabled)
        microphoneOn = enabled && audioTrack != null
        reportCapture()
    }

    /** Stops the camera itself (not only the track), so the system camera
     * indicator and ours both go off. */
    override fun setCameraEnabled(enabled: Boolean) {
        val camera = capturer ?: return
        if (enabled == cameraOn) return
        if (enabled) camera.startCapture(CAPTURE_WIDTH, CAPTURE_HEIGHT, CAPTURE_FPS) else runCatching { camera.stopCapture() }
        videoTrack?.setEnabled(enabled)
        cameraOn = enabled
        reportCapture()
    }

    override fun release() {
        if (released) return
        released = true
        runCatching { capturer?.stopCapture() }
        capturer?.dispose()
        localSink?.let { videoTrack?.removeSink(it) }
        remoteSink?.let { remoteTrack?.removeSink(it) }
        peer?.close()
        peer?.dispose()
        videoSource?.dispose()
        audioSource?.dispose()
        textureHelper?.dispose()
        factory?.dispose()
        capturer = null; peer = null; videoSource = null; audioSource = null; textureHelper = null; factory = null
        videoTrack = null; audioTrack = null; remoteTrack = null
        cameraOn = false; microphoneOn = false
        stopAudioRouting()
        reportCapture()
    }

    private suspend fun setDescription(local: Boolean, description: SessionDescription) {
        val pc = peer ?: error("not prepared")
        suspendCancellableCoroutine<Unit> { continuation ->
            val observer = object : SdpObserverAdapter() {
                override fun onSetSuccess() = continuation.resume(Unit)
                override fun onSetFailure(error: String?) = continuation.resumeWithException(IllegalStateException("setDescription: $error"))
            }
            if (local) pc.setLocalDescription(observer, description) else pc.setRemoteDescription(observer, description)
        }
    }

    private fun reportCapture() = events?.onCaptureState(cameraOn = cameraOn && !released, microphoneOn = microphoneOn && !released)

    @Suppress("DEPRECATION") // isSpeakerphoneOn below API 31
    private fun startAudioRouting(speaker: Boolean) {
        previousAudioMode = audioManager.mode
        audioManager.mode = AudioManager.MODE_IN_COMMUNICATION
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val type = if (speaker) AudioDeviceInfo.TYPE_BUILTIN_SPEAKER else AudioDeviceInfo.TYPE_BUILTIN_EARPIECE
            audioManager.availableCommunicationDevices.firstOrNull { it.type == type }?.let(audioManager::setCommunicationDevice)
        } else {
            audioManager.isSpeakerphoneOn = speaker
        }
    }

    @Suppress("DEPRECATION")
    private fun stopAudioRouting() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            audioManager.clearCommunicationDevice()
        } else {
            audioManager.isSpeakerphoneOn = false
        }
        audioManager.mode = previousAudioMode
    }

    private val observer = object : PeerConnection.Observer {
        override fun onIceCandidate(candidate: IceCandidate) {
            events?.onLocalCandidate(IceCandidateInit(candidate.sdp, candidate.sdpMid, candidate.sdpMLineIndex))
        }
        override fun onConnectionChange(newState: PeerConnection.PeerConnectionState) {
            events?.onConnectionState(when (newState) {
                PeerConnection.PeerConnectionState.NEW -> MediaConnectionState.NEW
                PeerConnection.PeerConnectionState.CONNECTING -> MediaConnectionState.CONNECTING
                PeerConnection.PeerConnectionState.CONNECTED -> MediaConnectionState.CONNECTED
                PeerConnection.PeerConnectionState.DISCONNECTED -> MediaConnectionState.DISCONNECTED
                PeerConnection.PeerConnectionState.FAILED -> MediaConnectionState.FAILED
                PeerConnection.PeerConnectionState.CLOSED -> MediaConnectionState.CLOSED
            })
        }
        override fun onTrack(transceiver: RtpTransceiver) {
            val track = transceiver.receiver.track() as? VideoTrack ?: return
            remoteTrack = track
            remoteSink?.let(track::addSink)
        }
        override fun onSignalingChange(state: PeerConnection.SignalingState) = Unit
        override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) = Unit
        override fun onIceConnectionReceivingChange(receiving: Boolean) = Unit
        override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) = Unit
        override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) = Unit
        override fun onAddStream(stream: MediaStream) = Unit
        override fun onRemoveStream(stream: MediaStream) = Unit
        override fun onDataChannel(channel: DataChannel) = Unit
        override fun onRenegotiationNeeded() = Unit
    }

    /** Only VP8 and VP9 are offered and accepted: H.264/H.265 patent
     * licensing is not covered by the libwebrtc licence
     * (docs/engineering/THIRD_PARTY_MEDIA.md). */
    private class RoyaltyFreeEncoderFactory(private val inner: VideoEncoderFactory) : VideoEncoderFactory {
        override fun createEncoder(info: VideoCodecInfo): VideoEncoder? = if (allowedVideoCodec(info.name)) inner.createEncoder(info) else null
        override fun getSupportedCodecs(): Array<VideoCodecInfo> = inner.getSupportedCodecs().filter { allowedVideoCodec(it.name) }.toTypedArray()
    }

    private class RoyaltyFreeDecoderFactory(private val inner: VideoDecoderFactory) : VideoDecoderFactory {
        override fun createDecoder(info: VideoCodecInfo): VideoDecoder? = if (allowedVideoCodec(info.name)) inner.createDecoder(info) else null
        override fun getSupportedCodecs(): Array<VideoCodecInfo> = inner.getSupportedCodecs().filter { allowedVideoCodec(it.name) }.toTypedArray()
    }

    private open class SdpObserverAdapter : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription) = Unit
        override fun onSetSuccess() = Unit
        override fun onCreateFailure(error: String?) = Unit
        override fun onSetFailure(error: String?) = Unit
    }

    private companion object {
        fun allowedVideoCodec(name: String) = name.equals("VP8", ignoreCase = true) || name.equals("VP9", ignoreCase = true)
        const val STREAM_ID = "nexus-call"
        const val CAPTURE_WIDTH = 640
        const val CAPTURE_HEIGHT = 480
        const val CAPTURE_FPS = 24
        @Volatile var initialized = false
        fun ensureInitialized(context: Context) {
            if (initialized) return
            synchronized(this) {
                if (!initialized) {
                    PeerConnectionFactory.initialize(PeerConnectionFactory.InitializationOptions.builder(context).createInitializationOptions())
                    initialized = true
                }
            }
        }
    }
}
