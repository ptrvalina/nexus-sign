import AVFoundation
import Foundation
import NEXUSSign
import WebRTC

/// `CallMediaEngine` on libwebrtc (stasel/WebRTC). One peer connection, the
/// microphone, and for VIDEO the front camera. Media is encrypted by
/// DTLS-SRTP as negotiated by libwebrtc; nothing is recorded. Only VP8 and
/// VP9 are offered (no H.264/H.265, see docs/engineering/THIRD_PARTY_MEDIA.md).
///
/// Attach renderers with `localRenderer` / `remoteRenderer` (for example the
/// `RTCMTLVideoView`s of `VerificationCallView`), before or after the start.
public final class WebRTCCallEngine: NSObject, CallMediaEngine, @unchecked Sendable {
    private static let factory: RTCPeerConnectionFactory = {
        RTCInitializeSSL()
        return RTCPeerConnectionFactory(encoderFactory: RoyaltyFreeEncoderFactory(), decoderFactory: RoyaltyFreeDecoderFactory())
    }()

    private let lock = NSLock()
    private var peer: RTCPeerConnection?
    private var audioTrack: RTCAudioTrack?
    private var videoTrack: RTCVideoTrack?
    private var remoteVideoTrack: RTCVideoTrack?
    private var capturer: RTCCameraVideoCapturer?
    private var captureDevice: AVCaptureDevice?
    private weak var events: MediaEvents?
    private var cameraOn = false
    private var microphoneOn = false
    private var released = false

    public weak var localRenderer: RTCVideoRenderer? {
        didSet { if let old = oldValue { videoTrack?.remove(old) }; if let new = localRenderer { videoTrack?.add(new) } }
    }
    public weak var remoteRenderer: RTCVideoRenderer? {
        didSet { if let old = oldValue { remoteVideoTrack?.remove(old) }; if let new = remoteRenderer { remoteVideoTrack?.add(new) } }
    }

    /// Media only through the TURN relay (finding D-14): the customer's local
    /// and public addresses are not offered to the operator side. A bank
    /// option; the call fails when Auth Core supplies no TURN server.
    public let relayOnly: Bool

    public init(relayOnly: Bool = false) {
        self.relayOnly = relayOnly
        super.init()
    }

    public func prepare(iceServers: [IceServer], video: Bool, events: MediaEvents) async throws {
        self.events = events
        let configuration = RTCConfiguration()
        let servers = relayOnly ? try IceServer.relayOnly(iceServers) : iceServers
        configuration.iceServers = servers.map { RTCIceServer(urlStrings: $0.urls, username: $0.username, credential: $0.credential) }
        if relayOnly { configuration.iceTransportPolicy = .relay }
        configuration.sdpSemantics = .unifiedPlan
        configuration.continualGatheringPolicy = .gatherContinually
        configuration.bundlePolicy = .maxBundle
        configuration.rtcpMuxPolicy = .require
        let constraints = RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)
        guard let pc = Self.factory.peerConnection(with: configuration, constraints: constraints, delegate: self) else {
            throw CallEngineError.peerConnectionUnavailable
        }
        peer = pc

        try configureAudioSession(video: video)
        let audio = Self.factory.audioTrack(with: Self.factory.audioSource(with: constraints), trackId: "nexus-microphone")
        pc.add(audio, streamIds: [Self.streamID])
        audioTrack = audio
        microphoneOn = true

        if video {
            let source = Self.factory.videoSource()
            let camera = RTCCameraVideoCapturer(delegate: source)
            guard let device = RTCCameraVideoCapturer.captureDevices().first(where: { $0.position == .front }) ?? RTCCameraVideoCapturer.captureDevices().first else {
                throw CallEngineError.noCamera
            }
            capturer = camera
            captureDevice = device
            try await startCapture()
            let track = Self.factory.videoTrack(with: source, trackId: "nexus-camera")
            pc.add(track, streamIds: [Self.streamID])
            videoTrack = track
            if let localRenderer { track.add(localRenderer) }
        }
        reportCapture()
    }

    public func createOffer(iceRestart: Bool) async throws -> String {
        guard let pc = peer else { throw CallEngineError.notPrepared }
        if iceRestart { pc.restartIce() }
        let constraints = RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)
        let offer: RTCSessionDescription = try await withCheckedThrowingContinuation { continuation in
            pc.offer(for: constraints) { description, error in
                if let description { continuation.resume(returning: description) } else { continuation.resume(throwing: error ?? CallEngineError.negotiation) }
            }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            pc.setLocalDescription(offer) { error in if let error { continuation.resume(throwing: error) } else { continuation.resume() } }
        }
        return offer.sdp
    }

    public func applyAnswer(sdp: String) async throws {
        guard let pc = peer else { throw CallEngineError.notPrepared }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            pc.setRemoteDescription(RTCSessionDescription(type: .answer, sdp: sdp)) { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }

    public func addRemoteCandidate(_ candidate: IceCandidateInit) async throws {
        guard let pc = peer else { throw CallEngineError.notPrepared }
        let ice = RTCIceCandidate(sdp: candidate.candidate, sdpMLineIndex: candidate.sdpMLineIndex ?? 0, sdpMid: candidate.sdpMid)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            pc.add(ice) { error in if let error { continuation.resume(throwing: error) } else { continuation.resume() } }
        }
    }

    public func setMicrophoneEnabled(_ enabled: Bool) {
        audioTrack?.isEnabled = enabled
        microphoneOn = enabled && audioTrack != nil
        reportCapture()
    }

    /// Stops the camera itself (not only the track), so the system camera
    /// indicator and ours both go off.
    public func setCameraEnabled(_ enabled: Bool) {
        guard capturer != nil, enabled != cameraOn else { return }
        if enabled {
            Task { try? await startCapture(); videoTrack?.isEnabled = true; reportCapture() }
        } else {
            capturer?.stopCapture()
            videoTrack?.isEnabled = false
            cameraOn = false
            reportCapture()
        }
    }

    public func releaseMedia() {
        lock.lock()
        guard !released else { lock.unlock(); return }
        released = true
        lock.unlock()
        capturer?.stopCapture()
        if let localRenderer { videoTrack?.remove(localRenderer) }
        if let remoteRenderer { remoteVideoTrack?.remove(remoteRenderer) }
        peer?.close()
        peer = nil; capturer = nil; captureDevice = nil
        audioTrack = nil; videoTrack = nil; remoteVideoTrack = nil
        cameraOn = false; microphoneOn = false
        deactivateAudioSession()
        reportCapture()
    }

    private func startCapture() async throws {
        guard let capturer, let device = captureDevice else { return }
        // A 640x480 (or nearest) format at up to 24 fps.
        let formats = RTCCameraVideoCapturer.supportedFormats(for: device)
        let format = formats.min(by: { a, b in
            let da = CMVideoFormatDescriptionGetDimensions(a.formatDescription), db = CMVideoFormatDescriptionGetDimensions(b.formatDescription)
            return abs(Int(da.width) - 640) + abs(Int(da.height) - 480) < abs(Int(db.width) - 640) + abs(Int(db.height) - 480)
        }) ?? formats.first
        guard let format else { throw CallEngineError.noCamera }
        let maxFps = format.videoSupportedFrameRateRanges.map(\.maxFrameRate).max() ?? 24
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            capturer.startCapture(with: device, format: format, fps: Int(min(maxFps, 24))) { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
        cameraOn = true
    }

    private func configureAudioSession(video: Bool) throws {
        let session = RTCAudioSession.sharedInstance()
        let configuration = RTCAudioSessionConfiguration.webRTC()
        configuration.category = AVAudioSession.Category.playAndRecord.rawValue
        configuration.mode = (video ? AVAudioSession.Mode.videoChat : AVAudioSession.Mode.voiceChat).rawValue
        configuration.categoryOptions = video ? [.allowBluetooth, .defaultToSpeaker] : [.allowBluetooth]
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        try session.setConfiguration(configuration, active: true)
    }

    private func deactivateAudioSession() {
        let session = RTCAudioSession.sharedInstance()
        session.lockForConfiguration()
        try? session.setActive(false)
        session.unlockForConfiguration()
    }

    private func reportCapture() {
        events?.captureState(cameraOn: cameraOn && !released, microphoneOn: microphoneOn && !released)
    }

    private static let streamID = "nexus-call"
}

public enum CallEngineError: Error { case peerConnectionUnavailable, notPrepared, noCamera, negotiation }

extension WebRTCCallEngine: RTCPeerConnectionDelegate {
    public func peerConnection(_ peerConnection: RTCPeerConnection, didGenerate candidate: RTCIceCandidate) {
        events?.localCandidate(IceCandidateInit(candidate: candidate.sdp, sdpMid: candidate.sdpMid, sdpMLineIndex: candidate.sdpMLineIndex))
    }

    public func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCPeerConnectionState) {
        let state: MediaConnectionState
        switch newState {
        case .new: state = .new
        case .connecting: state = .connecting
        case .connected: state = .connected
        case .disconnected: state = .disconnected
        case .failed: state = .failed
        case .closed: state = .closed
        @unknown default: return
        }
        events?.connectionState(state)
    }

    public func peerConnection(_ peerConnection: RTCPeerConnection, didStartReceivingOn transceiver: RTCRtpTransceiver) {
        guard let track = transceiver.receiver.track as? RTCVideoTrack else { return }
        remoteVideoTrack = track
        if let remoteRenderer { track.add(remoteRenderer) }
    }

    public func peerConnection(_ peerConnection: RTCPeerConnection, didChange stateChanged: RTCSignalingState) {}
    public func peerConnection(_ peerConnection: RTCPeerConnection, didAdd stream: RTCMediaStream) {}
    public func peerConnection(_ peerConnection: RTCPeerConnection, didRemove stream: RTCMediaStream) {}
    public func peerConnectionShouldNegotiate(_ peerConnection: RTCPeerConnection) {}
    public func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCIceConnectionState) {}
    public func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCIceGatheringState) {}
    public func peerConnection(_ peerConnection: RTCPeerConnection, didRemove candidates: [RTCIceCandidate]) {}
    public func peerConnection(_ peerConnection: RTCPeerConnection, didOpen dataChannel: RTCDataChannel) {}
}

/// VP8 and VP9 only (no H.264/H.265 patent exposure through this module).
private func allowedVideoCodec(_ info: RTCVideoCodecInfo) -> Bool {
    info.name.caseInsensitiveCompare("VP8") == .orderedSame || info.name.caseInsensitiveCompare("VP9") == .orderedSame
}

private final class RoyaltyFreeEncoderFactory: NSObject, RTCVideoEncoderFactory {
    private let inner = RTCDefaultVideoEncoderFactory()
    func createEncoder(_ info: RTCVideoCodecInfo) -> RTCVideoEncoder? { allowedVideoCodec(info) ? inner.createEncoder(info) : nil }
    func supportedCodecs() -> [RTCVideoCodecInfo] { inner.supportedCodecs().filter(allowedVideoCodec) }
}

private final class RoyaltyFreeDecoderFactory: NSObject, RTCVideoDecoderFactory {
    private let inner = RTCDefaultVideoDecoderFactory()
    func createDecoder(_ info: RTCVideoCodecInfo) -> RTCVideoDecoder? { allowedVideoCodec(info) ? inner.createDecoder(info) : nil }
    func supportedCodecs() -> [RTCVideoCodecInfo] { inner.supportedCodecs().filter(allowedVideoCodec) }
}
