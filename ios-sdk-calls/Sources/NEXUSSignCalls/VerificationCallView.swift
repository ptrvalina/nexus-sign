import AVFoundation
import NEXUSSign
import SwiftUI
import WebRTC

/// Camera and microphone permission for a call. Ask right before the
/// customer starts the call; an AUDIO call never asks for the camera. The
/// host app's Info.plist needs NSMicrophoneUsageDescription and, for VIDEO,
/// NSCameraUsageDescription.
public enum CallPermissions {
    public static func request(for channel: VerificationChannel) async -> Bool {
        guard await AVCaptureDevice.requestAccess(for: .audio) else { return false }
        if channel == .video { return await AVCaptureDevice.requestAccess(for: .video) }
        return true
    }
}

/// One verification call of the customer for SwiftUI: SDK session and
/// signalling, the libwebrtc engine and the call state machine.
///
/// ```swift
/// let session = try await sdk.openVerificationCall(authorization: authorization, channel: .video)
/// let model = try VerificationCallModel(sdk: sdk, session: session, terms: try authorization.signedTransaction().confirmationText)
/// // VerificationCallView(model: model); model.start()
/// ```
@MainActor
public final class VerificationCallModel: ObservableObject {
    @Published public private(set) var state: CallState = .idle
    @Published public private(set) var capture = CaptureState(cameraOn: false, microphoneOn: false)
    @Published public private(set) var microphoneEnabled = true
    @Published public private(set) var cameraEnabled = true
    /// The call code the operator reads out (finding A2-11); nil until the answer arrives.
    @Published public private(set) var callCode: String?

    public let session: VerificationSession
    /// The terms from the signed bytes (`confirmationText`), the same the operator sees.
    public let terms: String
    public let engine: WebRTCCallEngine
    public let controller: VerificationCallController
    private var stoppedForBackground = false

    /// `relayOnly`: media only through Auth Core's TURN server (finding D-14).
    public init(sdk: NEXUSSignSDK, session: VerificationSession, terms: String, options: VerificationCallController.Options = .init(), relayOnly: Bool = false) throws {
        self.session = session
        self.terms = terms
        self.engine = WebRTCCallEngine(relayOnly: relayOnly)
        controller = VerificationCallController(signalling: try sdk.callSignalling(for: session), engine: engine, options: options)
    }

    public func start() {
        Task {
            await controller.observe { [weak self] state, capture in
                // The capture list copies the weak reference into the task
                // (a captured `var` may not be used from concurrent code).
                // The call code is set before the state changes (VerificationCallController.callCode).
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.state = state; self.capture = capture
                    self.callCode = await self.controller.callCode
                }
            }
            await controller.start()
        }
    }

    public func toggleMicrophone() {
        microphoneEnabled.toggle()
        let enabled = microphoneEnabled
        Task { await controller.setMicrophoneEnabled(enabled) }
    }

    public func toggleCamera() {
        cameraEnabled.toggle()
        let enabled = cameraEnabled
        Task { await controller.setCameraEnabled(enabled) }
    }

    /// Ends or declines the call; nothing is verified or failed.
    public func hangUp() { Task { await controller.hangUp() } }

    /// The camera stops in the background (iOS does not allow background
    /// capture) and starts again when the app is active, unless the customer
    /// turned it off.
    public func scenePhaseChanged(_ phase: ScenePhase) {
        guard session.channel == .video, !state.isEnded else { return }
        switch phase {
        case .background:
            if cameraEnabled { stoppedForBackground = true; Task { await controller.setCameraEnabled(false) } }
        case .active:
            if stoppedForBackground { stoppedForBackground = false; Task { await controller.setCameraEnabled(true) } }
        default:
            break
        }
    }
}

/// Call screen: the operator's video (VIDEO), the customer's preview, the
/// transaction terms, an always-visible camera/microphone indicator, and
/// mute, camera and hang-up buttons. English defaults; pass `Labels` to localize.
public struct VerificationCallView: View {
    public struct Labels {
        public var waiting = "Waiting for a bank employee…"
        public var connecting = "Connecting…"
        public var connected = "Connected"
        public var reconnecting = "Reconnecting…"
        public var ended = "Call ended"
        public var cameraAndMicrophoneOn = "Camera and microphone on"
        public var microphoneOn = "Microphone on"
        public var cameraOn = "Camera on"
        public var off = "Camera and microphone off"
        public var notice = "The bank employee checks this payment with you. The call is not recorded. You confirm the payment yourself afterwards."
        /// Shown before the six-digit call code (finding A2-11).
        public var callCode = "Call code"
        public var callCodeNotice = "The bank employee reads this code to you. If it is different, hang up."
        public init() {}
    }

    @ObservedObject var model: VerificationCallModel
    @Environment(\.scenePhase) private var scenePhase
    let labels: Labels

    public init(model: VerificationCallModel, labels: Labels = Labels()) {
        self.model = model
        self.labels = labels
    }

    public var body: some View {
        ZStack(alignment: .top) {
            Color.black.ignoresSafeArea()
            if model.session.channel == .video {
                VideoView(attach: { model.engine.remoteRenderer = $0 }).ignoresSafeArea()
                VStack { Spacer(); HStack { Spacer(); VideoView(attach: { model.engine.localRenderer = $0 }, mirrored: true).frame(width: 110, height: 150).cornerRadius(8).padding() } }
                    .padding(.bottom, 80)
            }
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Circle().fill(Color.red).frame(width: 12, height: 12).opacity(model.capture.cameraOn || model.capture.microphoneOn ? 1 : 0)
                    Text(indicatorText).foregroundColor(.white).font(.subheadline.weight(.semibold))
                }
                .accessibilityElement(children: .combine)
                Text(statusText).foregroundColor(.gray).font(.footnote)
                Text(model.terms).foregroundColor(.white).font(.title3).padding(.top, 4)
                if let code = model.callCode {
                    Text("\(labels.callCode) \(code.prefix(3)) \(code.suffix(3))").foregroundColor(.white).font(.title2.monospacedDigit().weight(.bold))
                    Text(labels.callCodeNotice).foregroundColor(.gray).font(.caption)
                }
                Text(labels.notice).foregroundColor(.gray).font(.caption)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.black.opacity(0.65))
            VStack {
                Spacer()
                HStack(spacing: 24) {
                    Button(action: model.toggleMicrophone) { Image(systemName: model.microphoneEnabled ? "mic.fill" : "mic.slash.fill") }
                        .accessibilityLabel(model.microphoneEnabled ? "Mute" : "Unmute")
                    if model.session.channel == .video {
                        Button(action: model.toggleCamera) { Image(systemName: model.cameraEnabled ? "video.fill" : "video.slash.fill") }
                            .accessibilityLabel(model.cameraEnabled ? "Camera off" : "Camera on")
                    }
                    Button(action: model.hangUp) { Image(systemName: "phone.down.fill").foregroundColor(.white).padding(14).background(Circle().fill(Color.red)) }
                        .accessibilityLabel("Hang up")
                }
                .font(.title2)
                .foregroundColor(.white)
                .disabled(model.state.isEnded)
                .padding(.bottom, 24)
            }
        }
        .onChange(of: scenePhase) { model.scenePhaseChanged($0) }
        .onDisappear { if !model.state.isEnded { model.hangUp() } }
    }

    private var indicatorText: String {
        switch (model.capture.cameraOn, model.capture.microphoneOn) {
        case (true, true): return labels.cameraAndMicrophoneOn
        case (false, true): return labels.microphoneOn
        case (true, false): return labels.cameraOn
        case (false, false): return labels.off
        }
    }

    private var statusText: String {
        switch model.state {
        case .idle, .joining, .waitingForOperator: return labels.waiting
        case .connecting: return labels.connecting
        case .connected: return labels.connected
        case .reconnecting: return labels.reconnecting
        case .ended(let reason): return reason == .decided(verified: true) || reason == .decided(verified: false) ? labels.ended : "\(labels.ended) (\(reason))"
        }
    }
}

/// RTCMTLVideoView in SwiftUI.
private struct VideoView: UIViewRepresentable {
    let attach: (RTCVideoRenderer) -> Void
    var mirrored = false

    func makeUIView(context: Context) -> RTCMTLVideoView {
        let view = RTCMTLVideoView(frame: .zero)
        view.videoContentMode = .scaleAspectFit
        if mirrored { view.transform = CGAffineTransform(scaleX: -1, y: 1) }
        attach(view)
        return view
    }

    func updateUIView(_ uiView: RTCMTLVideoView, context: Context) {}
}
