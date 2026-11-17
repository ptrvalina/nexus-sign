import Foundation

// In-app audio and video verification calls (ADR 0017).
//
// Everything here works without a WebRTC library: session and signalling
// models, the signalling transport (the SDK implements it with device-signed
// requests to Auth Core) and the call state machine. Media is done by a
// CallMediaEngine; the WebRTC implementation is the optional package
// NEXUSSignCalls (ios-sdk-calls/), so a bank app that does not use calls
// carries no WebRTC binary.
//
// A call never authorizes a transaction. The operator's decision is recorded
// by Auth Core; the customer still confirms with approve(authorization:).

public enum VerificationChannel: String, Sendable { case audio = "AUDIO", video = "VIDEO" }

public struct IceServer: Equatable, Sendable {
    public let urls: [String]
    public let username: String?
    public let credential: String?
    public init(urls: [String], username: String? = nil, credential: String? = nil) {
        self.urls = urls; self.username = username; self.credential = credential
    }

    /// For a relay-only call (finding D-14): the TURN URLs only (`turn:` or
    /// `turns:`), so neither the customer's local nor public address reaches
    /// the operator side. Throws when Auth Core supplied no TURN server: the
    /// call is refused rather than made with direct candidates.
    public static func relayOnly(_ servers: [IceServer]) throws -> [IceServer] {
        let relays = servers.compactMap { server -> IceServer? in
            let urls = server.urls.filter { $0.lowercased().hasPrefix("turn:") || $0.lowercased().hasPrefix("turns:") }
            return urls.isEmpty ? nil : IceServer(urls: urls, username: server.username, credential: server.credential)
        }
        guard !relays.isEmpty else { throw NEXUSSignError.invalidArgument(detail: "relay-only call without a TURN server") }
        return relays
    }
}

/// An open verification session of one authorization.
public struct VerificationSession: Equatable, Sendable {
    public let sessionID: String
    public let authorizationID: String
    public let channel: VerificationChannel
    public let expiresAt: Date
}

/// STUN/TURN servers of the bank, with TURN credentials valid for this session only.
public struct VerificationCallInfo: Equatable, Sendable {
    public let sessionID: String
    public let channel: VerificationChannel
    public let expiresAt: Date
    public let iceServers: [IceServer]
    public let operatorJoined: Bool
}

public struct IceCandidateInit: Equatable, Sendable {
    public let candidate: String
    public let sdpMid: String?
    public let sdpMLineIndex: Int32?
    public init(candidate: String, sdpMid: String?, sdpMLineIndex: Int32?) {
        self.candidate = candidate; self.sdpMid = sdpMid; self.sdpMLineIndex = sdpMLineIndex
    }
}

public enum CallMessage: Equatable, Sendable {
    case offer(sdp: String)
    case answer(sdp: String)
    case candidate(IceCandidateInit)
    case bye(reason: String)
}

/// A message from the operator (`operator`) or Auth Core (`server`); `message`
/// is nil for a type this SDK version does not know.
public struct ReceivedSignal: Equatable, Sendable {
    public let seq: Int64
    public let from: String
    public let message: CallMessage?
    public init(seq: Int64, from: String, message: CallMessage?) { self.seq = seq; self.from = from; self.message = message }
}

public struct SignalBatch: Equatable, Sendable {
    public let signals: [ReceivedSignal]
    public let next: Int64
    public init(signals: [ReceivedSignal], next: Int64) { self.signals = signals; self.next = next }
}

/// Signalling transport of one session; errors are `NEXUSSignError`.
public protocol CallSignalling: Sendable {
    var sessionID: String { get }
    func join() async throws -> VerificationCallInfo
    /// A retry with the same `messageID` is accepted once by Auth Core.
    func send(_ message: CallMessage, messageID: String) async throws
    func receive(after: Int64, waitMilliseconds: Int) async throws -> SignalBatch
    /// Ends or declines the call: nothing is verified or failed.
    func cancel() async throws
}

public enum MediaConnectionState: Sendable { case new, connecting, connected, disconnected, failed, closed }

/// Callbacks of a media engine; may be called on any thread.
public protocol MediaEvents: AnyObject, Sendable {
    func localCandidate(_ candidate: IceCandidateInit)
    func connectionState(_ state: MediaConnectionState)
    func captureState(cameraOn: Bool, microphoneOn: Bool)
}

/// One peer connection with the microphone (and camera for VIDEO). The
/// device always makes the offer.
public protocol CallMediaEngine: AnyObject {
    func prepare(iceServers: [IceServer], video: Bool, events: MediaEvents) async throws
    /// Creates an offer, sets it as the local description, returns its SDP.
    func createOffer(iceRestart: Bool) async throws -> String
    func applyAnswer(sdp: String) async throws
    func addRemoteCandidate(_ candidate: IceCandidateInit) async throws
    func setMicrophoneEnabled(_ enabled: Bool)
    func setCameraEnabled(_ enabled: Bool)
    /// Stops capture and closes the connection. Called exactly once.
    /// (Not `release()`: an engine built on NSObject, as libwebrtc's delegates
    /// require, would then match NSObject's `release` as well.)
    func releaseMedia()
}

public enum CallEndReason: Equatable, Sendable {
    /// The operator recorded a result; VERIFIED still needs approve().
    case decided(verified: Bool)
    case cancelledByCustomer
    /// The operator hung up without a result; the customer may call again.
    case operatorLeft
    case expired
    case connectionLost
    /// Closed by Auth Core (authorization closed, credential revoked, ...).
    case closed(reason: String)
    case failed(message: String)
}

public enum CallState: Equatable, Sendable {
    case idle, joining, waitingForOperator, connecting, connected
    case reconnecting(attempt: Int)
    case ended(CallEndReason)

    public var isEnded: Bool { if case .ended = self { return true } else { return false } }
}

public struct CaptureState: Equatable, Sendable {
    public let cameraOn: Bool
    public let microphoneOn: Bool
    /// Public so that a media module (NEXUSSignCalls) can create one.
    public init(cameraOn: Bool, microphoneOn: Bool) {
        self.cameraOn = cameraOn; self.microphoneOn = microphoneOn
    }
}

/// The device side of one call; same rules as the Android SDK:
/// offer first; local candidates wait for their offer, remote ones for the
/// answer; duplicate or stale messages and unsolicited answers are ignored;
/// a dropped connection is restored by ICE restart (at most
/// `Options.maxIceRestarts`); a bye or the session expiry ends the call; the
/// media engine is released exactly once.
public actor VerificationCallController {
    public struct Options: Sendable {
        public var pollWaitMilliseconds = 8_000
        public var reconnectGraceMilliseconds: UInt64 = 4_000
        public var maxIceRestarts = 2
        public var sendAttempts = 3
        public var retryBackoffMilliseconds: UInt64 = 1_000
        public var maxRetryBackoffMilliseconds: UInt64 = 5_000
        public init() {}
    }

    private let signalling: CallSignalling
    private let engine: CallMediaEngine
    private let options: Options
    private var observers: [UUID: (CallState, CaptureState) -> Void] = [:]

    public private(set) var state: CallState = .idle
    public private(set) var capture = CaptureState(cameraOn: false, microphoneOn: false)
    /// Messages ignored as duplicates or out of order (diagnostics).
    public private(set) var ignoredMessages = 0

    private var lastSeq: Int64 = 0
    private var offerSent = false
    private var awaitingAnswer = false
    private var remoteDescription = false
    private var pendingLocal: [IceCandidateInit] = []
    private var pendingRemote: [IceCandidateInit] = []
    private var restarts = 0
    private var mediaConnected = false
    private var released = false
    private var busy = false
    private var pollTask: Task<Void, Never>?
    private var expiryTask: Task<Void, Never>?
    private var reconnectTask: Task<Void, Never>?
    private lazy var events = EventSink(controller: self)

    public init(signalling: CallSignalling, engine: CallMediaEngine, options: Options = Options()) {
        self.signalling = signalling
        self.engine = engine
        self.options = options
    }

    /// Called on every state or capture change (on the controller's executor).
    @discardableResult
    public func observe(_ observer: @escaping @Sendable (CallState, CaptureState) -> Void) -> UUID {
        let id = UUID()
        observers[id] = observer
        observer(state, capture)
        return id
    }

    public func removeObserver(_ id: UUID) { observers[id] = nil }

    /// Joins the session, starts capture and sends the offer.
    public func start() async {
        guard state == .idle else { return }
        set(.joining)
        do {
            let info = try await signalling.join()
            let delay = max(0, info.expiresAt.timeIntervalSinceNow)
            expiryTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                if !Task.isCancelled { await self?.end(.expired) }
            }
            try await engine.prepare(iceServers: info.iceServers, video: info.channel == .video, events: events)
            try await serialized { try await self.sendOffer(iceRestart: false) }
            guard !state.isEnded else { return }
            set(.waitingForOperator)
            pollTask = Task { [weak self] in await self?.pollLoop() }
        } catch {
            end(Self.closedOrFailed(error))
        }
    }

    /// The customer ends or declines the call.
    public func hangUp() async {
        guard !state.isEnded else { return }
        end(.cancelledByCustomer)
        // Already closed on the server, or no network: the session expires
        // on its own and verifies nothing.
        try? await signalling.cancel()
    }

    public func setMicrophoneEnabled(_ enabled: Bool) { if !state.isEnded { engine.setMicrophoneEnabled(enabled) } }
    public func setCameraEnabled(_ enabled: Bool) { if !state.isEnded { engine.setCameraEnabled(enabled) } }

    // MARK: Media events

    fileprivate func onLocalCandidate(_ candidate: IceCandidateInit) async {
        guard !state.isEnded else { return }
        if offerSent && !busy {
            try? await sendReliably(.candidate(candidate))
        } else {
            pendingLocal.append(candidate)
        }
    }

    fileprivate func onCapture(cameraOn: Bool, microphoneOn: Bool) {
        capture = released ? CaptureState(cameraOn: false, microphoneOn: false) : CaptureState(cameraOn: cameraOn, microphoneOn: microphoneOn)
        notify()
    }

    fileprivate func onMediaState(_ media: MediaConnectionState) async {
        guard !state.isEnded else { return }
        switch media {
        case .connected:
            mediaConnected = true
            reconnectTask?.cancel(); reconnectTask = nil
            set(.connected)
        case .disconnected:
            guard mediaConnected, reconnectTask == nil else { return }
            set(.reconnecting(attempt: restarts + 1))
            let grace = options.reconnectGraceMilliseconds
            reconnectTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: grace * 1_000_000)
                guard !Task.isCancelled else { return }
                await self?.graceElapsed()
            }
        case .failed:
            reconnectTask?.cancel(); reconnectTask = nil
            if mediaConnected || remoteDescription { await restartIce() } else { end(.connectionLost) }
        case .closed:
            if !released { end(.connectionLost) }
        case .new, .connecting:
            break
        }
    }

    private func graceElapsed() async {
        reconnectTask = nil
        if state != .connected { await restartIce() }
    }

    // MARK: Signalling

    /// Runs `body` with no other offer or signal handling in between (actor
    /// methods interleave at each await).
    private func serialized(_ body: () async throws -> Void) async throws {
        while busy { try await Task.sleep(nanoseconds: 5_000_000) }
        busy = true
        defer { busy = false }
        try await body()
        // Candidates that arrived while busy, and belong to the sent offer.
        if offerSent {
            let held = pendingLocal
            pendingLocal.removeAll()
            for candidate in held { try await sendReliably(.candidate(candidate)) }
        }
    }

    private func sendOffer(iceRestart: Bool) async throws {
        offerSent = false
        remoteDescription = false
        let sdp = try await engine.createOffer(iceRestart: iceRestart)
        try await sendReliably(.offer(sdp: sdp))
        offerSent = true
        awaitingAnswer = true
    }

    /// One messageID per message; only failures that may not have reached
    /// Auth Core are retried, a refusal (4xx) is final.
    private func sendReliably(_ message: CallMessage) async throws {
        let messageID = UUID().uuidString.lowercased()
        var backoff = options.retryBackoffMilliseconds
        for attempt in 1...options.sendAttempts {
            do {
                try await signalling.send(message, messageID: messageID)
                return
            } catch NEXUSSignError.networkUnavailable(let underlying) {
                if attempt == options.sendAttempts { throw NEXUSSignError.networkUnavailable(underlying: underlying) }
            } catch NEXUSSignError.serverError(let status, let message) {
                if status < 500 || attempt == options.sendAttempts { throw NEXUSSignError.serverError(statusCode: status, message: message) }
            }
            try await Task.sleep(nanoseconds: backoff * 1_000_000)
            backoff = min(backoff * 2, options.maxRetryBackoffMilliseconds)
        }
    }

    private func pollLoop() async {
        var backoff = options.retryBackoffMilliseconds
        while !state.isEnded && !Task.isCancelled {
            let batch: SignalBatch
            do {
                batch = try await signalling.receive(after: lastSeq, waitMilliseconds: options.pollWaitMilliseconds)
                backoff = options.retryBackoffMilliseconds
            } catch NEXUSSignError.networkUnavailable {
                // Offline for a moment: keep the call; the expiry ends it if
                // the network does not come back.
                try? await Task.sleep(nanoseconds: backoff * 1_000_000)
                backoff = min(backoff * 2, options.maxRetryBackoffMilliseconds)
                continue
            } catch NEXUSSignError.serverError(let status, _) where status >= 500 {
                try? await Task.sleep(nanoseconds: backoff * 1_000_000)
                backoff = min(backoff * 2, options.maxRetryBackoffMilliseconds)
                continue
            } catch {
                end(Self.closedOrFailed(error))
                return
            }
            do {
                try await serialized {
                    for signal in batch.signals { try await self.handle(signal) }
                }
            } catch {
                end(Self.closedOrFailed(error))
                return
            }
        }
    }

    private func handle(_ signal: ReceivedSignal) async throws {
        guard !state.isEnded else { return }
        guard signal.seq > lastSeq else { ignoredMessages += 1; return }
        lastSeq = signal.seq
        switch signal.message {
        case .answer(let sdp):
            guard awaitingAnswer, signal.from == "operator" else { ignoredMessages += 1; return }
            // Media without a DTLS fingerprint would not be DTLS-SRTP
            // (finding D-14): the call ends instead of connecting.
            guard Self.hasDtlsFingerprint(sdp) else {
                end(.failed(message: "the operator's answer has no DTLS fingerprint"))
                try? await signalling.cancel()
                return
            }
            try await engine.applyAnswer(sdp: sdp)
            awaitingAnswer = false
            remoteDescription = true
            let held = pendingRemote
            pendingRemote.removeAll()
            for candidate in held { try await engine.addRemoteCandidate(candidate) }
            if state == .waitingForOperator { set(.connecting) }
        case .candidate(let candidate):
            guard signal.from == "operator" else { ignoredMessages += 1; return }
            if remoteDescription { try await engine.addRemoteCandidate(candidate) } else { pendingRemote.append(candidate) }
        case .bye(let reason):
            end(Self.byeReason(reason))
        case .offer, .none:
            ignoredMessages += 1 // the device always offers; unknown types are skipped
        }
    }

    private func restartIce() async {
        guard !state.isEnded, !awaitingAnswer else { return }
        guard restarts < options.maxIceRestarts else {
            end(.connectionLost)
            // Close the session so the customer can call again at once.
            try? await signalling.cancel()
            return
        }
        restarts += 1
        set(.reconnecting(attempt: restarts))
        do {
            try await serialized { try await self.sendOffer(iceRestart: true) }
        } catch {
            end(Self.closedOrFailed(error))
        }
    }

    // MARK: Ending

    private func set(_ new: CallState) {
        guard !state.isEnded else { return }
        state = new
        notify()
    }

    private func notify() { for observer in observers.values { observer(state, capture) } }

    private func end(_ reason: CallEndReason) {
        guard !state.isEnded else { return }
        state = .ended(reason)
        reconnectTask?.cancel()
        expiryTask?.cancel()
        pollTask?.cancel()
        if !released {
            released = true
            engine.releaseMedia()
        }
        capture = CaptureState(cameraOn: false, microphoneOn: false)
        notify()
    }

    static func byeReason(_ reason: String) -> CallEndReason {
        switch reason {
        case "decided:VERIFIED", "session_verified": return .decided(verified: true)
        case "decided:FAILED", "session_failed": return .decided(verified: false)
        case "operator_left": return .operatorLeft
        case "session_expired": return .expired
        case "cancelled", "session_cancelled": return .cancelledByCustomer
        default: return .closed(reason: reason)
        }
    }

    /// True when the SDP carries an `a=fingerprint` line with a SHA-256,
    /// SHA-384 or SHA-512 certificate hash of the right length (RFC 8122),
    /// which DTLS-SRTP needs.
    static func hasDtlsFingerprint(_ sdp: String) -> Bool {
        let lengths = ["sha-256": 32, "sha-384": 48, "sha-512": 64]
        for rawLine in sdp.split(whereSeparator: { $0 == "\n" || $0 == "\r" || $0 == "\r\n" }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard line.lowercased().hasPrefix("a=fingerprint:") else { continue }
            let parts = line.dropFirst("a=fingerprint:".count).split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count == 2, let expected = lengths[parts[0].lowercased()] else { continue }
            let bytes = parts[1].split(separator: ":", omittingEmptySubsequences: false)
            if bytes.count == expected && bytes.allSatisfy({ $0.count == 2 && $0.allSatisfy(\.isHexDigit) }) { return true }
        }
        return false
    }

    static func closedOrFailed(_ error: Error) -> CallEndReason {
        if case NEXUSSignError.serverError(let status, let message) = error {
            if status == 410 { return .expired }
            if status == 409 || status == 404 { return .closed(reason: message ?? "closed") }
        }
        return .failed(message: String(describing: error))
    }
}

/// Forwards media callbacks (any thread) into the controller actor.
private final class EventSink: MediaEvents, @unchecked Sendable {
    weak var controller: VerificationCallController?
    init(controller: VerificationCallController) { self.controller = controller }
    func localCandidate(_ candidate: IceCandidateInit) { Task { [controller] in await controller?.onLocalCandidate(candidate) } }
    func connectionState(_ state: MediaConnectionState) { Task { [controller] in await controller?.onMediaState(state) } }
    func captureState(cameraOn: Bool, microphoneOn: Bool) { Task { [controller] in await controller?.onCapture(cameraOn: cameraOn, microphoneOn: microphoneOn) } }
}

// MARK: Wire format (openapi.yaml: CallSignalRequest, CallSignal)

enum CallWire {
    static func encode(_ message: CallMessage, messageID: String) -> [String: Any] {
        var body: [String: Any]
        switch message {
        case .offer(let sdp): body = ["type": "offer", "payload": ["sdp": sdp]]
        case .answer(let sdp): body = ["type": "answer", "payload": ["sdp": sdp]]
        case .candidate(let c):
            var payload: [String: Any] = ["candidate": c.candidate]
            if let mid = c.sdpMid { payload["sdpMid"] = mid }
            if let index = c.sdpMLineIndex { payload["sdpMLineIndex"] = Int(index) }
            body = ["type": "candidate", "payload": payload]
        case .bye(let reason): body = ["type": "bye", "payload": ["reason": reason]]
        }
        body["messageId"] = messageID
        return body
    }

    static func decodeBatch(_ body: [String: Any], after: Int64) -> SignalBatch {
        let signals: [ReceivedSignal] = (body["signals"] as? [[String: Any]] ?? []).compactMap { o in
            guard let seq = int64(o["seq"]) else { return nil }
            return ReceivedSignal(seq: seq, from: o["from"] as? String ?? "", message: decodeMessage(o["type"] as? String, o["payload"] as? [String: Any]))
        }
        return SignalBatch(signals: signals, next: int64(body["next"]) ?? signals.map(\.seq).max() ?? after)
    }

    private static func decodeMessage(_ type: String?, _ payload: [String: Any]?) -> CallMessage? {
        switch type {
        case "offer": return (payload?["sdp"] as? String).map { .offer(sdp: $0) }
        case "answer": return (payload?["sdp"] as? String).map { .answer(sdp: $0) }
        case "candidate":
            guard let candidate = payload?["candidate"] as? String else { return nil }
            return .candidate(IceCandidateInit(candidate: candidate, sdpMid: payload?["sdpMid"] as? String, sdpMLineIndex: int64(payload?["sdpMLineIndex"]).map { Int32($0) }))
        case "bye": return .bye(reason: payload?["reason"] as? String ?? "bye")
        default: return nil
        }
    }

    static func decodeSession(_ body: [String: Any], authorizationID: String) throws -> VerificationSession {
        guard let id = body["sessionId"] as? String, let channel = (body["channel"] as? String).flatMap(VerificationChannel.init(rawValue:)),
              let expires = (body["expiresAt"] as? String).flatMap(parseDate) else { throw invalid }
        return VerificationSession(sessionID: id, authorizationID: authorizationID, channel: channel, expiresAt: expires)
    }

    static func decodeJoin(_ body: [String: Any]) throws -> VerificationCallInfo {
        guard let id = body["sessionId"] as? String, let channel = (body["channel"] as? String).flatMap(VerificationChannel.init(rawValue:)),
              let expires = (body["expiresAt"] as? String).flatMap(parseDate) else { throw invalid }
        let servers: [IceServer] = (body["iceServers"] as? [[String: Any]] ?? []).compactMap { o in
            let urls = (o["urls"] as? [String]) ?? (o["urls"] as? String).map { [$0] } ?? []
            return urls.isEmpty ? nil : IceServer(urls: urls, username: o["username"] as? String, credential: o["credential"] as? String)
        }
        return VerificationCallInfo(sessionID: id, channel: channel, expiresAt: expires, iceServers: servers, operatorJoined: body["operatorJoined"] as? Bool ?? false)
    }

    /// `GET /v1/mobile/customer-calls/{id}`: `{call, iceServers}`. The operator has joined once the call is CONNECTED.
    static func decodeCustomerCallJoin(_ body: [String: Any]) throws -> VerificationCallInfo {
        guard let call = body["call"] as? [String: Any], let id = call["callId"] as? String,
              let channel = (call["channel"] as? String).flatMap(VerificationChannel.init(rawValue:)),
              let expires = (call["expiresAt"] as? String).flatMap(parseDate) else { throw invalid }
        if let state = call["state"] as? String, !["WAITING", "CONNECTED"].contains(state) {
            throw NEXUSSignError.serverError(statusCode: 409, message: "The call is \(state)")
        }
        let servers: [IceServer] = (body["iceServers"] as? [[String: Any]] ?? []).compactMap { o in
            let urls = (o["urls"] as? [String]) ?? (o["urls"] as? String).map { [$0] } ?? []
            return urls.isEmpty ? nil : IceServer(urls: urls, username: o["username"] as? String, credential: o["credential"] as? String)
        }
        return VerificationCallInfo(sessionID: id, channel: channel, expiresAt: expires, iceServers: servers, operatorJoined: call["state"] as? String == "CONNECTED")
    }

    private static let invalid = NEXUSSignError.invalidServerResponse(detail: "unexpected response format")

    private static func int64(_ value: Any?) -> Int64? {
        if let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() { return n.int64Value }
        return nil
    }

    static func parseDate(_ text: String) -> Date? {
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return withFraction.date(from: text) ?? ISO8601DateFormatter().date(from: text)
    }
}

/// `CallSignalling` over device-signed requests to Auth Core.
final class DeviceCallSignalling: CallSignalling, @unchecked Sendable {
    let sessionID: String
    private let network: NetworkClient
    init(sessionID: String, network: NetworkClient) { self.sessionID = sessionID; self.network = network }

    func join() async throws -> VerificationCallInfo { try CallWire.decodeJoin(try await network.joinCall(sessionID: sessionID)) }
    func send(_ message: CallMessage, messageID: String) async throws {
        try await network.sendCallSignal(sessionID: sessionID, body: CallWire.encode(message, messageID: messageID))
    }
    func receive(after: Int64, waitMilliseconds: Int) async throws -> SignalBatch {
        CallWire.decodeBatch(try await network.receiveCallSignals(sessionID: sessionID, after: after, waitMilliseconds: min(waitMilliseconds, network.callPollWaitMilliseconds)), after: after)
    }
    func cancel() async throws { try await network.cancelCall(sessionID: sessionID) }
}

/// [CallSignalling] for a call the customer started: the same call engine,
/// media and signalling rules; `cancel` hangs up or stops waiting.
final class CustomerCallSignalling: CallSignalling, @unchecked Sendable {
    let sessionID: String
    private let network: NetworkClient
    init(callID: String, network: NetworkClient) { self.sessionID = callID; self.network = network }

    func join() async throws -> VerificationCallInfo { try CallWire.decodeCustomerCallJoin(try await network.joinCustomerCall(callID: sessionID)) }
    func send(_ message: CallMessage, messageID: String) async throws {
        try await network.sendCustomerCallSignal(callID: sessionID, body: CallWire.encode(message, messageID: messageID))
    }
    func receive(after: Int64, waitMilliseconds: Int) async throws -> SignalBatch {
        CallWire.decodeBatch(try await network.receiveCustomerCallSignals(callID: sessionID, after: after, waitMilliseconds: min(waitMilliseconds, network.callPollWaitMilliseconds)), after: after)
    }
    func cancel() async throws { try await network.endCustomerCall(callID: sessionID) }
}
