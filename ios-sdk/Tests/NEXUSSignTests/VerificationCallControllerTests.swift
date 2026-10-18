import XCTest
@testable import NEXUSSign

/// The call state machine against an in-memory relay with Auth Core's
/// signalling rules and a scripted media engine (same cases as the Android
/// SDK's VerificationCallControllerTest). Not a media test.
final class VerificationCallControllerTests: XCTestCase {
    final class Relay: CallSignalling, @unchecked Sendable {
        let sessionID = "00000000-0000-4000-8000-000000000001"
        let channel: VerificationChannel
        let expiresAt: Date
        private let lock = NSLock()
        private var seq: Int64 = 0
        private var _toOperator: [CallMessage] = []
        private var toDevice: [ReceivedSignal] = []
        private var replayed: [ReceivedSignal] = []
        private var ids = Set<String>()
        private var offers = 0, answers = 0
        private var _cancelled = 0
        var receiveError: Error?

        init(channel: VerificationChannel = .video, expiresAt: Date = Date().addingTimeInterval(300)) { self.channel = channel; self.expiresAt = expiresAt }

        var toOperator: [CallMessage] { lock.lock(); defer { lock.unlock() }; return _toOperator }
        var cancelled: Int { lock.lock(); defer { lock.unlock() }; return _cancelled }
        var offersSent: Int { toOperator.filter { if case .offer = $0 { return true } else { return false } }.count }

        func join() async throws -> VerificationCallInfo {
            VerificationCallInfo(sessionID: sessionID, channel: channel, expiresAt: expiresAt, iceServers: [IceServer(urls: ["stun:turn.bank.example:3478"])], operatorJoined: false)
        }

        func send(_ message: CallMessage, messageID: String) async throws {
            lock.lock(); defer { lock.unlock() }
            guard ids.insert(messageID).inserted else { return }
            switch message {
            case .offer:
                if offers > answers { throw NEXUSSignError.serverError(statusCode: 409, message: "offer pending") }
                offers += 1
            case .candidate:
                if offers == 0 { throw NEXUSSignError.serverError(statusCode: 409, message: "candidate before offer") }
            case .answer:
                throw NEXUSSignError.serverError(statusCode: 400, message: "device never answers")
            case .bye: break
            }
            _toOperator.append(message)
        }

        func receive(after: Int64, waitMilliseconds: Int) async throws -> SignalBatch {
            if let receiveError { throw receiveError }
            let deadline = Date().addingTimeInterval(Double(min(waitMilliseconds, 200)) / 1000)
            while true {
                lock.lock()
                let batch = replayed + toDevice.filter { $0.seq > after }
                replayed.removeAll()
                lock.unlock()
                if !batch.isEmpty || Date() >= deadline { return SignalBatch(signals: batch, next: batch.last?.seq ?? after) }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
        }

        func cancel() async throws { lock.lock(); _cancelled += 1; lock.unlock() }

        func operatorSends(_ message: CallMessage, from: String = "operator") {
            lock.lock(); defer { lock.unlock() }
            if case .answer = message { answers += 1 }
            seq += 1
            toDevice.append(ReceivedSignal(seq: seq, from: from, message: message))
        }

        func replay(_ index: Int) { lock.lock(); replayed.append(toDevice[index]); lock.unlock() }
    }

    final class Engine: CallMediaEngine, @unchecked Sendable {
        private let lock = NSLock()
        private var _log: [String] = []
        var events: MediaEvents!
        var video: Bool?
        private(set) var releases = 0
        private var offers = 0
        var log: [String] { lock.lock(); defer { lock.unlock() }; return _log }
        private func add(_ entry: String) { lock.lock(); _log.append(entry); lock.unlock() }

        func prepare(iceServers: [IceServer], video: Bool, events: MediaEvents) async throws {
            self.events = events; self.video = video; add("prepare")
            events.captureState(cameraOn: video, microphoneOn: true)
        }
        func createOffer(iceRestart: Bool) async throws -> String { offers += 1; add("offer:\(iceRestart)"); return "v=0 offer \(offers)" }
        func applyAnswer(sdp: String) async throws { add("answer:\(sdp)") }
        func addRemoteCandidate(_ candidate: IceCandidateInit) async throws { add("remote:\(candidate.candidate)") }
        func setMicrophoneEnabled(_ enabled: Bool) { add("mic:\(enabled)") }
        func setCameraEnabled(_ enabled: Bool) { add("camera:\(enabled)") }
        func release() { releases += 1; add("release") }
    }

    private var fast: VerificationCallController.Options {
        var o = VerificationCallController.Options()
        o.pollWaitMilliseconds = 100; o.reconnectGraceMilliseconds = 100; o.retryBackoffMilliseconds = 20; o.maxRetryBackoffMilliseconds = 50
        return o
    }

    private func candidate(_ n: Int) -> IceCandidateInit { IceCandidateInit(candidate: "candidate:\(n) 1 udp 1 10.0.0.\(n) 9 typ host", sdpMid: "0", sdpMLineIndex: 0) }

    private func until(_ what: String, _ condition: () async -> Bool) async throws {
        let deadline = Date().addingTimeInterval(5)
        while !(await condition()) {
            if Date() > deadline { XCTFail("timed out waiting for \(what)"); return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    func testOfferFirstAndCandidateBuffering() async throws {
        let relay = Relay(), engine = Engine()
        let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
        await call.start()
        XCTAssertEqual(relay.toOperator.first, .offer(sdp: "v=0 offer 1"))
        XCTAssertEqual(engine.video, true)
        engine.events.localCandidate(candidate(1))
        try await until("candidate relayed") { relay.toOperator.count == 2 }
        relay.operatorSends(.candidate(candidate(9)))
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertFalse(engine.log.contains { $0.hasPrefix("remote:") }, "held until the answer")
        relay.operatorSends(.answer(sdp: "v=0 answer"))
        try await until("candidate applied") { engine.log.last == "remote:candidate:9 1 udp 1 10.0.0.9 9 typ host" }
        XCTAssertEqual(engine.log, ["prepare", "offer:false", "answer:v=0 answer", "remote:candidate:9 1 udp 1 10.0.0.9 9 typ host"])
        engine.events.connectionState(.connected)
        try await until("connected") { await call.state == .connected }
    }

    func testAudioOnlyDoesNotStartTheCamera() async throws {
        let relay = Relay(channel: .audio), engine = Engine()
        let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
        await call.start()
        XCTAssertEqual(engine.video, false)
        try await until("capture state") { await call.capture == CaptureState(cameraOn: false, microphoneOn: true) }
    }

    func testDuplicatesStaleAndUnsolicitedMessagesAreIgnored() async throws {
        let relay = Relay(), engine = Engine()
        let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
        await call.start()
        relay.operatorSends(.answer(sdp: "v=0 a1"))
        relay.operatorSends(.candidate(candidate(4)))
        try await until("candidate") { engine.log.contains { $0.contains("10.0.0.4") } }
        relay.replay(0); relay.replay(1)
        relay.operatorSends(.answer(sdp: "v=0 a2"))
        relay.operatorSends(.offer(sdp: "v=0 from operator"))
        try await until("ignored") { await call.ignoredMessages >= 4 }
        XCTAssertEqual(engine.log.filter { $0.hasPrefix("answer:") }.count, 1)
        XCTAssertEqual(engine.log.filter { $0.contains("10.0.0.4") }.count, 1)
    }

    func testIceRestartAfterADrop() async throws {
        let relay = Relay(), engine = Engine()
        let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
        await call.start()
        relay.operatorSends(.answer(sdp: "v=0 a1"))
        try await until("answer") { engine.log.contains("answer:v=0 a1") }
        engine.events.connectionState(.connected)
        try await until("connected") { await call.state == .connected }
        engine.events.connectionState(.disconnected)
        try await until("restart offer") { relay.offersSent == 2 }
        XCTAssertTrue(engine.log.contains("offer:true"))
        relay.operatorSends(.answer(sdp: "v=0 a2"))
        try await until("answer 2") { engine.log.contains("answer:v=0 a2") }
        engine.events.connectionState(.connected)
        try await until("connected again") { await call.state == .connected }
    }

    func testRestartLimitEndsTheCallAndClosesTheSession() async throws {
        let relay = Relay(), engine = Engine()
        var options = fast; options.maxIceRestarts = 1
        let call = VerificationCallController(signalling: relay, engine: engine, options: options)
        await call.start()
        relay.operatorSends(.answer(sdp: "v=0 a1"))
        try await until("answer") { engine.log.contains("answer:v=0 a1") }
        engine.events.connectionState(.failed)
        try await until("restart") { relay.offersSent == 2 }
        relay.operatorSends(.answer(sdp: "v=0 a2"))
        try await until("answer 2") { engine.log.contains("answer:v=0 a2") }
        engine.events.connectionState(.failed)
        try await until("ended") { await call.state == .ended(.connectionLost) }
        try await until("cancelled") { relay.cancelled == 1 }
        XCTAssertEqual(engine.releases, 1)
    }

    func testByeReasons() async throws {
        let cases: [(String, String, CallEndReason)] = [
            ("decided:VERIFIED", "operator", .decided(verified: true)),
            ("decided:FAILED", "operator", .decided(verified: false)),
            ("operator_left", "operator", .operatorLeft),
            ("session_expired", "server", .expired),
            ("credential_revoked", "server", .closed(reason: "credential_revoked")),
        ]
        for (reason, from, expected) in cases {
            let relay = Relay(), engine = Engine()
            let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
            await call.start()
            relay.operatorSends(.bye(reason: reason), from: from)
            try await until("ended \(reason)") { await call.state == .ended(expected) }
            XCTAssertEqual(engine.releases, 1)
            let capture = await call.capture
            XCTAssertEqual(capture, CaptureState(cameraOn: false, microphoneOn: false))
        }
    }

    func testExpiryEndsTheCallWithoutNetwork() async throws {
        let relay = Relay(expiresAt: Date().addingTimeInterval(0.4)), engine = Engine()
        let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
        await call.start()
        relay.receiveError = NEXUSSignError.networkUnavailable(underlying: URLError(.notConnectedToInternet))
        try await until("expired") { await call.state == .ended(.expired) }
    }

    func testHangUpCancelsOnceAndReleasesMedia() async throws {
        let relay = Relay(), engine = Engine()
        let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
        await call.start()
        await call.hangUp()
        await call.hangUp()
        let state = await call.state
        XCTAssertEqual(state, .ended(.cancelledByCustomer))
        XCTAssertEqual(relay.cancelled, 1)
        XCTAssertEqual(engine.releases, 1)
    }

    func testWireFormat() throws {
        let offer = CallWire.encode(.offer(sdp: "v=0"), messageID: "m")
        XCTAssertEqual(offer["type"] as? String, "offer")
        XCTAssertEqual((offer["payload"] as? [String: Any])?["sdp"] as? String, "v=0")
        XCTAssertEqual(offer["messageId"] as? String, "m")
        let body = try JSONSerialization.jsonObject(with: Data("""
        {"signals":[{"seq":3,"from":"operator","type":"answer","payload":{"sdp":"v=0 a"}},
          {"seq":4,"from":"operator","type":"candidate","payload":{"candidate":"candidate:2","sdpMid":"0","sdpMLineIndex":1}},
          {"seq":5,"from":"server","type":"bye","payload":{"reason":"session_expired"}},
          {"seq":6,"from":"operator","type":"future-type","payload":{}}],"next":6}
        """.utf8)) as! [String: Any]
        let batch = CallWire.decodeBatch(body, after: 2)
        XCTAssertEqual(batch, SignalBatch(signals: [
            ReceivedSignal(seq: 3, from: "operator", message: .answer(sdp: "v=0 a")),
            ReceivedSignal(seq: 4, from: "operator", message: .candidate(IceCandidateInit(candidate: "candidate:2", sdpMid: "0", sdpMLineIndex: 1))),
            ReceivedSignal(seq: 5, from: "server", message: .bye(reason: "session_expired")),
            ReceivedSignal(seq: 6, from: "operator", message: nil),
        ], next: 6))
        let join = try CallWire.decodeJoin(try JSONSerialization.jsonObject(with: Data("""
        {"sessionId":"s","channel":"AUDIO","expiresAt":"2026-10-18T10:00:00.000Z","operatorJoined":false,
         "iceServers":[{"urls":["stun:a:3478"]},{"urls":["turn:a:3478?transport=udp"],"username":"1:s","credential":"c"}]}
        """.utf8)) as! [String: Any])
        XCTAssertEqual(join.channel, .audio)
        XCTAssertEqual(join.iceServers, [IceServer(urls: ["stun:a:3478"]), IceServer(urls: ["turn:a:3478?transport=udp"], username: "1:s", credential: "c")])
    }
}
