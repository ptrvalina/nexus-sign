import XCTest
@testable import NEXUSSign

/// What every real answer carries: DTLS-SRTP needs the certificate hash.
let dtlsFingerprint = "\r\na=fingerprint:sha-256 " + Array(repeating: "AB", count: 32).joined(separator: ":")

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

        /// Holds the lock for `body` only. A synchronous helper, so async
        /// methods never call lock()/unlock() themselves (an error in Swift 6).
        private func locked<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }

        var toOperator: [CallMessage] { lock.lock(); defer { lock.unlock() }; return _toOperator }
        var cancelled: Int { lock.lock(); defer { lock.unlock() }; return _cancelled }
        var offersSent: Int { toOperator.filter { if case .offer = $0 { return true } else { return false } }.count }

        func join() async throws -> VerificationCallInfo {
            VerificationCallInfo(sessionID: sessionID, channel: channel, expiresAt: expiresAt, iceServers: [IceServer(urls: ["stun:turn.bank.example:3478"])], operatorJoined: false)
        }

        func send(_ message: CallMessage, messageID: String) async throws {
            try locked {
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
        }

        func receive(after: Int64, waitMilliseconds: Int) async throws -> SignalBatch {
            if let receiveError { throw receiveError }
            let deadline = Date().addingTimeInterval(Double(min(waitMilliseconds, 200)) / 1000)
            while true {
                let batch: [ReceivedSignal] = locked {
                    let batch = replayed + toDevice.filter { $0.seq > after }
                    replayed.removeAll()
                    return batch
                }
                if !batch.isEmpty || Date() >= deadline { return SignalBatch(signals: batch, next: batch.last?.seq ?? after) }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
        }

        func cancel() async throws { locked { _cancelled += 1 } }

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
        /// When set, the offer this engine creates (with a DTLS fingerprint).
        var offerSdp: String?
        var log: [String] { lock.lock(); defer { lock.unlock() }; return _log }
        private func add(_ entry: String) { lock.lock(); _log.append(entry); lock.unlock() }

        func prepare(iceServers: [IceServer], video: Bool, events: MediaEvents) async throws {
            self.events = events; self.video = video; add("prepare")
            events.captureState(cameraOn: video, microphoneOn: true)
        }
        func createOffer(iceRestart: Bool) async throws -> String { offers += 1; add("offer:\(iceRestart)"); return offerSdp ?? "v=0 offer \(offers)" }
        // Logs the first SDP line; the rest is the DTLS fingerprint.
        func applyAnswer(sdp: String) async throws { add("answer:\(sdp.components(separatedBy: "\r\n")[0])") }
        func addRemoteCandidate(_ candidate: IceCandidateInit) async throws { add("remote:\(candidate.candidate)") }
        func setMicrophoneEnabled(_ enabled: Bool) { add("mic:\(enabled)") }
        func setCameraEnabled(_ enabled: Bool) { add("camera:\(enabled)") }
        func releaseMedia() { releases += 1; add("release") }
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
        relay.operatorSends(.answer(sdp: "v=0 answer" + dtlsFingerprint))
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
        relay.operatorSends(.answer(sdp: "v=0 a1" + dtlsFingerprint))
        relay.operatorSends(.candidate(candidate(4)))
        try await until("candidate") { engine.log.contains { $0.contains("10.0.0.4") } }
        relay.replay(0); relay.replay(1)
        relay.operatorSends(.answer(sdp: "v=0 a2" + dtlsFingerprint))
        relay.operatorSends(.offer(sdp: "v=0 from operator"))
        try await until("ignored") { await call.ignoredMessages >= 4 }
        XCTAssertEqual(engine.log.filter { $0.hasPrefix("answer:") }.count, 1)
        XCTAssertEqual(engine.log.filter { $0.contains("10.0.0.4") }.count, 1)
    }

    func testIceRestartAfterADrop() async throws {
        let relay = Relay(), engine = Engine()
        let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
        await call.start()
        relay.operatorSends(.answer(sdp: "v=0 a1" + dtlsFingerprint))
        try await until("answer") { engine.log.contains("answer:v=0 a1") }
        engine.events.connectionState(.connected)
        try await until("connected") { await call.state == .connected }
        engine.events.connectionState(.disconnected)
        try await until("restart offer") { relay.offersSent == 2 }
        XCTAssertTrue(engine.log.contains("offer:true"))
        relay.operatorSends(.answer(sdp: "v=0 a2" + dtlsFingerprint))
        try await until("answer 2") { engine.log.contains("answer:v=0 a2") }
        engine.events.connectionState(.connected)
        try await until("connected again") { await call.state == .connected }
    }

    func testRestartLimitEndsTheCallAndClosesTheSession() async throws {
        let relay = Relay(), engine = Engine()
        var options = fast; options.maxIceRestarts = 1
        let call = VerificationCallController(signalling: relay, engine: engine, options: options)
        await call.start()
        relay.operatorSends(.answer(sdp: "v=0 a1" + dtlsFingerprint))
        try await until("answer") { engine.log.contains("answer:v=0 a1") }
        engine.events.connectionState(.failed)
        try await until("restart") { relay.offersSent == 2 }
        relay.operatorSends(.answer(sdp: "v=0 a2" + dtlsFingerprint))
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

    /// Finding D-14: an answer without a DTLS fingerprint is not applied; the
    /// call ends and the session is closed.
    func testAnswerWithoutDtlsFingerprintEndsTheCall() async throws {
        let relay = Relay(), engine = Engine()
        let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
        await call.start()
        relay.operatorSends(.answer(sdp: "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc"))
        try await until("ended") { await call.state.isEnded }
        let state = await call.state
        XCTAssertEqual(state, .ended(.failed(message: "the operator's answer has no DTLS fingerprint")))
        XCTAssertFalse(engine.log.contains { $0.hasPrefix("answer:") }, "the answer is not applied")
        try await until("cancelled") { relay.cancelled == 1 }
        XCTAssertEqual(engine.releases, 1)
    }

    /// Finding D-14: a relay-only call keeps only TURN URLs, and is refused
    /// when Auth Core supplied none.
    func testRelayOnlyKeepsOnlyTurnServers() throws {
        let servers = [
            IceServer(urls: ["stun:stun.bank.example:3478"]),
            IceServer(urls: ["turn:turn.bank.example:3478?transport=udp", "stun:turn.bank.example:3478", "TURNS:turn.bank.example:5349"], username: "u", credential: "c"),
        ]
        XCTAssertEqual(try IceServer.relayOnly(servers),
                       [IceServer(urls: ["turn:turn.bank.example:3478?transport=udp", "TURNS:turn.bank.example:5349"], username: "u", credential: "c")])
        XCTAssertThrowsError(try IceServer.relayOnly([IceServer(urls: ["stun:stun.bank.example:3478"])])) { error in
            guard case NEXUSSignError.invalidArgument = error else { return XCTFail("got \(error)") }
        }
    }

    func testDtlsFingerprintCheck() {
        let hash = { (n: Int) in Array(repeating: "0f", count: n).joined(separator: ":") }
        XCTAssertTrue(VerificationCallController.hasDtlsFingerprint("v=0\r\na=fingerprint:sha-256 \(hash(32))\r\n"))
        XCTAssertTrue(VerificationCallController.hasDtlsFingerprint("v=0\na=fingerprint:SHA-384 \(hash(48))"))
        XCTAssertTrue(VerificationCallController.hasDtlsFingerprint("a=fingerprint:sha-512 \(hash(64))"))
        XCTAssertFalse(VerificationCallController.hasDtlsFingerprint("v=0\r\n"))
        XCTAssertFalse(VerificationCallController.hasDtlsFingerprint("a=fingerprint:sha-256 \(hash(31))"))
        XCTAssertFalse(VerificationCallController.hasDtlsFingerprint("a=fingerprint:sha-1 \(hash(20))"))
        XCTAssertFalse(VerificationCallController.hasDtlsFingerprint("a=fingerprint:sha-256 \(hash(31)):zz"))
        XCTAssertFalse(VerificationCallController.hasDtlsFingerprint("a=fingerprint:sha-256"))
    }

    /// Finding A2-11: the call code from the offer and the answer, as the
    /// operator console computes it (shared vectors).
    func testCallCodeVectors() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "call-code-v1", withExtension: "json"))
        let vectors = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        for v in try XCTUnwrap(vectors["valid"] as? [[String: String]]) {
            XCTAssertEqual(CallCode.fingerprint(v["offer"]!), v["offerFingerprint"], v["name"]!)
            XCTAssertEqual(CallCode.fingerprint(v["answer"]!), v["answerFingerprint"], v["name"]!)
            XCTAssertEqual(CallCode.code(offer: v["offer"]!, answer: v["answer"]!), v["code"], v["name"]!)
        }
        for v in try XCTUnwrap(vectors["noFingerprint"] as? [[String: String]]) {
            XCTAssertNil(CallCode.code(offer: v["offer"]!, answer: v["answer"]!), v["name"]!)
        }
    }

    func testCallCodeIsSetWhenTheAnswerArrives() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "call-code-v1", withExtension: "json"))
        let vectors = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let v = try XCTUnwrap((vectors["valid"] as? [[String: String]])?.first)
        let relay = Relay(), engine = Engine()
        engine.offerSdp = v["offer"]
        let call = VerificationCallController(signalling: relay, engine: engine, options: fast)
        await call.start()
        let before = await call.callCode
        XCTAssertNil(before)
        relay.operatorSends(.answer(sdp: v["answer"]!))
        try await until("call code") { await call.callCode == v["code"] }
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
