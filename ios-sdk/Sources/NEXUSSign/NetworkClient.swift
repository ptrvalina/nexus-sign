import Foundation
import Security

/// HTTP client for the Auth Core mobile API.
///
/// An enrolled device signs each request with its Secure Enclave
/// authentication key (device protocols v1) and holds no token. Bearer
/// tokens are used only for enrolment (BOOTSTRAP) and recovery, each passed
/// in explicitly.
final class NetworkClient {
    /// An enrolled device that signs its own requests.
    struct DeviceIdentity {
        let credentialID: String
        let sign: (Data) throws -> Data
    }

    /// Public keys of one enrolment, as PEM.
    struct EnrolmentKeys {
        let signing: String
        let authentication: String
        let offline: String
    }

    private let config: NEXUSSignConfig
    private let session: URLSession
    private let lock = NSLock()
    private var identity: DeviceIdentity?
    /// Auth Core time minus device time, learned from a rejected timestamp.
    private var clockOffset: Int64 = 0

    init(config: NEXUSSignConfig, session: URLSession? = nil) {
        self.config = config
        self.session = session ?? CertificatePinning.session(pins: config.certificatePins)
    }

    /// Set once the device is enrolled; every device request is signed with it.
    var deviceIdentity: DeviceIdentity? {
        get { lock.lock(); defer { lock.unlock() }; return identity }
        set { lock.lock(); defer { lock.unlock() }; identity = newValue }
    }

    func bootstrap(keys: EnrolmentKeys, securityLevel: String, attestation: [String: Any], bootstrapToken: String) async throws -> NexusMobileRegistration {
        let body: [String: Any] = [
            "publicKeyPem": keys.signing,
            "authPublicKeyPem": keys.authentication,
            "offlinePublicKeyPem": keys.offline,
            "platform": "IOS",
            "securityLevel": securityLevel,
            "deviceAttestation": attestation,
        ]
        return try await send("POST", "/v1/mobile/bootstrap", body: body, token: .fixed(bootstrapToken))
    }

    func fetchAuthorization(authorizationID: String) async throws -> NexusAuthorization {
        try await send("GET", "/v1/mobile/authorizations/\(authorizationID)")
    }

    func signAuthorization(authorizationID: String, signature: Data) async throws -> VerifyResponse {
        let body: [String: Any] = ["signature": signature.base64EncodedString(), "signatureFormat": "der"]
        return try await send("POST", "/v1/mobile/authorizations/\(authorizationID)/signature", body: body)
    }

    /// Offline confirmation v2: the deferred device signature. Any 2xx means
    /// Auth Core has it; other answers are `serverError(statusCode:)`.
    func uploadDeferredSignature(authorizationID: String, signatureBase64: String) async throws {
        let body: [String: Any] = ["signature": signatureBase64, "signatureFormat": "der"]
        _ = try await perform("POST", "/v1/mobile/authorizations/\(authorizationID)/deferred-signature", body: body, token: .device)
    }

    struct PushRegistrationResponse: Decodable {
        let status: String
        let provider: String
        let serverPublicKeyPem: String?
        let keyId: String
    }

    struct PushEnvelopeResponse: Decodable {
        let messageId: String
        let status: String
        let envelope: NexusPushEnvelope
    }

    /// With `devicePublicKeyPEM` a new push key is agreed; otherwise only the
    /// token is updated, for the key named by `keyID`.
    func registerPush(deviceToken: String, environment: NexusAPNsEnvironment, devicePublicKeyPEM: String?, keyID: String?) async throws -> PushRegistrationResponse {
        var body: [String: Any] = ["provider": "APNS", "deviceToken": deviceToken, "apnsEnvironment": environment.rawValue]
        if let devicePublicKeyPEM { body["devicePublicKeyPem"] = devicePublicKeyPEM }
        if let keyID { body["keyId"] = keyID }
        return try await send("POST", "/v1/mobile/push-registration", body: body)
    }

    func unregisterPush() async throws {
        _ = try await perform("DELETE", "/v1/mobile/push-registration", body: nil, token: .device)
    }

    func fetchPushEnvelope(messageID: String) async throws -> PushEnvelopeResponse {
        try await send("GET", "/v1/mobile/push-messages/\(messageID)")
    }

    func recoveryParameters() async throws -> NexusRecoveryParameters {
        try await send("GET", "/v1/mobile/recovery/setup")
    }

    func configureRecovery(salt: String, recoveryPublicKeyPEM: String, wrappedRecoveryKey: Data, signature: Data) async throws {
        let body: [String: Any] = [
            "protocol": RecoveryProtocol.version,
            "salt": salt,
            "recoveryPublicKeyPem": recoveryPublicKeyPEM,
            "wrappedRecoveryKey": wrappedRecoveryKey.base64EncodedString(),
            "signature": signature.base64EncodedString(),
        ]
        try await sendExpectingNoContent("POST", "/v1/mobile/recovery/setup", body: body)
    }

    func recover(session recoverySession: NexusRecoverySession, proof: Data, keys: EnrolmentKeys, attestation: [String: Any]) async throws -> NexusRecoveryResult {
        let body: [String: Any] = [
            "proof": proof.base64EncodedString(),
            "newPublicKeyPem": keys.signing,
            "authPublicKeyPem": keys.authentication,
            "offlinePublicKeyPem": keys.offline,
            "platform": "IOS",
            "securityLevel": "SECURE_ENCLAVE",
            "deviceAttestation": attestation,
        ]
        return try await send("POST", "/v1/recovery/sessions/\(recoverySession.sessionId)/complete", body: body, token: .fixed(recoverySession.accessToken))
    }

    // MARK: - Transport

    // MARK: Verification calls (ADR 0017)

    func openVerificationSession(authorizationID: String, channel: VerificationChannel) async throws -> [String: Any] {
        try await sendJSON("POST", "/v1/mobile/authorizations/\(authorizationID)/verification-sessions", body: ["channel": channel.rawValue])
    }

    func joinCall(sessionID: String) async throws -> [String: Any] {
        try await sendJSON("GET", "/v1/mobile/verification-sessions/\(sessionID)/call")
    }

    func sendCallSignal(sessionID: String, body: [String: Any]) async throws {
        _ = try await perform("POST", "/v1/mobile/verification-sessions/\(sessionID)/signals", body: body, token: .device)
    }

    func receiveCallSignals(sessionID: String, after: Int64, waitMilliseconds: Int) async throws -> [String: Any] {
        try await sendJSON("GET", "/v1/mobile/verification-sessions/\(sessionID)/signals?after=\(after)&waitMs=\(waitMilliseconds)")
    }

    func cancelCall(sessionID: String) async throws {
        _ = try await perform("POST", "/v1/mobile/verification-sessions/\(sessionID)/cancel", body: [:], token: .device)
    }

    func declineAuthorization(authorizationID: String, reason: NexusDeclineReason) async throws {
        _ = try await perform("POST", "/v1/mobile/authorizations/\(authorizationID)/decline", body: ["reason": reason.rawValue], token: .device)
    }

    // MARK: Device replacement hold (A2-01)

    func deviceReplacements() async throws -> [NexusDeviceReplacement] {
        let list: DeviceReplacementList = try await send("GET", "/v1/mobile/device-replacements")
        return list.replacements
    }

    func decideDeviceReplacement(replacementID: String, approve: Bool) async throws -> NexusDeviceReplacement {
        try await send("POST", "/v1/mobile/device-replacements/\(replacementID)/\(approve ? "approve" : "cancel")", body: [:])
    }

    /// Longest long-poll wait that fits in the request timeout.
    var callPollWaitMilliseconds: Int { max(0, min(15_000, Int(config.requestTimeout * 1000) - 2_000)) }

    private func sendJSON(_ method: String, _ path: String, body: [String: Any]? = nil) async throws -> [String: Any] {
        let data = try await perform(method, path, body: body, token: .device)
        guard let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw NEXUSSignError.serverError(statusCode: 200, message: "Unexpected response format")
        }
        return object
    }

    private enum TokenSource {
        /// Signed by the enrolled device's authentication key.
        case device
        /// A BOOTSTRAP or recovery token.
        case fixed(String)
    }

    private func send<T: Decodable>(_ method: String, _ path: String, body: [String: Any]? = nil, token: TokenSource = .device) async throws -> T {
        let data = try await perform(method, path, body: body, token: token)
        guard !data.isEmpty else {
            throw NEXUSSignError.serverError(statusCode: 200, message: "Unexpected empty response")
        }
        do {
            return try JSONDecoder.nexus().decode(T.self, from: data)
        } catch {
            // A body that does not decode is an Auth Core contract problem, not a connectivity one.
            throw NEXUSSignError.serverError(statusCode: 200, message: "Unexpected response format")
        }
    }

    private func sendExpectingNoContent(_ method: String, _ path: String, body: [String: Any]? = nil) async throws {
        _ = try await perform(method, path, body: body, token: .device)
    }

    private func perform(_ method: String, _ path: String, body: [String: Any]?, token: TokenSource) async throws -> Data {
        let bodyData = try body.map { try JSONSerialization.data(withJSONObject: $0) }
        var attempt = 0
        while true {
            attempt += 1
            // appendingPathComponent would percent-encode a "?", so the query
            // (call signals: ?after=&waitMs=) is set separately.
            let pathParts = path.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
            var url = config.baseURL.appendingPathComponent(String(pathParts[0]).trimmingCharacters(in: CharacterSet(charactersIn: "/")))
            if pathParts.count == 2, var components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
                components.percentEncodedQuery = String(pathParts[1])
                url = components.url ?? url
            }
            var request = URLRequest(url: url)
            request.httpMethod = method
            request.timeoutInterval = config.requestTimeout
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue("NEXUSSign-iOS/\(NEXUSSignVersion.current)", forHTTPHeaderField: "User-Agent")
            if let bodyData {
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                request.httpBody = bodyData
            }

            let device = deviceIdentity
            switch token {
            case .fixed(let value):
                request.setValue("Bearer \(value)", forHTTPHeaderField: "Authorization")
            case .device:
                guard let device else { throw NEXUSSignError.notRegistered }
                // Sign the path and query exactly as they go on the wire.
                let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
                let target = (components?.percentEncodedPath ?? path) + (components?.percentEncodedQuery.map { "?" + $0 } ?? "")
                try signRequest(&request, device: device, method: method, path: target, body: bodyData ?? Data())
            }

            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await session.data(for: request)
            } catch {
                throw NEXUSSignError.networkUnavailable(underlying: error)
            }
            guard let http = response as? HTTPURLResponse else {
                throw NEXUSSignError.networkUnavailable(underlying: URLError(.badServerResponse))
            }
            if http.statusCode == 401, case .device = token, attempt == 1 {
                // A rejected timestamp carries Auth Core's time: correct the
                // clock offset once and sign again with a fresh nonce.
                // The value is unauthenticated, so only plausible offsets are used.
                if let serverTime = (try? JSONDecoder.nexus().decode(ErrorResponse.self, from: data))?.serverTime {
                    let offset = serverTime - Int64(Date().timeIntervalSince1970)
                    if abs(offset) <= 86_400 {
                        setClockOffset(offset)
                        continue
                    }
                }
            }
            guard (200..<300).contains(http.statusCode) else {
                let message = try? JSONDecoder.nexus().decode(ErrorResponse.self, from: data).error
                throw NEXUSSignError.serverError(statusCode: http.statusCode, message: message)
            }
            return data
        }
    }

    /// Device protocols v1: sign method, path, time, nonce, credential and body hash.
    private func signRequest(_ request: inout URLRequest, device: DeviceIdentity, method: String, path: String, body: Data) throws {
        let timestamp = String(Int64(Date().timeIntervalSince1970) + currentClockOffset())
        var nonceBytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, nonceBytes.count, &nonceBytes) == errSecSuccess else {
            throw NEXUSSignError.keyOperationFailed(status: errSecParam)
        }
        let nonce = Data(nonceBytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let input = DeviceProtocol.requestSigningInput(method: method, path: path, timestamp: timestamp, nonce: nonce,
                                                       credentialID: device.credentialID, body: body)
        request.setValue(device.credentialID, forHTTPHeaderField: "X-NEXUS-Credential")
        request.setValue(timestamp, forHTTPHeaderField: "X-NEXUS-Timestamp")
        request.setValue(nonce, forHTTPHeaderField: "X-NEXUS-Nonce")
        request.setValue(try device.sign(input).base64EncodedString(), forHTTPHeaderField: "X-NEXUS-Signature")
    }

    private func currentClockOffset() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        return clockOffset
    }

    private func setClockOffset(_ offset: Int64) {
        lock.lock(); defer { lock.unlock() }
        clockOffset = offset
    }
}
