import Foundation
import CryptoKit
import Security

/// Secure push v1, identical in Auth Core and the Android SDK (vectors in
/// `secure-push-v1.json`; specification in docs/protocol/secure-push.md):
///
/// - the push key, agreed once per device credential over ECDH P-256 and HKDF-SHA256;
/// - AES-256-GCM envelopes bound to the message and credential IDs;
/// - the delivery receipt, an HMAC under the push key;
/// - the key ID both sides compare at every token refresh.
enum PushProtocol {
    static let domain = "NEXUS-SIGN/PUSH/v1"
    static let receiptDomain = "NEXUS-SIGN/PUSH-RECEIPT/v1"
    static let keyIDDomain = "NEXUS-SIGN/PUSH-KEY-ID/v1"
    static let ivLength = 12
    static let tagLength = 16

    static func derivePushKey(sharedSecret: Data, credentialID: String) -> SymmetricKey {
        precondition(sharedSecret.count == 32, "ECDH shared secret must be 32 bytes")
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: Data(domain.utf8),
            info: Data(credentialID.utf8),
            outputByteCount: 32
        )
    }

    static func associatedData(messageID: String, credentialID: String) -> Data {
        Data("\(domain)\n\(messageID)\n\(credentialID)".utf8)
    }

    /// The plaintext of a sealed envelope; throws if anything was altered.
    static func open(_ envelope: NexusPushEnvelope, key: SymmetricKey) throws -> Data {
        guard envelope.v == 1 else { throw NEXUSSignError.pushMessageInvalid(reason: "unsupported_version") }
        guard let iv = Data(base64URLEncoded: envelope.iv), iv.count == ivLength,
              let sealed = Data(base64URLEncoded: envelope.ct), sealed.count > tagLength else {
            throw NEXUSSignError.pushMessageInvalid(reason: "malformed_envelope")
        }
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv),
                                            ciphertext: sealed.prefix(sealed.count - tagLength),
                                            tag: sealed.suffix(tagLength))
            return try AES.GCM.open(box, using: key, authenticating: associatedData(messageID: envelope.id, credentialID: envelope.cid))
        } catch {
            throw NEXUSSignError.pushMessageInvalid(reason: "decryption_failed")
        }
    }

    /// First 16 bytes of HMAC-SHA256(K, key ID domain), base64url.
    static func keyID(_ key: SymmetricKey) -> String {
        Data(Data(HMAC<SHA256>.authenticationCode(for: Data(keyIDDomain.utf8), using: key)).prefix(16)).base64URLEncodedString()
    }

    static func receipt(key: SymmetricKey, messageID: String, credentialID: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data("\(receiptDomain)\n\(messageID)\n\(credentialID)".utf8), using: key)
        return Data(mac).base64URLEncodedString()
    }
}

/// A sealed message as Auth Core sends it: in the APNs payload under the key
/// `nexus`, and from `GET /v1/mobile/push-messages/{id}`.
public struct NexusPushEnvelope: Codable, Equatable {
    public let v: Int
    public let id: String
    public let cid: String
    public let iv: String
    public let ct: String

    /// The envelope of a NEXUS-SIGN push, or `nil` for any other notification.
    public init?(userInfo: [AnyHashable: Any]) {
        guard let object = userInfo["nexus"] as? [String: Any],
              let data = try? JSONSerialization.data(withJSONObject: object),
              let envelope = try? JSONDecoder().decode(NexusPushEnvelope.self, from: data) else { return nil }
        self = envelope
    }
}

public enum NexusPushCategory: String, Equatable {
    case authorizationRequest = "AUTHORIZATION_REQUEST"
    case incomingPayment = "INCOMING_PAYMENT"
    case outgoingPayment = "OUTGOING_PAYMENT"
    case cardTransaction = "CARD_TRANSACTION"
    case account = "ACCOUNT"
    case security = "SECURITY"
    case general = "GENERAL"
}

/// A decrypted push message, ready to show.
public struct NexusPushMessage: Equatable {
    public let messageId: String
    public let category: NexusPushCategory
    public let title: String
    public let body: String
    /// For `.authorizationRequest`: pass to `fetchAuthorization`. The
    /// confirmation screen is built from the signed bytes, not from this push.
    public let authorizationId: String?
    public let data: [String: String]
    public let sentAt: Date
    let credentialId: String
}

private struct PushContent: Decodable {
    let v: Int
    let category: String
    let title: String
    let body: String
    let authorizationId: String?
    let data: [String: String]
    let sentAt: String
}

public enum NexusAPNsEnvironment: String {
    case production = "PRODUCTION"
    /// Builds signed with a development provisioning profile.
    case development = "DEVELOPMENT"
}

/// The push key in the keychain, readable after the first unlock so a
/// notification service extension can use it while the phone is locked. The
/// Secure Enclave holds only asymmetric keys, so this symmetric key is a
/// device-only keychain item (never synced or backed up), tagged with the
/// credential it was agreed for.
struct PushKeyStore {
    private let service: String
    private let accessGroup: String?

    init(bankID: String, accessGroup: String?) {
        self.service = "com.nexis.nexussign.\(bankID).pushKey"
        self.accessGroup = accessGroup
    }

    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: false,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    func save(_ key: SymmetricKey, credentialID: String) throws {
        delete()
        var item = baseQuery()
        item[kSecAttrAccount as String] = credentialID
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        var bytes = key.withUnsafeBytes { Data($0) }
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        item[kSecValueData as String] = bytes
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw NEXUSSignError.keyOperationFailed(status: status) }
    }

    /// The key agreed for `credentialID`, or `nil` if there is none (or it
    /// belongs to an earlier credential).
    func load(credentialID: String) throws -> SymmetricKey? {
        var query = baseQuery()
        query[kSecAttrAccount as String] = credentialID
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard var data = item as? Data, data.count == 32 else { return nil }
            defer { data.resetBytes(in: 0..<data.count) }
            return SymmetricKey(data: data)
        case errSecItemNotFound:
            return nil
        default:
            throw NEXUSSignError.keyOperationFailed(status: status)
        }
    }

    func delete() {
        SecItemDelete(baseQuery() as CFDictionary)
    }
}

/// Opens NEXUS-SIGN push messages without network or user interaction, for a
/// Notification Service Extension. The extension must share the app's
/// keychain access group and use the same `bankID` and group as the app's
/// `NEXUSSignConfig`.
///
/// ```swift
/// let reader = NEXUSSignPushReader(bankID: "globalbank", keychainAccessGroup: "TEAMID.com.globalbank.shared")
/// if let message = try? reader.open(userInfo: request.content.userInfo) {
///     content.title = message.title
///     content.body = message.body
///     try? await reader.sendReceipt(for: message, baseURL: authCoreURL)
/// }
/// ```
public struct NEXUSSignPushReader {
    private let store: PushKeyStore
    /// Public-key pins for the receipt request, as `NEXUSSignConfig.certificatePins`
    /// (a Notification Service Extension passes the app's pins here).
    let certificatePins: Set<String>

    public init(bankID: String, keychainAccessGroup: String? = nil, certificatePins: Set<String> = []) {
        precondition(certificatePins.isEmpty || (certificatePins.count >= 2 && certificatePins.allSatisfy(CertificatePinning.isWellFormedPin)),
                     "certificatePins must be empty or at least two sha256/<base64> pins")
        self.store = PushKeyStore(bankID: bankID, accessGroup: keychainAccessGroup)
        self.certificatePins = certificatePins
    }

    /// The session for the receipt: the caller's, or one that enforces the
    /// pins (finding D-08: receipts used to bypass the configured pins).
    func receiptSession(_ provided: URLSession?) -> URLSession {
        provided ?? CertificatePinning.session(pins: certificatePins)
    }

    /// True for a notification sent by NEXUS-SIGN secure push.
    public func isSecurePush(_ userInfo: [AnyHashable: Any]) -> Bool {
        NexusPushEnvelope(userInfo: userInfo) != nil
    }

    public func open(userInfo: [AnyHashable: Any]) throws -> NexusPushMessage {
        guard let envelope = NexusPushEnvelope(userInfo: userInfo) else {
            throw NEXUSSignError.pushMessageInvalid(reason: "not_a_secure_push")
        }
        return try open(envelope)
    }

    public func open(_ envelope: NexusPushEnvelope) throws -> NexusPushMessage {
        guard UUID(uuidString: envelope.id) != nil, UUID(uuidString: envelope.cid) != nil else {
            throw NEXUSSignError.pushMessageInvalid(reason: "malformed_envelope")
        }
        guard let key = try store.load(credentialID: envelope.cid) else {
            throw NEXUSSignError.pushMessageInvalid(reason: "no_push_key")
        }
        let plaintext = try PushProtocol.open(envelope, key: key)
        guard let content = try? JSONDecoder().decode(PushContent.self, from: plaintext), content.v == 1,
              let category = NexusPushCategory(rawValue: content.category),
              let sentAt = SignedPayload.parseTimestamp(content.sentAt) else {
            throw NEXUSSignError.pushMessageInvalid(reason: "invalid_content")
        }
        // Auth Core refuses such text; checked again because the app shows it.
        guard SignedPayload.isDisplaySafe(content.title),
              SignedPayload.isDisplaySafe(content.body.replacingOccurrences(of: "\n", with: " ")) else {
            throw NEXUSSignError.pushMessageInvalid(reason: "unsafe_text")
        }
        if let authorizationId = content.authorizationId, UUID(uuidString: authorizationId) == nil {
            throw NEXUSSignError.pushMessageInvalid(reason: "invalid_content")
        }
        return NexusPushMessage(messageId: envelope.id, category: category, title: content.title, body: content.body,
                                authorizationId: content.authorizationId, data: content.data, sentAt: sentAt,
                                credentialId: envelope.cid)
    }

    /// The receipt that proves this device decrypted `message`.
    func receipt(for message: NexusPushMessage) throws -> String {
        guard let key = try store.load(credentialID: message.credentialId) else {
            throw NEXUSSignError.pushMessageInvalid(reason: "no_push_key")
        }
        return PushProtocol.receipt(key: key, messageID: message.messageId, credentialID: message.credentialId)
    }

    /// Confirms delivery to Auth Core (`POST /v1/push-receipts/{id}`). Works
    /// while the phone is locked: the receipt is authenticated by the push
    /// key, not the request-signing key.
    public func sendReceipt(for message: NexusPushMessage, baseURL: URL, session: URLSession? = nil, timeout: TimeInterval = 10) async throws {
        guard baseURL.scheme == "https" || (baseURL.scheme == "http" && ["localhost", "127.0.0.1", "::1"].contains(baseURL.host ?? "")) else {
            throw NEXUSSignError.configurationInvalid(detail: "Auth Core base URL must be https")
        }
        let body = try JSONSerialization.data(withJSONObject: ["credentialId": message.credentialId, "receipt": try receipt(for: message)])
        var request = URLRequest(url: baseURL.appendingPathComponent("v1/push-receipts/\(message.messageId)"))
        request.httpMethod = "POST"
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("NEXUSSign-iOS/\(NEXUSSignVersion.current)", forHTTPHeaderField: "User-Agent")
        request.httpBody = body
        let response: URLResponse
        do {
            (_, response) = try await receiptSession(session).data(for: request)
        } catch {
            throw NEXUSSignError.networkUnavailable(underlying: error)
        }
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw NEXUSSignError.serverError(statusCode: (response as? HTTPURLResponse)?.statusCode ?? 0, message: "Push receipt was not accepted")
        }
    }
}

extension Data {
    init?(base64URLEncoded text: String) {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
