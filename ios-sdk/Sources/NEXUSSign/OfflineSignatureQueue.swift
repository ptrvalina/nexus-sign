import Foundation

/// Offline confirmation v2 (docs/protocol/offline-confirmation-v2-deferred-signature.md):
/// the device signatures made during offline confirmations, kept until Auth
/// Core has them. An item is written before the code is shown, so there is no
/// code without a stored signature.
struct PendingOfflineSignature: Codable, Equatable {
    let authorizationId: String
    /// Base64 DER ECDSA signature over the canonical bytes.
    let signature: String
    let createdAtEpochSeconds: Int64
}

/// What Auth Core answered for one upload.
enum UploadOutcome: Equatable {
    /// 200 VERIFIED / ALREADY_RECORDED or 202 RECEIVED.
    case accepted
    /// 409, 422, 403, 404 and other 4xx: retrying cannot succeed.
    case refused(statusCode: Int)
    /// No answer, 401, 429 or 5xx: kept and retried.
    case retry

    static func of(statusCode: Int) -> UploadOutcome {
        switch statusCode {
        case 200..<300: return .accepted
        case 401, 429: return .retry
        case 400..<500: return .refused(statusCode: statusCode)
        default: return .retry
        }
    }
}

/// Result of one delivery round.
public struct OfflineSignatureDelivery: Equatable {
    public let delivered: Int
    public let refused: Int
    public let pending: Int
}

final class OfflineSignatureQueue {
    /// Auth Core's longest signature deadline (OFFLINE_SIGNATURE_DEADLINE_HOURS ≤ 720).
    static let maxAgeSeconds: Int64 = 30 * 24 * 3600

    /// One atomic, backup-excluded file per bank (finding D-06): an item is
    /// on disk when `add` returns, before the code is computed.
    private let file: DurableFile
    private let clock: () -> Int64
    private let lock = NSLock()

    init(bankID: String, directory: URL? = nil, legacyDefaults: UserDefaults = .standard,
         clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) }) {
        self.file = DurableFile(name: "\(SDKState.safeName(bankID)).offline-signatures.json", directory: directory)
        self.clock = clock
        // Items of earlier SDK builds, kept in UserDefaults, are moved once.
        let legacyKey = "com.nexis.nexussign.\(bankID).offline.pending"
        if file.read() == nil, let data = legacyDefaults.data(forKey: legacyKey),
           let items = try? JSONDecoder().decode([PendingOfflineSignature].self, from: data) {
            if (try? save(items)) != nil { legacyDefaults.removeObject(forKey: legacyKey) }
        }
    }

    func pending() -> [PendingOfflineSignature] {
        lock.lock(); defer { lock.unlock() }
        return load()
    }

    /// Adds or replaces the item for an authorization (one signature each).
    func add(authorizationID: String, signature: Data) throws {
        lock.lock(); defer { lock.unlock() }
        var items = load().filter { $0.authorizationId != authorizationID }
        items.append(PendingOfflineSignature(authorizationId: authorizationID, signature: signature.base64EncodedString(), createdAtEpochSeconds: clock()))
        try save(items)
    }

    /// Uploads every item; removes those Auth Core accepted or definitively
    /// refused, and items older than `maxAgeSeconds`; keeps the rest.
    func deliver(_ upload: (PendingOfflineSignature) async -> UploadOutcome) async -> OfflineSignatureDelivery {
        var delivered = 0
        var refused = 0
        let now = clock()
        for item in pending() {
            if now - item.createdAtEpochSeconds > Self.maxAgeSeconds {
                remove(item); refused += 1
                continue
            }
            switch await upload(item) {
            case .accepted: remove(item); delivered += 1
            case .refused: remove(item); refused += 1
            case .retry: break
            }
        }
        return OfflineSignatureDelivery(delivered: delivered, refused: refused, pending: pending().count)
    }

    /// If the write fails the item stays and is uploaded again later; Auth
    /// Core answers a repeated upload with ALREADY_RECORDED.
    private func remove(_ item: PendingOfflineSignature) {
        lock.lock(); defer { lock.unlock() }
        try? save(load().filter { $0 != item })
    }

    private func load() -> [PendingOfflineSignature] {
        guard let data = file.read() else { return [] }
        return (try? JSONDecoder().decode([PendingOfflineSignature].self, from: data)) ?? []
    }

    private func save(_ items: [PendingOfflineSignature]) throws {
        try file.write(try JSONEncoder().encode(items))
    }
}
