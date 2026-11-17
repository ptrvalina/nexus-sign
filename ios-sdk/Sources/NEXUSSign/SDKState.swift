import Foundation

/// A small file the SDK owns in Application Support (finding D-06): written
/// whole and atomically (`Data.write(options: .atomic)`, a rename), so a
/// reader sees the old or the new content and never a mix; protected until
/// the first unlock after boot; excluded from iCloud and computer backups,
/// because it describes keys that exist only on this device.
final class DurableFile {
    let url: URL
    /// Number of completed writes (diagnostics and tests).
    private(set) var writes = 0

    init(name: String, directory: URL? = nil) {
        let base = directory ?? Self.defaultDirectory
        self.url = base.appendingPathComponent(name, isDirectory: false)
    }

    static var defaultDirectory: URL {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        return support.appendingPathComponent("NEXUSSign", isDirectory: true)
    }

    func read() -> Data? {
        try? Data(contentsOf: url)
    }

    func write(_ data: Data) throws {
        var directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var options: Data.WritingOptions = [.atomic]
        #if os(iOS)
        options.insert(.completeFileProtectionUntilFirstUserAuthentication)
        #endif
        try data.write(to: url, options: options)
        // An atomic write replaces the file, so the flag is set again each time.
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var file = url
        try file.setResourceValues(values)
        try? directory.setResourceValues(values)
        writes += 1
    }

    func delete() {
        try? FileManager.default.removeItem(at: url)
    }
}

/// Non-secret SDK state per bank: the credential registered by the last
/// successful `bootstrap()` or recovery, the offline key agreement Auth Core
/// confirmed, and whether a key set confirmed by Auth Core still has to be
/// promoted to the active tags.
///
/// Kept as one JSON document in a `DurableFile` (finding D-06). Before, each
/// field was a separate UserDefaults key, flushed later by cfprefsd and
/// included in backups: after a power loss the keys could be re-tagged while
/// the credential ID was still the old one. `update` writes several fields in
/// one atomic write. State written by earlier SDK builds to UserDefaults is
/// moved here once.
final class SDKState {
    struct Snapshot: Codable, Equatable {
        var credentialId: String?
        var offlineServerPublicKey: String?
        var offlineKeyAgreement: String?
        var pendingCredentialId: String?
        var pendingOfflineServerPublicKey: String?
        var pendingOfflineKeyAgreement: String?
        var deviceSignatures = false
        var pendingDeviceSignatures = false
        var replacementCommitPending = false
        var biometryDomainState: Data?
    }

    private let file: DurableFile
    private let lock = NSLock()
    private var snapshot: Snapshot
    /// The last write that failed; the state stays in memory meanwhile.
    private(set) var lastPersistenceError: Error?

    private static let registryLock = NSLock()
    private static var registry: [String: SDKState] = [:]

    /// One instance per bank and directory in a process, so every component
    /// sees the same state.
    static func shared(bankID: String, directory: URL? = nil, legacyDefaults: UserDefaults = .standard) -> SDKState {
        registryLock.lock(); defer { registryLock.unlock() }
        let key = "\((directory ?? DurableFile.defaultDirectory).path)|\(bankID)"
        if let existing = registry[key] { return existing }
        let state = SDKState(bankID: bankID, directory: directory, legacyDefaults: legacyDefaults)
        registry[key] = state
        return state
    }

    init(bankID: String, directory: URL? = nil, legacyDefaults: UserDefaults = .standard) {
        file = DurableFile(name: "\(Self.safeName(bankID)).state.json", directory: directory)
        if let data = file.read(), let stored = try? JSONDecoder().decode(Snapshot.self, from: data) {
            snapshot = stored
            return
        }
        // Moves the state of earlier SDK builds out of UserDefaults, once.
        let legacy = LegacyDefaults(bankID: bankID, defaults: legacyDefaults)
        snapshot = legacy.snapshot()
        guard legacy.exists else { return }
        do {
            try file.write(try JSONEncoder().encode(snapshot))
            legacy.remove()
        } catch {
            lastPersistenceError = error // the legacy keys stay and are moved at the next start
        }
    }

    /// File names are derived from the bank ID; anything but a conservative
    /// character set is replaced.
    static func safeName(_ bankID: String) -> String {
        String(bankID.unicodeScalars.map { CharacterSet.alphanumerics.contains($0) || "-_.".unicodeScalars.contains($0) ? Character($0) : "_" })
    }

    var current: Snapshot { lock.lock(); defer { lock.unlock() }; return snapshot }

    /// Changes several fields together: one atomic write.
    func update(_ change: (inout Snapshot) -> Void) {
        lock.lock(); defer { lock.unlock() }
        var next = snapshot
        change(&next)
        guard next != snapshot else { return }
        snapshot = next
        do {
            try file.write(try JSONEncoder().encode(next))
            lastPersistenceError = nil
        } catch {
            lastPersistenceError = error
        }
    }

    var writes: Int { file.writes }

    // Single fields, for reads and one-field changes.

    /// Credential ID confirmed by Auth Core; `nil` until enrolment succeeds.
    var registeredCredentialID: String? {
        get { current.credentialId }
        set { update { $0.credentialId = newValue } }
    }

    /// Auth Core's half of the static offline key agreement (enrolments with
    /// `STATIC` key agreement only).
    var offlineServerPublicKeyPEM: String? {
        get { current.offlineServerPublicKey }
        set { update { $0.offlineServerPublicKey = newValue } }
    }

    /// `PER_AUTHORIZATION` when Auth Core confirmed a fresh server key per
    /// offline confirmation (finding D-01), `STATIC` or `nil` otherwise.
    var offlineKeyAgreement: String? {
        get { current.offlineKeyAgreement }
        set { update { $0.offlineKeyAgreement = newValue } }
    }

    var pendingCredentialID: String? {
        get { current.pendingCredentialId }
        set { update { $0.pendingCredentialId = newValue } }
    }

    var deviceSignatures: Bool {
        get { current.deviceSignatures }
        set { update { $0.deviceSignatures = newValue } }
    }

    var pendingDeviceSignatures: Bool {
        get { current.pendingDeviceSignatures }
        set { update { $0.pendingDeviceSignatures = newValue } }
    }

    var pendingOfflineServerPublicKeyPEM: String? {
        get { current.pendingOfflineServerPublicKey }
        set { update { $0.pendingOfflineServerPublicKey = newValue } }
    }

    var pendingOfflineKeyAgreement: String? {
        get { current.pendingOfflineKeyAgreement }
        set { update { $0.pendingOfflineKeyAgreement = newValue } }
    }

    /// Set when Auth Core has confirmed an enrolment or recovery and the
    /// replacement key is the credential, but the local re-tag has not
    /// completed yet.
    var replacementCommitPending: Bool {
        get { current.replacementCommitPending }
        set { update { $0.replacementCommitPending = newValue } }
    }

    /// `LAContext.evaluatedPolicyDomainState` when the active keys were
    /// enrolled. A different value later means the biometric enrolment changed
    /// and the biometry-bound keys are gone.
    var biometryDomainState: Data? {
        get { current.biometryDomainState }
        set { update { $0.biometryDomainState = newValue } }
    }
}

/// The UserDefaults keys of SDK builds before finding D-06 was fixed.
struct LegacyDefaults {
    let defaults: UserDefaults
    let prefix: String

    init(bankID: String, defaults: UserDefaults) {
        self.defaults = defaults
        self.prefix = "com.nexis.nexussign.\(bankID)."
    }

    static let keys = ["credentialId", "offlineServerPublicKey", "pendingCredentialId", "deviceSignatures", "pendingDeviceSignatures",
                       "pendingOfflineServerPublicKey", "recoveryCommitPending", "biometryDomainState"]

    var exists: Bool { Self.keys.contains { defaults.object(forKey: prefix + $0) != nil } }

    func snapshot() -> SDKState.Snapshot {
        var s = SDKState.Snapshot()
        s.credentialId = defaults.string(forKey: prefix + "credentialId")
        s.offlineServerPublicKey = defaults.string(forKey: prefix + "offlineServerPublicKey")
        s.offlineKeyAgreement = s.offlineServerPublicKey == nil ? nil : "STATIC"
        s.pendingCredentialId = defaults.string(forKey: prefix + "pendingCredentialId")
        s.pendingOfflineServerPublicKey = defaults.string(forKey: prefix + "pendingOfflineServerPublicKey")
        s.pendingOfflineKeyAgreement = s.pendingOfflineServerPublicKey == nil ? nil : "STATIC"
        s.deviceSignatures = defaults.bool(forKey: prefix + "deviceSignatures")
        s.pendingDeviceSignatures = defaults.bool(forKey: prefix + "pendingDeviceSignatures")
        s.replacementCommitPending = defaults.bool(forKey: prefix + "recoveryCommitPending")
        s.biometryDomainState = defaults.data(forKey: prefix + "biometryDomainState")
        return s
    }

    func remove() {
        for key in Self.keys { defaults.removeObject(forKey: prefix + key) }
    }
}
