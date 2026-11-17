import XCTest
@testable import NEXUSSign

/// Finding D-06: the registration state and the pending offline signatures
/// are one atomic, backup-excluded file each, not UserDefaults keys that
/// cfprefsd flushes later and backups copy.
final class DurableStateTests: XCTestCase {
    private func freshDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("DurableStateTests-\(UUID().uuidString)", isDirectory: true)
    }

    private func freshDefaults() -> (UserDefaults, String) {
        let name = "DurableStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return (defaults, name)
    }

    func testARegistrationIsWrittenInOneAtomicWriteAndReadBackByANewInstance() throws {
        let directory = freshDirectory()
        let (defaults, name) = freshDefaults()
        let state = SDKState(bankID: "bank-a", directory: directory, legacyDefaults: defaults)
        XCTAssertEqual(state.writes, 0)
        state.update {
            $0.pendingCredentialId = "c-2"
            $0.pendingOfflineKeyAgreement = "PER_AUTHORIZATION"
            $0.pendingDeviceSignatures = true
            $0.replacementCommitPending = true
        }
        XCTAssertEqual(state.writes, 1, "the fields of one commit are written together")
        // As after a crash right here: a new process reads all of them or none.
        let reread = SDKState(bankID: "bank-a", directory: directory, legacyDefaults: defaults)
        XCTAssertEqual(reread.current, state.current)
        XCTAssertEqual(reread.pendingCredentialID, "c-2")
        XCTAssertTrue(reread.replacementCommitPending)
        XCTAssertTrue(defaults.persistentDomain(forName: name)?.isEmpty ?? true, "nothing goes to UserDefaults")
    }

    func testTheFileIsExcludedFromBackups() throws {
        let directory = freshDirectory()
        let state = SDKState(bankID: "bank-b", directory: directory, legacyDefaults: freshDefaults().0)
        state.registeredCredentialID = "c-1"
        let url = directory.appendingPathComponent("bank-b.state.json")
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
        // Rewritten atomically (a new file): still excluded.
        state.registeredCredentialID = "c-2"
        XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
    }

    func testStateOfEarlierBuildsMovesOutOfUserDefaultsOnce() throws {
        let directory = freshDirectory()
        let (defaults, _) = freshDefaults()
        let prefix = "com.nexis.nexussign.bank-c."
        defaults.set("c-legacy", forKey: prefix + "credentialId")
        defaults.set("-----BEGIN PUBLIC KEY-----x", forKey: prefix + "offlineServerPublicKey")
        defaults.set(true, forKey: prefix + "deviceSignatures")
        defaults.set(true, forKey: prefix + "recoveryCommitPending")
        let state = SDKState(bankID: "bank-c", directory: directory, legacyDefaults: defaults)
        XCTAssertEqual(state.registeredCredentialID, "c-legacy")
        XCTAssertEqual(state.offlineKeyAgreement, "STATIC", "an earlier enrolment used the static agreement")
        XCTAssertTrue(state.deviceSignatures)
        XCTAssertTrue(state.replacementCommitPending)
        for key in LegacyDefaults.keys { XCTAssertNil(defaults.object(forKey: prefix + key), key) }
        // The file now holds it; a later start does not read UserDefaults again.
        defaults.set("other", forKey: prefix + "credentialId")
        XCTAssertEqual(SDKState(bankID: "bank-c", directory: directory, legacyDefaults: defaults).registeredCredentialID, "c-legacy")
    }

    func testOneInstancePerBankInAProcess() {
        let directory = freshDirectory()
        let a = SDKState.shared(bankID: "bank-d", directory: directory)
        let b = SDKState.shared(bankID: "bank-d", directory: directory)
        XCTAssertTrue(a === b)
        XCTAssertFalse(a === SDKState.shared(bankID: "bank-e", directory: directory))
    }

    func testBankIDsBecomeSafeFileNames() {
        XCTAssertEqual(SDKState.safeName("bank-a.prod_1"), "bank-a.prod_1")
        XCTAssertEqual(SDKState.safeName("../evil/x"), ".._evil_x")
    }

    func testPendingOfflineSignaturesMoveOutOfUserDefaults() throws {
        let directory = freshDirectory()
        let (defaults, _) = freshDefaults()
        let item = PendingOfflineSignature(authorizationId: "00000000-0000-4000-8000-00000000000a", signature: "c2ln", createdAtEpochSeconds: 1)
        defaults.set(try JSONEncoder().encode([item]), forKey: "com.nexis.nexussign.bank-f.offline.pending")
        let queue = OfflineSignatureQueue(bankID: "bank-f", directory: directory, legacyDefaults: defaults, clock: { 2 })
        XCTAssertEqual(queue.pending(), [item])
        XCTAssertNil(defaults.object(forKey: "com.nexis.nexussign.bank-f.offline.pending"))
        let url = directory.appendingPathComponent("bank-f.offline-signatures.json")
        XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
    }
}
