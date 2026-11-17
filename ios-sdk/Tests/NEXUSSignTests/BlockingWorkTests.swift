import XCTest
@testable import NEXUSSign

/// Finding D-12: Secure Enclave operations that wait for Face ID and PBKDF2
/// with millions of iterations block a thread for seconds. They must not run
/// on Swift's cooperative pool, which has only one thread per core.
final class BlockingWorkTests: XCTestCase {
    func testWorkRunsOnTheDedicatedQueue() async throws {
        let onQueue = try await NEXUSSignSDK.offCooperativePool {
            DispatchQueue.getSpecific(key: NEXUSSignSDK.blockingWorkQueueKey) != nil
        }
        XCTAssertTrue(onQueue)
    }

    func testErrorsReachTheCaller() async {
        do {
            _ = try await NEXUSSignSDK.offCooperativePool { () throws -> Int in throw NEXUSSignError.authenticationDenied }
            XCTFail("expected an error")
        } catch NEXUSSignError.authenticationDenied {
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testRecoverySeedDerivationGivesTheSameSeed() async throws {
        let phrase = try RecoveryPhrase.generate()
        let salt = Data(repeating: 7, count: 16)
        let direct = RecoveryProtocol.seed(phrase: phrase, salt: salt, iterations: 1_000)
        let moved = try await NEXUSSignSDK.offCooperativePool { RecoveryProtocol.seed(phrase: phrase, salt: salt, iterations: 1_000) }
        XCTAssertEqual(direct, moved)
    }

    /// More blocked operations than the cooperative pool has threads: other
    /// tasks still run. Run synchronously inside the async functions (the old
    /// code), the blockers take every pool thread and the probe waits for them.
    func testBlockedOperationsDoNotStarveOtherTasks() async throws {
        let blockers = ProcessInfo.processInfo.activeProcessorCount + 2
        let started = Date()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<blockers {
                group.addTask { try await NEXUSSignSDK.offCooperativePool { Thread.sleep(forTimeInterval: 2.0) } }
            }
            // Give the blockers time to start before probing.
            try await Task.sleep(nanoseconds: 200_000_000)
            let probeStart = Date()
            let probe = Task.detached { 1 + 1 }
            let value = await probe.value
            XCTAssertEqual(value, 2)
            XCTAssertLessThan(Date().timeIntervalSince(probeStart), 1.0, "a task waited for the blocked operations")
            try await group.waitForAll()
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 6.0)
    }
}
