import XCTest
@testable import NEXUSSign

/// Offline confirmation v2: the pending signature queue and the QR prefixes.
/// Mirrors android-sdk OfflineSignatureQueueTest.
final class OfflineSignatureQueueTests: XCTestCase {
    private let a = "00000000-0000-4000-8000-00000000000a"
    private let b = "00000000-0000-4000-8000-00000000000b"
    private let c = "00000000-0000-4000-8000-00000000000c"

    private func freshDefaults() -> UserDefaults {
        let name = "OfflineSignatureQueueTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return defaults
    }

    func testKeepsOnlyWhatAuthCoreHasNotTakenOrRefused() async throws {
        let defaults = freshDefaults()
        let queue = OfflineSignatureQueue(bankID: "test", defaults: defaults, clock: { 1_000 })
        try queue.add(authorizationID: a, signature: Data("sig-a".utf8))
        try queue.add(authorizationID: b, signature: Data("sig-b".utf8))
        try queue.add(authorizationID: c, signature: Data("sig-c".utf8))
        let answers = [a: 200, b: 503, c: 409]
        let result = await queue.deliver { UploadOutcome.of(statusCode: answers[$0.authorizationId]!) }
        XCTAssertEqual(result, OfflineSignatureDelivery(delivered: 1, refused: 1, pending: 1))
        XCTAssertEqual(queue.pending().map(\.authorizationId), [b])
        XCTAssertEqual(OfflineSignatureQueue(bankID: "test", defaults: defaults, clock: { 1_000 }).pending().map(\.authorizationId), [b])
    }

    func testStatusClassification() {
        for code in [200, 202] { XCTAssertEqual(UploadOutcome.of(statusCode: code), .accepted) }
        for code in [400, 403, 404, 409, 422] { XCTAssertEqual(UploadOutcome.of(statusCode: code), .refused(statusCode: code)) }
        for code in [401, 429, 500, 503] { XCTAssertEqual(UploadOutcome.of(statusCode: code), .retry) }
    }

    func testOldItemsAreDroppedWithoutUpload() async throws {
        var now: Int64 = 1_000
        let queue = OfflineSignatureQueue(bankID: "test", defaults: freshDefaults(), clock: { now })
        try queue.add(authorizationID: a, signature: Data("first".utf8))
        try queue.add(authorizationID: a, signature: Data("second".utf8))
        XCTAssertEqual(queue.pending().count, 1)
        now += OfflineSignatureQueue.maxAgeSeconds + 1
        var uploads = 0
        let result = await queue.deliver { _ in uploads += 1; return .accepted }
        XCTAssertEqual(uploads, 0)
        XCTAssertEqual(result, OfflineSignatureDelivery(delivered: 0, refused: 1, pending: 0))
    }

    func testQRPrefixesVersionOneAndTwoCarryTheSameBytes() throws {
        let bytes = Data(#"{"a":"b"}"#.utf8)
        let body = bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        XCTAssertEqual(try DeviceProtocol.qrPayloadVersion("NXS1.\(body)"), 1)
        XCTAssertEqual(try DeviceProtocol.qrPayloadVersion("NXS2.\(body)"), 2)
        XCTAssertEqual(try DeviceProtocol.qrPayloadBytes("NXS1.\(body)"), bytes)
        XCTAssertEqual(try DeviceProtocol.qrPayloadBytes("NXS2.\(body)"), bytes)
        for unknown in ["NXS3.\(body)", "nxs2.\(body)", body] {
            XCTAssertThrowsError(try DeviceProtocol.qrPayloadBytes(unknown))
        }
    }
}
