import XCTest
@testable import NEXUSSign

/// Finding D-11: failures that are not HTTP answers get their own cases
/// instead of `serverError(statusCode: 0 or 200, ...)`, and no internal error
/// type reaches the host app.
final class ErrorModelTests: XCTestCase {
    func testWrappedKeyOfTheWrongLengthIsAnInvalidServerResponse() {
        XCTAssertThrowsError(try RecoveryProtocol.unwrap(Data(count: 10), wrapKey: SymmetricKeyStub.key, associatedData: Data())) { error in
            guard case NEXUSSignError.invalidServerResponse(let detail) = error else { return XCTFail("got \(error)") }
            XCTAssertEqual(detail, "invalid wrapped recovery key")
        }
    }

    func testPushReceiptRefusesPlainHTTPAsAConfigurationError() async {
        let reader = NEXUSSignPushReader(bankID: "error-model-tests")
        let message = NexusPushMessage(messageId: UUID().uuidString, category: .security, title: "t", body: "b",
                                       authorizationId: nil, data: [:], sentAt: Date(), credentialId: UUID().uuidString)
        do {
            try await reader.sendReceipt(for: message, baseURL: URL(string: "http://auth.bank.example")!)
            XCTFail("sent over http")
        } catch NEXUSSignError.configurationInvalid(let detail) {
            XCTAssertEqual(detail, "Auth Core base URL must be https")
        } catch {
            XCTFail("got \(error)")
        }
    }

    func testEveryNewCaseHasADescription() {
        let cases: [NEXUSSignError] = [
            .invalidServerResponse(detail: "x"), .invalidRecoverySession(detail: "x"), .randomGenerationFailed(status: -1),
            .configurationInvalid(detail: "x"), .cryptographicOperationFailed(detail: "x"), .invalidArgument(detail: "x"),
        ]
        for error in cases { XCTAssertFalse((error.errorDescription ?? "").isEmpty, "\(error)") }
    }
}

import CryptoKit
private enum SymmetricKeyStub { static let key = SymmetricKey(size: .bits256) }
