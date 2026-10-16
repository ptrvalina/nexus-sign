import XCTest
@testable import NEXUSSign

final class ConfigurationTests: XCTestCase {
    func testConfigurationPreservesBankScope() {
        let config = NEXUSSignConfig(
            bankID: "bank.example",
            baseURL: URL(string: "https://auth.example.test")!,
            sessionToken: { _ in "short-lived-session-token" }
        )

        XCTAssertEqual(config.bankID, "bank.example")
        XCTAssertEqual(config.baseURL.absoluteString, "https://auth.example.test")
        XCTAssertEqual(config.requestTimeout, 10)
    }

    /// FI-006: pins use OkHttp's `sha256/<base64>` form; a configuration with
    /// pins keeps them (the initializer refuses fewer than two).
    func testCertificatePinFormat() {
        let pinA = "sha256/" + String(repeating: "A", count: 43) + "="
        let pinB = "sha256/" + String(repeating: "B", count: 43) + "="
        XCTAssertTrue(CertificatePinning.isWellFormedPin(pinA))
        XCTAssertFalse(CertificatePinning.isWellFormedPin("sha1/" + String(repeating: "A", count: 27) + "="))
        XCTAssertFalse(CertificatePinning.isWellFormedPin("sha256/" + String(repeating: "A", count: 40)))
        XCTAssertFalse(CertificatePinning.isWellFormedPin(String(repeating: "A", count: 43) + "="))
        let config = NEXUSSignConfig(bankID: "b", baseURL: URL(string: "https://auth.example.test")!, sessionToken: { _ in "t" }, certificatePins: [pinA, pinB])
        XCTAssertEqual(config.certificatePins, [pinA, pinB])
    }
}
