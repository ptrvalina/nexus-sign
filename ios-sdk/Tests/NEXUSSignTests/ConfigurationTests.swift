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
}
