import XCTest
@testable import NEXUSSign

/// Runs the shared payment mandate terms vectors
/// (auth-core/test-vectors/mandate-terms-v1.json): the SDK accepts the terms
/// Auth Core builds, field for field, and refuses the others with the
/// expected reason before anything is shown or signed. Same vectors as
/// MandateTermsVectorsTest in the Android SDK.
final class MandateTermsVectorsTests: XCTestCase {
    private func vectors() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "mandate-terms-v1", withExtension: "json"))
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func parse(_ v: [String: Any]) throws -> NexusMandateTerms {
        try MandateTermsParser.parse(termsBase64: try XCTUnwrap(v["termsBase64"] as? String), termsHash: try XCTUnwrap(v["termsHash"] as? String),
                                     mandateId: try XCTUnwrap(v["mandateId"] as? String), credentialId: try XCTUnwrap(v["credentialId"] as? String))
    }

    func testValidTermsParseToTheSignedFields() throws {
        let valid = try XCTUnwrap(try vectors()["valid"] as? [[String: Any]])
        XCTAssertEqual(valid.count, 3)
        for v in valid {
            let name = v["name"] as? String ?? "?"
            let expected = try XCTUnwrap(v["expected"] as? [String: Any])
            let terms = try parse(v)
            XCTAssertEqual(terms.perPaymentLimitMinor, expected["per_payment_limit_minor"] as? String, name)
            XCTAssertEqual(terms.totalLimitMinor, expected["total_limit_minor"] as? String, name)
            XCTAssertEqual(terms.payee, expected["payee"] as? [String: String], name)
            XCTAssertEqual(terms.currency, expected["currency"] as? String, name)
            XCTAssertEqual(terms.frequency, expected["frequency"] as? String, name)
            XCTAssertEqual(terms.validUntil, expected["valid_until"] as? String, name)
            XCTAssertEqual(terms.mandateReference, expected["mandate_reference"] as? String, name)
        }
    }

    func testInvalidTermsAreRefusedWithTheExpectedReason() throws {
        let invalid = try XCTUnwrap(try vectors()["invalid"] as? [[String: Any]])
        XCTAssertEqual(invalid.count, 17)
        for v in invalid {
            let name = v["name"] as? String ?? "?"
            do {
                _ = try parse(v)
                XCTFail("accepted: \(name)")
            } catch let rejected as SignedPayload.Rejected {
                XCTAssertEqual(rejected.reason, v["reason"] as? String, name)
            }
        }
    }

    func testThePromptTextComesFromTheSignedTerms() throws {
        let valid = try XCTUnwrap(try vectors()["valid"] as? [[String: Any]])
        let text = try parse(valid[1]).confirmationText
        XCTAssertTrue(text.contains("Up to 150.00 EUR per payment, yearly"), text)
        XCTAssertTrue(text.contains("At most 1200.00 EUR in total"), text)
        XCTAssertTrue(text.contains("iban: DE89370400440532013000"), text)
    }
}
