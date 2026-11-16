import XCTest
import CryptoKit
@testable import NEXUSSign

/// The signing key fingerprint the SDK reports to the bank's app must be the
/// value the bank's check computes (bank-trust-v1.json, generated in Node.js).
final class BankTrustVectorsTests: XCTestCase {

    func testSigningKeyFingerprintsMatchTheVectors() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "bank-trust-v1", withExtension: "json"))
        let vectors = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let cases = try XCTUnwrap(vectors["fingerprints"] as? [[String: Any]])
        XCTAssertEqual(cases.count, 2)
        for item in cases {
            let key = try P256.Signing.PublicKey(pemRepresentation: try XCTUnwrap(item["publicKeyPem"] as? String))
            // The Secure Enclave returns the 65-byte point; the SDK wraps it.
            let der = SubjectPublicKeyInfo.der(fromRawECPoint: key.x963Representation)
            XCTAssertEqual(der, try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(item["spkiDerBase64"] as? String))))
            XCTAssertEqual(SubjectPublicKeyInfo.fingerprint(der), item["signingKeySha256"] as? String)
        }
    }
}
