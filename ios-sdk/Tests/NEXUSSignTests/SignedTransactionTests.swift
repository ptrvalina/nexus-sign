import XCTest
@testable import NEXUSSign

/// Runs the shared WYSIWYS vectors (auth-core/test-vectors/signed-payload-v1.json,
/// bundled as a test resource) through the iOS parser. Identical cases run in
/// the Android SDK and in Auth Core, so the three implementations cannot drift.
final class SignedTransactionTests: XCTestCase {

    private func loadVectors() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "signed-payload-v1", withExtension: "json"))
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        return try XCTUnwrap(object as? [String: Any])
    }

    private func bytes(_ base64: Any?) throws -> Data {
        try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(base64 as? String)))
    }

    func testValidVectorsParseToTheSignedFields() throws {
        let valid = try XCTUnwrap(try loadVectors()["valid"] as? [[String: Any]])
        XCTAssertFalse(valid.isEmpty)
        for vector in valid {
            let name = vector["name"] as? String ?? "?"
            let fields = try XCTUnwrap(vector["fields"] as? [String: Any])
            let signed = try SignedPayload.parse(try bytes(vector["canonical_base64"]))
            XCTAssertEqual(signed.amountMinor, fields["amount_minor"] as? String, name)
            XCTAssertEqual(signed.currency, fields["currency"] as? String, name)
            XCTAssertEqual(signed.beneficiary, fields["beneficiary"] as? [String: String], name)
            XCTAssertEqual(signed.transactionReference, fields["transaction_reference"] as? String, name)
            XCTAssertEqual(signed.expiresAt, fields["expires_at"] as? String, name)
            XCTAssertEqual(signed.policyVersion, fields["policy_version"] as? String, name)
        }
    }

    func testInvalidVectorsAreRejectedWithTheExpectedReason() throws {
        let invalid = try XCTUnwrap(try loadVectors()["invalid"] as? [[String: Any]])
        XCTAssertGreaterThanOrEqual(invalid.count, 10)
        for vector in invalid {
            let name = vector["name"] as? String ?? "?"
            do {
                _ = try SignedPayload.parse(try bytes(vector["canonical_base64"]))
                XCTFail("accepted invalid vector: \(name)")
            } catch let rejected as SignedPayload.Rejected {
                XCTAssertEqual(rejected.reason, vector["reason"] as? String, name)
            }
        }
    }

    func testResponseFieldsThatDisagreeWithTheSignedBytesAreRefused() throws {
        let block = try XCTUnwrap(try loadVectors()["response_mismatch"] as? [String: Any])
        let baseB64 = try XCTUnwrap(block["base_canonical_base64"] as? String)
        let signed = try SignedPayload.parse(try bytes(baseB64))
        let good = AuthorizationEnvelope(
            authorizationId: signed.authorizationId, nexusId: signed.nexusId, credentialId: signed.credentialId,
            transactionReference: signed.transactionReference, operationType: signed.operationType,
            amountMinor: signed.amountMinor, currency: signed.currency, beneficiary: signed.beneficiary,
            policyReference: signed.policyReference, policyVersion: signed.policyVersion,
            issuedAt: try XCTUnwrap(SignedPayload.parseTimestamp(signed.issuedAt)),
            expiresAt: try XCTUnwrap(SignedPayload.parseTimestamp(signed.expiresAt)),
            canonicalPayloadHash: try XCTUnwrap(block["base_canonical_sha256"] as? String),
            canonicalPayloadBase64: baseB64
        )
        XCTAssertEqual(try SignedPayload.verify(good), signed)

        for mismatch in try XCTUnwrap(block["cases"] as? [[String: Any]]) {
            var tampered = good
            switch mismatch["field"] as? String {
            case "amountMinor": tampered.amountMinor = try XCTUnwrap(mismatch["value"] as? String)
            case "currency": tampered.currency = try XCTUnwrap(mismatch["value"] as? String)
            case "beneficiary": tampered.beneficiary = try XCTUnwrap(mismatch["value"] as? [String: String])
            case "transactionReference": tampered.transactionReference = try XCTUnwrap(mismatch["value"] as? String)
            case "expiresAt": tampered.expiresAt = try XCTUnwrap(SignedPayload.parseTimestamp(try XCTUnwrap(mismatch["value"] as? String)))
            case "authorizationId": tampered.authorizationId = try XCTUnwrap(mismatch["value"] as? String)
            case "canonicalPayloadHash": tampered.canonicalPayloadHash = try XCTUnwrap(mismatch["value"] as? String)
            default: XCTFail("unknown field \(String(describing: mismatch["field"]))")
            }
            XCTAssertThrowsError(try SignedPayload.verify(tampered), mismatch["name"] as? String ?? "?") { error in
                XCTAssertEqual((error as? SignedPayload.Rejected)?.reason, "response_mismatch")
            }
        }
    }

    func testAmountsAreFormattedWithIntegerArithmetic() throws {
        for vector in try XCTUnwrap(try loadVectors()["amount_formatting"] as? [[String: Any]]) {
            let digits = try XCTUnwrap((vector["fraction_digits"] as? NSNumber)?.intValue)
            XCTAssertEqual(
                SignedPayload.formatMinorUnits(try XCTUnwrap(vector["amount_minor"] as? String), fractionDigits: digits),
                vector["expected"] as? String
            )
        }
        XCTAssertEqual(SignedPayload.fractionDigits(currency: "PLN"), 2)
        XCTAssertEqual(SignedPayload.fractionDigits(currency: "JPY"), 0)
        XCTAssertEqual(SignedPayload.fractionDigits(currency: "KWD"), 3)
        // ISO 4217, where CLDR (and so NumberFormatter) differs.
        XCTAssertEqual(SignedPayload.fractionDigits(currency: "RSD"), 2)
        XCTAssertEqual(SignedPayload.fractionDigits(currency: "IQD"), 3)
        XCTAssertEqual(SignedPayload.fractionDigits(currency: "CLF"), 4)
    }

    func testPromptTextAndBeneficiaryDisplayMatchTheSharedVectors() throws {
        let valid = try XCTUnwrap(try loadVectors()["valid"] as? [[String: Any]])
        for vector in valid {
            let name = vector["name"] as? String ?? "?"
            let signed = try SignedPayload.parse(try bytes(vector["canonical_base64"]))
            XCTAssertEqual(signed.beneficiaryDisplay, vector["beneficiary_display"] as? String, name)
            XCTAssertEqual(signed.confirmationText, vector["confirmation_text"] as? String, name)
        }
        let block = try XCTUnwrap(try loadVectors()["response_mismatch"] as? [String: Any])
        let signed = try SignedPayload.parse(try bytes(block["base_canonical_base64"]))
        XCTAssertEqual(signed.confirmationText, "1250.00 PLN → PL61109010140000071219812874 · Jan Kowalski\ntransfer • BANK-2026-000001")
    }

    /// Auth Core sends timestamps with milliseconds, which JSONDecoder's default
    /// and `.iso8601` strategies both reject.
    func testAuthorizationResponseWithMillisecondTimestampsDecodesAndVerifies() throws {
        let block = try XCTUnwrap(try loadVectors()["response_mismatch"] as? [String: Any])
        let baseB64 = try XCTUnwrap(block["base_canonical_base64"] as? String)
        let signed = try SignedPayload.parse(try bytes(baseB64))
        let response: [String: Any] = [
            "authorizationId": signed.authorizationId, "nexusId": signed.nexusId, "credentialId": signed.credentialId,
            "transactionReference": signed.transactionReference, "operationType": signed.operationType,
            "amountMinor": signed.amountMinor, "currency": signed.currency, "beneficiary": signed.beneficiary,
            "policyReference": signed.policyReference, "policyVersion": signed.policyVersion,
            "canonicalPayloadHash": try XCTUnwrap(block["base_canonical_sha256"] as? String),
            "canonicalPayloadBase64": baseB64,
            "issuedAt": signed.issuedAt, "expiresAt": signed.expiresAt, "state": "PENDING_USER",
            "nonce": signed.nonce, "signature": NSNull(), "verifiedAt": NSNull(),
        ]
        let data = try JSONSerialization.data(withJSONObject: response)
        let authorization = try JSONDecoder.nexus().decode(NexusAuthorization.self, from: data)
        XCTAssertEqual(try authorization.signedTransaction(), signed)
        XCTAssertEqual(authorization.displayAmount, "1250.00 PLN")
    }

    /// The protocol 1 vectors still pin the phrase derivation: protocol 2's
    /// seed is the same PBKDF2 output as the protocol 1 verifier, and the
    /// phrase is normalized the same way. Protocol 2 itself is covered by
    /// RecoveryProtocolTests (recovery-v2.json).
    func testRecoverySeedMatchesTheProtocol1Derivation() throws {
        let recovery = try XCTUnwrap(try loadVectors()["recovery"] as? [String: Any])
        let salt = try bytes(recovery["salt_base64"])
        let iterations = try XCTUnwrap((recovery["iterations"] as? NSNumber)?.intValue)
        XCTAssertEqual((recovery["key_length"] as? NSNumber)?.intValue, RecoveryProtocol.keyLength)
        let phrase = try XCTUnwrap(recovery["phrase"] as? [String])
        let seed = RecoveryProtocol.seed(phrase: phrase, salt: salt, iterations: iterations)
        XCTAssertEqual(seed, try bytes(recovery["verifier_base64"]))
        let sloppy = try XCTUnwrap(recovery["phrase_unnormalized"] as? [String])
        XCTAssertEqual(RecoveryProtocol.seed(phrase: sloppy, salt: salt, iterations: iterations), seed)
    }
}
