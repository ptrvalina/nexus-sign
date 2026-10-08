import XCTest
import CryptoKit
@testable import NEXUSSign

/// Device protocols v1 must match Auth Core and Android byte for byte
/// (auth-core/test-vectors/device-protocols-v1.json, generated independently
/// in Node.js), or requests would be rejected and offline codes never match.
final class DeviceProtocolTests: XCTestCase {

    private func loadVectors() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "device-protocols-v1", withExtension: "json"))
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func hex(_ string: String) -> Data {
        var data = Data()
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            data.append(UInt8(string[index..<next], radix: 16)!)
            index = next
        }
        return data
    }

    func testRequestSigningInputMatchesVectorsAndSampleSignaturesVerify() throws {
        let section = try XCTUnwrap(try loadVectors()["device_request"] as? [String: Any])
        let key = try P256.Signing.PublicKey(pemRepresentation: try XCTUnwrap(section["auth_public_key_pem"] as? String))
        for request in try XCTUnwrap(section["requests"] as? [[String: Any]]) {
            let name = request["name"] as? String ?? "?"
            let input = DeviceProtocol.requestSigningInput(
                method: try XCTUnwrap(request["method"] as? String),
                path: try XCTUnwrap(request["path"] as? String),
                timestamp: try XCTUnwrap(request["timestamp"] as? String),
                nonce: try XCTUnwrap(request["nonce"] as? String),
                credentialID: try XCTUnwrap(request["credential_id"] as? String),
                body: Data(try XCTUnwrap(request["body"] as? String).utf8)
            )
            XCTAssertEqual(input, Data(base64Encoded: try XCTUnwrap(request["signing_input_base64"] as? String)), name)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request["sample_signature_der_base64"] as? String))))
            XCTAssertTrue(key.isValidSignature(signature, for: input), name)
        }
    }

    func testOfflineKeyAgreementDerivationTagAndCodeMatchVectors() throws {
        let offline = try XCTUnwrap(try loadVectors()["offline"] as? [String: Any])
        let device = try P256.KeyAgreement.PrivateKey(rawRepresentation: hex(try XCTUnwrap(offline["device_private_scalar_hex"] as? String)))
        let server = try P256.KeyAgreement.PublicKey(pemRepresentation: try XCTUnwrap(offline["server_public_key_pem"] as? String))
        let shared = try device.sharedSecretFromKeyAgreement(with: server).withUnsafeBytes { Data($0) }
        XCTAssertEqual(shared, hex(try XCTUnwrap(offline["shared_secret_hex"] as? String)))

        let credentialID = try XCTUnwrap(offline["credential_id"] as? String)
        let key = DeviceProtocol.deriveOfflineKey(sharedSecret: shared, credentialID: credentialID)
        XCTAssertEqual(key.withUnsafeBytes { Data($0) }, hex(try XCTUnwrap(offline["offline_key_hex"] as? String)))

        for confirmation in try XCTUnwrap(offline["confirmations"] as? [[String: Any]]) {
            let name = confirmation["name"] as? String ?? "?"
            let payload = try DeviceProtocol.qrPayloadBytes(try XCTUnwrap(confirmation["qr_payload"] as? String))
            XCTAssertEqual(payload, Data(base64Encoded: try XCTUnwrap(confirmation["canonical_base64"] as? String)), name)
            let tag = DeviceProtocol.offlineTag(key: key, canonicalPayload: payload)
            XCTAssertEqual(tag, Data(base64Encoded: try XCTUnwrap(confirmation["tag_base64"] as? String)), name)
            XCTAssertEqual(DeviceProtocol.offlineCode(tag: tag), confirmation["code"] as? String, name)
            XCTAssertNoThrow(try SignedPayload.parse(payload), name)
        }
    }

    func testUnknownQRFormatsAreRejected() {
        XCTAssertThrowsError(try DeviceProtocol.qrPayloadBytes("https://example.com"))
        XCTAssertThrowsError(try DeviceProtocol.qrPayloadBytes("NXS1.***"))
    }
}
