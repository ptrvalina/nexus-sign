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

    /// Offline v3 (finding D-01): the key in the QR code, the secret and the
    /// key derived from it are different for every authorization.
    func testOfflineV3PerAuthorizationKeysMatchVectors() throws {
        let section = try XCTUnwrap(try loadVectors()["offline_v3"] as? [String: Any])
        let device = try P256.KeyAgreement.PrivateKey(rawRepresentation: hex(try XCTUnwrap(section["device_private_scalar_hex"] as? String)))
        let credentialID = try XCTUnwrap(section["credential_id"] as? String)
        var keys = Set<Data>()
        for confirmation in try XCTUnwrap(section["confirmations"] as? [[String: Any]]) {
            let name = confirmation["name"] as? String ?? "?"
            let qr = try XCTUnwrap(confirmation["qr_payload"] as? String)
            XCTAssertEqual(try DeviceProtocol.qrPayloadVersion(qr), 3, name)
            let payload = try DeviceProtocol.qrPayloadBytes(qr)
            XCTAssertEqual(payload, Data(base64Encoded: try XCTUnwrap(confirmation["canonical_base64"] as? String)), name)
            let serverPEM = try XCTUnwrap(try DeviceProtocol.qrServerPublicKeyPEM(qr), name)
            let expectedServer = try P256.KeyAgreement.PublicKey(pemRepresentation: try XCTUnwrap(confirmation["server_public_key_pem"] as? String))
            XCTAssertEqual(try P256.KeyAgreement.PublicKey(pemRepresentation: serverPEM).rawRepresentation, expectedServer.rawRepresentation, name)
            let shared = try device.sharedSecretFromKeyAgreement(with: expectedServer).withUnsafeBytes { Data($0) }
            XCTAssertEqual(shared, hex(try XCTUnwrap(confirmation["shared_secret_hex"] as? String)), name)
            let key = DeviceProtocol.deriveOfflineKeyPerAuthorization(sharedSecret: shared, credentialID: credentialID,
                                                                       authorizationID: try XCTUnwrap(confirmation["authorization_id"] as? String))
            let keyBytes = key.withUnsafeBytes { Data($0) }
            XCTAssertEqual(keyBytes, hex(try XCTUnwrap(confirmation["offline_key_hex"] as? String)), name)
            let tag = DeviceProtocol.offlineTag(key: key, canonicalPayload: payload)
            XCTAssertEqual(tag, Data(base64Encoded: try XCTUnwrap(confirmation["tag_base64"] as? String)), name)
            XCTAssertEqual(DeviceProtocol.offlineCode(tag: tag), confirmation["code"] as? String, name)
            keys.insert(keyBytes)
        }
        XCTAssertEqual(keys.count, 2, "a secret taken for one authorization does not serve another")
    }

    func testV3QRCodesWithoutAValidKeyAreRejected() throws {
        let section = try XCTUnwrap(try loadVectors()["offline_v3"] as? [String: Any])
        let qr = try XCTUnwrap((section["confirmations"] as? [[String: Any]])?.first?["qr_payload"] as? String)
        let body = qr.split(separator: ".")[1]
        XCTAssertThrowsError(try DeviceProtocol.qrPayloadBytes("NXS3.\(body)"), "no key part")
        XCTAssertThrowsError(try DeviceProtocol.qrServerPublicKeyPEM("NXS3.\(body).AAAA"), "not a P-256 key")
        XCTAssertThrowsError(try DeviceProtocol.qrPayloadBytes("NXS2.\(body).AAAA"), "v2 has one part")
        XCTAssertNil(try DeviceProtocol.qrServerPublicKeyPEM("NXS2.\(body)"))
    }

    func testUnknownQRFormatsAreRejected() {
        XCTAssertThrowsError(try DeviceProtocol.qrPayloadBytes("https://example.com"))
        XCTAssertThrowsError(try DeviceProtocol.qrPayloadBytes("NXS1.***"))
    }
}
