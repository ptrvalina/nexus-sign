import XCTest
import CryptoKit
@testable import NEXUSSign

/// Secure push v1 must match Auth Core and Android byte for byte
/// (auth-core/test-vectors/secure-push-v1.json, generated independently in
/// Node.js), or the app could not open a single message.
final class SecurePushTests: XCTestCase {

    private func loadVectors() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "secure-push-v1", withExtension: "json"))
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

    private func envelope(_ object: Any?) throws -> NexusPushEnvelope {
        let data = try JSONSerialization.data(withJSONObject: try XCTUnwrap(object))
        return try JSONDecoder().decode(NexusPushEnvelope.self, from: data)
    }

    private func pushKey(_ vectors: [String: Any]) throws -> (SymmetricKey, String) {
        let agreement = try XCTUnwrap(vectors["key_agreement"] as? [String: Any])
        let credentialID = try XCTUnwrap(agreement["credential_id"] as? String)
        return (SymmetricKey(data: hex(try XCTUnwrap(agreement["push_key_hex"] as? String))), credentialID)
    }

    func testKeyAgreementMatchesVectors() throws {
        let agreement = try XCTUnwrap(try loadVectors()["key_agreement"] as? [String: Any])
        let device = try P256.KeyAgreement.PrivateKey(rawRepresentation: hex(try XCTUnwrap(agreement["device_private_scalar_hex"] as? String)))
        let server = try P256.KeyAgreement.PublicKey(pemRepresentation: try XCTUnwrap(agreement["server_public_key_pem"] as? String))
        let shared = try device.sharedSecretFromKeyAgreement(with: server).withUnsafeBytes { Data($0) }
        XCTAssertEqual(shared, hex(try XCTUnwrap(agreement["shared_secret_hex"] as? String)))

        let key = PushProtocol.derivePushKey(sharedSecret: shared, credentialID: try XCTUnwrap(agreement["credential_id"] as? String))
        XCTAssertEqual(key.withUnsafeBytes { Data($0) }, hex(try XCTUnwrap(agreement["push_key_hex"] as? String)))
        XCTAssertEqual(PushProtocol.keyID(key), agreement["key_id"] as? String)
        XCTAssertEqual(SubjectPublicKeyInfo.pem(fromRawECPoint: device.publicKey.x963Representation) + "\n",
                       try XCTUnwrap(agreement["device_public_key_pem"] as? String))
    }

    func testEveryVectorMessageOpensAndItsReceiptMatches() throws {
        let vectors = try loadVectors()
        let (key, credentialID) = try pushKey(vectors)
        for message in try XCTUnwrap(vectors["messages"] as? [[String: Any]]) {
            let name = message["name"] as? String ?? "?"
            let sealed = try envelope(message["envelope"])
            let plaintext = try PushProtocol.open(sealed, key: key)
            XCTAssertEqual(String(decoding: plaintext, as: UTF8.self), message["plaintext_utf8"] as? String, name)
            XCTAssertEqual(PushProtocol.associatedData(messageID: sealed.id, credentialID: credentialID),
                           Data(try XCTUnwrap(message["aad_utf8"] as? String).utf8), name)
            XCTAssertEqual(PushProtocol.receipt(key: key, messageID: sealed.id, credentialID: credentialID), message["receipt"] as? String, name)
        }
    }

    func testEveryInvalidVectorIsRefused() throws {
        let vectors = try loadVectors()
        let (key, _) = try pushKey(vectors)
        for invalid in try XCTUnwrap(vectors["invalid"] as? [[String: Any]]) {
            let name = invalid["name"] as? String ?? "?"
            XCTAssertThrowsError(try PushProtocol.open(try envelope(invalid["envelope"]), key: key), name)
        }
    }

    func testEnvelopeIsReadFromTheAPNsPayloadOnly() throws {
        let vectors = try loadVectors()
        let first = try XCTUnwrap((vectors["messages"] as? [[String: Any]])?.first)
        let userInfo: [AnyHashable: Any] = ["aps": ["alert": ["title": "New message"], "mutable-content": 1], "nexus": first["envelope"] as Any]
        XCTAssertEqual(NexusPushEnvelope(userInfo: userInfo)?.id, first["message_id"] as? String)
        XCTAssertNil(NexusPushEnvelope(userInfo: ["aps": ["alert": "Hello"]]))
        XCTAssertNil(NexusPushEnvelope(userInfo: ["nexus": "not an object"]))
    }

    /// Finding D-08: receipts go through a session that enforces the
    /// configured pins, not URLSession.shared.
    func testReceiptsUseThePinnedSession() {
        let pins: Set<String> = ["sha256/" + Data(repeating: 1, count: 32).base64EncodedString(),
                                 "sha256/" + Data(repeating: 2, count: 32).base64EncodedString()]
        let pinned = NEXUSSignPushReader(bankID: "pin-test", certificatePins: pins)
        let session = pinned.receiptSession(nil)
        XCTAssertFalse(session === URLSession.shared)
        XCTAssertTrue(session.delegate is CertificatePinning.Delegate)
        XCTAssertTrue(NEXUSSignPushReader(bankID: "pin-test").receiptSession(nil) === URLSession.shared, "without pins: system trust only")
        let own = URLSession(configuration: .ephemeral)
        XCTAssertTrue(pinned.receiptSession(own) === own, "a session the app passes is used as given")
    }
}
