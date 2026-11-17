import XCTest
import CryptoKit
@testable import NEXUSSign

/// Recovery protocol 2 must match Android and Auth Core byte for byte
/// (vectors in recovery-v2.json, generated with Node.js), or a phrase set up
/// on one platform could not recover the identity on the other.
final class RecoveryProtocolTests: XCTestCase {
    private var v: [String: Any]!

    override func setUpWithError() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "recovery-v2", withExtension: "json"))
        v = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func str(_ key: String) -> String { v[key] as! String }
    private func hex(_ s: String) -> Data {
        var data = Data(); var index = s.startIndex
        while index < s.endIndex {
            let next = s.index(index, offsetBy: 2)
            data.append(UInt8(s[index..<next], radix: 16)!); index = next
        }
        return data
    }
    private var phrase: [String] { v["phrase"] as! [String] }
    private var salt: Data { Data(base64Encoded: str("salt_b64"))! }
    private var iterations: Int { (v["iterations"] as! NSNumber).intValue }
    private var recoverySPKI: Data { RecoveryProtocol.spki(fromPEM: str("recovery_public_key_pem"))! }
    private var proof: [String: String] { v["proof"] as! [String: String] }
    private func bytes(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

    func testSeedAndWrappingKeyMatchTheVectors() {
        let seed = RecoveryProtocol.seed(phrase: phrase, salt: salt, iterations: iterations)
        XCTAssertEqual(seed, hex(str("seed_hex")))
        XCTAssertEqual(bytes(RecoveryProtocol.wrapKey(seed: seed, nexusID: str("nexus_id"))), hex(str("wrap_key_hex")))
    }

    func testRecoveryKeyWrapsToTheVectorBytesAndUnwrapsBack() throws {
        let wrapKey = SymmetricKey(data: hex(str("wrap_key_hex")))
        let aad = RecoveryProtocol.associatedData(nexusID: str("nexus_id"), recoveryPublicKeySPKI: recoverySPKI)
        XCTAssertEqual(String(decoding: aad, as: UTF8.self), str("wrap_aad_utf8"))
        let key = try P256.Signing.PrivateKey(rawRepresentation: hex(str("recovery_private_scalar_hex")))
        XCTAssertEqual(key.publicKey.derRepresentation, recoverySPKI)
        let wrapped = try RecoveryProtocol.wrap(key, wrapKey: wrapKey, associatedData: aad,
                                                nonce: try AES.GCM.Nonce(data: hex(str("wrap_iv_hex"))))
        XCTAssertEqual(wrapped, Data(base64Encoded: str("wrapped_recovery_key_b64")))
        XCTAssertEqual(try RecoveryProtocol.unwrap(wrapped, wrapKey: wrapKey, associatedData: aad).rawRepresentation, key.rawRepresentation)
    }

    func testWrongPhraseOrAnotherIdentityCannotOpenTheWrappedKey() throws {
        let wrapped = Data(base64Encoded: str("wrapped_recovery_key_b64"))!
        let wrongPhrase = (v["invalid"] as! [[String: Any]])[0]["phrase"] as! [String]
        let wrongKey = RecoveryProtocol.wrapKey(seed: RecoveryProtocol.seed(phrase: wrongPhrase, salt: salt, iterations: iterations), nexusID: str("nexus_id"))
        XCTAssertThrowsError(try RecoveryProtocol.unwrap(wrapped, wrapKey: wrongKey,
                                                         associatedData: RecoveryProtocol.associatedData(nexusID: str("nexus_id"), recoveryPublicKeySPKI: recoverySPKI))) {
            guard case NEXUSSignError.invalidRecoveryPhrase? = $0 as? NEXUSSignError else { return XCTFail("\($0)") }
        }
        XCTAssertThrowsError(try RecoveryProtocol.unwrap(wrapped, wrapKey: SymmetricKey(data: hex(str("wrap_key_hex"))),
                                                         associatedData: RecoveryProtocol.associatedData(nexusID: "987654321", recoveryPublicKeySPKI: recoverySPKI))) {
            guard case NEXUSSignError.invalidRecoveryPhrase? = $0 as? NEXUSSignError else { return XCTFail("\($0)") }
        }
    }

    func testSetupAndProofSigningInputsMatchAndTheVectorProofVerifies() throws {
        let wrapped = Data(base64Encoded: str("wrapped_recovery_key_b64"))!
        let setup = RecoveryProtocol.setupSigningInput(nexusID: str("nexus_id"), credentialID: str("credential_id"), saltBase64: str("salt_b64"),
                                                       recoveryPublicKeySPKI: recoverySPKI, wrapped: wrapped)
        XCTAssertEqual(String(decoding: setup, as: UTF8.self), str("setup_signing_input_utf8"))
        let input = RecoveryProtocol.proofSigningInput(sessionID: proof["session_id"]!, nonceBase64: proof["nonce_b64"]!, nexusID: str("nexus_id"),
                                                       newSigningKeySPKI: RecoveryProtocol.spki(fromPEM: proof["new_signing_public_key_pem"]!)!)
        XCTAssertEqual(String(decoding: input, as: UTF8.self), proof["signing_input_utf8"])
        let publicKey = try P256.Signing.PublicKey(derRepresentation: recoverySPKI)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: Data(base64Encoded: proof["signature_der_b64"]!)!)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: input))
    }

    func testAFreshKeyRoundTripsThroughThePhrase() throws {
        let key = P256.Signing.PrivateKey()
        let spki = key.publicKey.derRepresentation
        let wrapKey = RecoveryProtocol.wrapKey(seed: RecoveryProtocol.seed(phrase: phrase, salt: salt, iterations: iterations), nexusID: "123456789")
        let aad = RecoveryProtocol.associatedData(nexusID: "123456789", recoveryPublicKeySPKI: spki)
        let restored = try RecoveryProtocol.unwrap(try RecoveryProtocol.wrap(key, wrapKey: wrapKey, associatedData: aad), wrapKey: wrapKey, associatedData: aad)
        let data = Data("probe".utf8)
        XCTAssertTrue(key.publicKey.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: try RecoveryProtocol.sign(data, with: restored)), for: data))
    }

    func testPhraseNormalisationAcceptsPastedInput() {
        let typed = ["  Abandon", "ABANDON\n", "abandon abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "About "]
        let words = RecoveryPhrase.normalized(typed)
        XCTAssertEqual(words.count, 12)
        XCTAssertTrue(RecoveryPhrase.isWellFormed(typed))
        XCTAssertFalse(RecoveryPhrase.isWellFormed(Array(words.dropLast()) + ["abandon"])) // checksum
        XCTAssertEqual(RecoveryProtocol.seed(phrase: typed, salt: salt, iterations: 1),
                       RecoveryProtocol.seed(phrase: words, salt: salt, iterations: 1))
    }

    /// Same cases as the Android SDK (finding D-10): Unicode White_Space
    /// separates words; a zero-width space does not.
    func testUnicodeSpacesSeparateWordsAsOnAndroid() {
        let allZero = Array(repeating: "abandon", count: 11) + ["about"]
        for space in ["\u{00A0}", "\u{3000}", "\u{2009}", "\u{202F}", "\u{2028}", "\u{0085}"] {
            XCTAssertEqual(RecoveryPhrase.normalized([allZero.joined(separator: space)]), allZero, space.unicodeScalars.first.map { String($0.value, radix: 16) } ?? "")
        }
        XCTAssertFalse(RecoveryPhrase.isWellFormed([allZero.joined(separator: "\u{200B}")]))
    }
}
