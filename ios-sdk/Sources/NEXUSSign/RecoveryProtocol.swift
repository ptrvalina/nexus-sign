import CommonCrypto
import CryptoKit
import Foundation

/// Recovery protocol 2, identical on iOS, Android and Auth Core (vectors in
/// `recovery-v2.json`, specification in docs/protocol/recovery-protocol-v2.md):
///
///     seed    = PBKDF2-HMAC-SHA256(normalized phrase, salt, iterations, 32)
///     wrapKey = HKDF-SHA256(seed, salt "NEXUS-SIGN/RECOVERY-WRAP/v2", info nexusId)
///     wrapped = iv || AES-256-GCM(wrapKey, iv, recovery private scalar, associatedData)
///
/// The recovery key pair is created in memory (it must be restorable on a new
/// device, so it cannot live in the Secure Enclave); its private half exists on
/// the device only while a phrase is set up or used, and Auth Core holds only
/// the public key and `wrapped`.
enum RecoveryProtocol {
    static let version = 2
    static let kdf = "PBKDF2-HMAC-SHA256"
    static let keyLength = 32
    static let wrappedLength = 12 + 32 + 16

    static func seed(phrase: [String], salt: Data, iterations: Int) -> Data {
        let password = RecoveryPhrase.normalized(phrase).joined(separator: " ")
        return pbkdf2(password: Data(password.utf8), salt: salt, iterations: iterations, keyLength: keyLength)
    }

    static func wrapKey(seed: Data, nexusID: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: seed),
                               salt: Data("NEXUS-SIGN/RECOVERY-WRAP/v2".utf8),
                               info: Data(nexusID.utf8),
                               outputByteCount: 32)
    }

    static func associatedData(nexusID: String, recoveryPublicKeySPKI: Data) -> Data {
        Data("NEXUS-SIGN/RECOVERY-KEY/v2\n\(nexusID)\n\(sha256Hex(recoveryPublicKeySPKI))".utf8)
    }

    static func wrap(_ privateKey: P256.Signing.PrivateKey, wrapKey: SymmetricKey, associatedData: Data, nonce: AES.GCM.Nonce = AES.GCM.Nonce()) throws -> Data {
        let box = try AES.GCM.seal(privateKey.rawRepresentation, using: wrapKey, nonce: nonce, authenticating: associatedData)
        guard let combined = box.combined, combined.count == wrappedLength else {
            throw NEXUSSignError.serverError(statusCode: 0, message: "Recovery key could not be wrapped")
        }
        return combined
    }

    /// The recovery private key; a wrong phrase fails the GCM tag.
    static func unwrap(_ wrapped: Data, wrapKey: SymmetricKey, associatedData: Data) throws -> P256.Signing.PrivateKey {
        guard wrapped.count == wrappedLength, let box = try? AES.GCM.SealedBox(combined: wrapped) else {
            throw NEXUSSignError.serverError(statusCode: 0, message: "Invalid wrapped recovery key")
        }
        guard let scalar = try? AES.GCM.open(box, using: wrapKey, authenticating: associatedData) else {
            throw NEXUSSignError.invalidRecoveryPhrase
        }
        return try P256.Signing.PrivateKey(rawRepresentation: scalar)
    }

    /// Signed with the biometric signing key to register a recovery key.
    static func setupSigningInput(nexusID: String, credentialID: String, saltBase64: String, recoveryPublicKeySPKI: Data, wrapped: Data) -> Data {
        Data(["NEXUS-SIGN/RECOVERY-SETUP/v2", nexusID, credentialID, saltBase64, sha256Hex(recoveryPublicKeySPKI), sha256Hex(wrapped)]
            .joined(separator: "\n").utf8)
    }

    /// Signed with the recovery key: binds the proof to the session and the new device key.
    static func proofSigningInput(sessionID: String, nonceBase64: String, nexusID: String, newSigningKeySPKI: Data) -> Data {
        Data(["NEXUS-SIGN/RECOVERY-PROOF/v2", sessionID, nonceBase64, nexusID, sha256Hex(newSigningKeySPKI)]
            .joined(separator: "\n").utf8)
    }

    /// ECDSA P-256 / SHA-256, DER.
    static func sign(_ input: Data, with privateKey: P256.Signing.PrivateKey) throws -> Data {
        try privateKey.signature(for: input).derRepresentation
    }

    /// SubjectPublicKeyInfo DER of a PEM public key.
    static func spki(fromPEM pem: String) -> Data? {
        let body = pem.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("-----") }.joined()
        return Data(base64Encoded: body)
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// PBKDF2-HMAC-SHA256 from CommonCrypto. The callers pass parameters
    /// already checked against the supported range (NEXUSSignSDK.validated).
    private static func pbkdf2(password: Data, salt: Data, iterations: Int, keyLength: Int) -> Data {
        precondition(!password.isEmpty && !salt.isEmpty && (1...Int(UInt32.max)).contains(iterations), "invalid PBKDF2 parameters")
        var derived = Data(count: keyLength)
        let status = derived.withUnsafeMutableBytes { out in
            password.withUnsafeBytes { secret in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         secret.bindMemory(to: CChar.self).baseAddress, secret.count,
                                         saltBytes.bindMemory(to: UInt8.self).baseAddress, saltBytes.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                                         out.bindMemory(to: UInt8.self).baseAddress, keyLength)
                }
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 failed (\(status))")
        return derived
    }
}
