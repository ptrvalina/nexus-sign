import Foundation
import CryptoKit

/// Device protocols v1, identical in Auth Core and the Android SDK (vectors in
/// `device-protocols-v1.json`):
///
/// - request signing input for the device authentication key;
/// - offline confirmation key derivation, tag and 8-digit code;
/// - the offline QR payload format.
enum DeviceProtocol {
    static let requestDomain = "NEXUS-SIGN/DEVICE-REQUEST/v1"
    static let offlineKDFSalt = "NEXUS-SIGN/OFFLINE/v1"
    static let offlineCodeDomain = "NEXUS-SIGN/OFFLINE-CODE/v1"
    static let qrPrefix = "NXS1."
    /// Offline confirmation v2: the same bytes; the device also signs them
    /// and uploads the signature later (deferred device signature).
    static let qrPrefixV2 = "NXS2."
    /// Offline confirmation v3 (finding D-01): after the canonical bytes, a
    /// `.` and Auth Core's P-256 key for this authorization (DER SPKI,
    /// base64url). The Secure Enclave agrees a secret with that key, so a
    /// secret taken from the app process serves this authorization only.
    static let qrPrefixV3 = "NXS3."
    static let offlineKDFSaltV3 = "NEXUS-SIGN/OFFLINE/v3"
    static let codeDigits = 8

    static func requestSigningInput(method: String, path: String, timestamp: String, nonce: String, credentialID: String, body: Data) -> Data {
        let bodyHash = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        let lines = [requestDomain, method.uppercased(), path, timestamp, nonce, credentialID, bodyHash]
        return Data(lines.joined(separator: "\n").utf8)
    }

    /// HKDF-SHA256 over the 32-byte ECDH secret, bound to the credential.
    static func deriveOfflineKey(sharedSecret: Data, credentialID: String) -> SymmetricKey {
        precondition(sharedSecret.count == 32, "ECDH shared secret must be 32 bytes")
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: Data(offlineKDFSalt.utf8),
            info: Data(credentialID.utf8),
            outputByteCount: 32
        )
    }

    /// Offline v3: HKDF-SHA256 bound to the credential and the authorization.
    static func deriveOfflineKeyPerAuthorization(sharedSecret: Data, credentialID: String, authorizationID: String) -> SymmetricKey {
        precondition(sharedSecret.count == 32, "ECDH shared secret must be 32 bytes")
        var info = Data(credentialID.utf8)
        info.append(0)
        info.append(contentsOf: Data(authorizationID.utf8))
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: Data(offlineKDFSaltV3.utf8),
            info: info,
            outputByteCount: 32
        )
    }

    static func offlineTag(key: SymmetricKey, canonicalPayload: Data) -> Data {
        var message = Data(offlineCodeDomain.utf8)
        message.append(0)
        message.append(contentsOf: SHA256.hash(data: canonicalPayload))
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
    }

    /// RFC 4226 dynamic truncation to 8 digits.
    static func offlineCode(tag: Data) -> String {
        let bytes = [UInt8](tag)
        let offset = Int(bytes[bytes.count - 1] & 0x0f)
        let binary = (UInt32(bytes[offset] & 0x7f) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
        let code = String(binary % 100_000_000)
        return String(repeating: "0", count: codeDigits - code.count) + code
    }

    /// The canonical authorization bytes carried by an offline QR code.
    /// 1 for `NXS1.`, 2 for `NXS2.`, 3 for `NXS3.`; anything else is refused.
    static func qrPayloadVersion(_ qrPayload: String) throws -> Int {
        let text = qrPayload.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix(qrPrefix) { return 1 }
        if text.hasPrefix(qrPrefixV2) { return 2 }
        if text.hasPrefix(qrPrefixV3) { return 3 }
        throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_qr", detail: "unknown QR format")
    }

    /// The parts after the prefix: one for v1 and v2, two for v3.
    private static func qrParts(_ qrPayload: String) throws -> (version: Int, parts: [Substring]) {
        let text = qrPayload.trimmingCharacters(in: .whitespacesAndNewlines)
        let version = try qrPayloadVersion(text)
        let parts = text.dropFirst(qrPrefix.count).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == (version == 3 ? 2 : 1) else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_qr", detail: "wrong number of QR parts")
        }
        return (version, parts)
    }

    private static func base64url(_ part: Substring, _ what: String) throws -> Data {
        guard part.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_qr", detail: "\(what) is not base64url")
        }
        var base64 = part.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64), !data.isEmpty else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_qr", detail: "\(what) is not base64url")
        }
        return data
    }

    static func qrPayloadBytes(_ qrPayload: String) throws -> Data {
        try base64url(try qrParts(qrPayload).parts[0], "QR payload")
    }

    /// Offline v3: Auth Core's key for this authorization, as PEM; `nil` for
    /// v1 and v2. Refused unless it is a valid P-256 public key.
    static func qrServerPublicKeyPEM(_ qrPayload: String) throws -> String? {
        let (version, parts) = try qrParts(qrPayload)
        guard version == 3 else { return nil }
        let spki = try base64url(parts[1], "server key")
        guard let key = try? P256.KeyAgreement.PublicKey(derRepresentation: spki) else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_qr", detail: "server key is not a P-256 public key")
        }
        return key.pemRepresentation
    }
}
