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
    static func qrPayloadBytes(_ qrPayload: String) throws -> Data {
        let text = qrPayload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix(qrPrefix) else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_qr", detail: "unknown QR format")
        }
        var base64 = String(text.dropFirst(qrPrefix.count))
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64), !data.isEmpty else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_qr", detail: "QR payload is not base64url")
        }
        return data
    }
}
