import CryptoKit
import Foundation

/// Wraps the 65-byte uncompressed P-256 point returned by
/// `SecKeyCopyExternalRepresentation` in a SubjectPublicKeyInfo header
/// (RFC 5480) and PEM-encodes it, the format Auth Core expects.
enum SubjectPublicKeyInfo {

    /// Fixed 26-byte prefix identifying an EC public key on the
    /// prime256v1 (secp256r1 / P-256) curve, per RFC 5480. Constant for
    /// every P-256 key; only the 65-byte point that follows varies.
    private static let p256Header: [UInt8] = [
        0x30, 0x59, 0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00,
    ]

    /// DER SubjectPublicKeyInfo of a P-256 key from its 65-byte point.
    static func der(fromRawECPoint rawPoint: Data) -> Data {
        Data(p256Header) + rawPoint
    }

    /// Fingerprint of a signing key: lowercase hex SHA-256 of its DER
    /// SubjectPublicKeyInfo (vectors in `bank-trust-v1.json`). The bank
    /// approves the device key by this value (bank credential trust v1).
    static func fingerprint(_ subjectPublicKeyInfo: Data) -> String {
        SHA256.hash(data: subjectPublicKeyInfo).map { String(format: "%02x", $0) }.joined()
    }

    static func pem(fromRawECPoint rawPoint: Data) -> String {
        let base64 = Self.der(fromRawECPoint: rawPoint).base64EncodedString()
        let wrapped = stride(from: 0, to: base64.count, by: 64).map { start -> Substring in
            let begin = base64.index(base64.startIndex, offsetBy: start)
            let end = base64.index(begin, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            return base64[begin..<end]
        }.joined(separator: "\n")

        return "-----BEGIN PUBLIC KEY-----\n\(wrapped)\n-----END PUBLIC KEY-----"
    }
}
