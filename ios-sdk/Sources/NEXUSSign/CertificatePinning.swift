import CryptoKit
import Foundation
import Security

/// Optional public-key pinning for the Auth Core host (FI-006).
///
/// A pin is `sha256/` followed by the base64 SHA-256 of a certificate's
/// SubjectPublicKeyInfo, the format of OkHttp's CertificatePinner, so one pin
/// list serves both SDKs. The system's trust evaluation runs first; pinning
/// only narrows which valid chains are accepted. A chain matches when any of
/// its certificates (leaf, intermediate or root) has a pinned key.
enum CertificatePinning {

    /// `.shared` without pins; otherwise an ephemeral session whose delegate
    /// enforces them.
    static func session(pins: Set<String>) -> URLSession {
        guard !pins.isEmpty else { return .shared }
        return URLSession(configuration: .ephemeral, delegate: Delegate(pins: pins), delegateQueue: nil)
    }

    static func isWellFormedPin(_ pin: String) -> Bool {
        guard pin.hasPrefix("sha256/"), let digest = Data(base64Encoded: String(pin.dropFirst(7))) else { return false }
        return digest.count == 32
    }

    /// The pin of a certificate's public key, or nil for a key type without
    /// a known SubjectPublicKeyInfo header.
    static func pin(of certificate: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(certificate),
              let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              let type = attributes[kSecAttrKeyType] as? String,
              let bits = attributes[kSecAttrKeySizeInBits] as? Int,
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let header = spkiHeader(keyType: type, bits: bits) else { return nil }
        let digest = SHA256.hash(data: Data(header) + raw)
        return "sha256/" + Data(digest).base64EncodedString()
    }

    /// DER prefixes that turn the key bytes from SecKeyCopyExternalRepresentation
    /// (an uncompressed EC point, or a PKCS#1 RSAPublicKey) into a
    /// SubjectPublicKeyInfo (RFC 5480, RFC 3279).
    private static func spkiHeader(keyType: String, bits: Int) -> [UInt8]? {
        let ec = kSecAttrKeyTypeECSECPrimeRandom as String
        let rsa = kSecAttrKeyTypeRSA as String
        if keyType == ec {
            switch bits {
            case 256:
                return [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]
            case 384:
                return [0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00]
            default:
                return nil
            }
        }
        if keyType == rsa {
            switch bits {
            case 2048:
                return [0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
                        0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00]
            case 3072:
                return [0x30, 0x82, 0x01, 0xa2, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
                        0x05, 0x00, 0x03, 0x82, 0x01, 0x8f, 0x00]
            case 4096:
                return [0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
                        0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00]
            default:
                return nil
            }
        }
        return nil
    }

    final class Delegate: NSObject, URLSessionDelegate {
        private let pins: Set<String>

        init(pins: Set<String>) { self.pins = pins }

        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            guard SecTrustEvaluateWithError(trust, nil),
                  let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  chain.contains(where: { CertificatePinning.pin(of: $0).map(pins.contains) ?? false }) else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        }
    }
}
