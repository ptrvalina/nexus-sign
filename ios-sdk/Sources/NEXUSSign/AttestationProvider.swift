import Foundation
import DeviceCheck
import CryptoKit

/// Wraps Apple App Attest. The attestation lets Auth Core check that the key
/// was enrolled by a genuine Apple device running the bank's app as signed
/// for the configured App ID. It does not detect jailbreaks or debuggers.
///
/// This class only produces the attestation object; Auth Core verifies it
/// against Apple's App Attest root CA.
final class AttestationProvider {

    private let service = DCAppAttestService.shared

    var isSupported: Bool {
        service.isSupported
    }

    /// Generates a new App Attest key. A fresh key is attested at each
    /// enrolment and recovery; the SDK does not use App Attest assertions, so
    /// the key identifier is not stored.
    func generateAttestationKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyID, error in
                if let error {
                    continuation.resume(throwing: NEXUSSignError.attestationFailed(underlying: error))
                } else if let keyID {
                    continuation.resume(returning: keyID)
                } else {
                    continuation.resume(throwing: NEXUSSignError.attestationFailed(underlying: URLError(.unknown)))
                }
            }
        }
    }

    /// Produces an App Attest object bound to the caller-supplied protocol bytes.
    func attest(keyID: String, clientData: Data) async throws -> Data {
        let clientDataHash = Data(SHA256.hash(data: clientData))

        return try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyID, clientDataHash: clientDataHash) { attestationObject, error in
                if let error {
                    continuation.resume(throwing: NEXUSSignError.attestationFailed(underlying: error))
                } else if let attestationObject {
                    continuation.resume(returning: attestationObject)
                } else {
                    continuation.resume(throwing: NEXUSSignError.attestationFailed(underlying: URLError(.unknown)))
                }
            }
        }
    }
}
