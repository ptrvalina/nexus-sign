import Foundation

public struct NexusAuthorization: Decodable, Equatable {
    public let authorizationId: String
    public let nexusId: String
    public let credentialId: String?
    public let transactionReference: String
    public let operationType: String
    public let amountMinor: String
    public let currency: String
    public let beneficiary: [String: String]
    public let policyReference: String
    public let policyVersion: String
    public let canonicalPayloadHash: String
    public let canonicalPayloadBase64: String
    public let issuedAt: Date
    public let expiresAt: Date
    public let state: String

    /// The transaction exactly as it will be signed, parsed from
    /// `canonicalPayloadBase64` and cross-checked against every other field of
    /// this response. Build confirmation UI from this, not from the fields above.
    ///
    /// - Throws: `NEXUSSignError.authorizationPayloadInvalid` if the signed bytes
    ///   are malformed, not canonical, or disagree with the response fields.
    public func signedTransaction() throws -> NexusSignedTransaction {
        let envelope = AuthorizationEnvelope(
            authorizationId: authorizationId, nexusId: nexusId, credentialId: credentialId,
            transactionReference: transactionReference, operationType: operationType,
            amountMinor: amountMinor, currency: currency, beneficiary: beneficiary,
            policyReference: policyReference, policyVersion: policyVersion,
            issuedAt: issuedAt, expiresAt: expiresAt,
            canonicalPayloadHash: canonicalPayloadHash, canonicalPayloadBase64: canonicalPayloadBase64
        )
        do {
            return try SignedPayload.verify(envelope)
        } catch let rejected as SignedPayload.Rejected {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: rejected.reason, detail: rejected.detail)
        }
    }

    /// Formatted amount taken from the signed payload (empty if it does not verify).
    public var displayAmount: String {
        guard let signed = try? signedTransaction() else { return "" }
        return "\(signed.formattedAmount) \(signed.currency)"
    }
}

public enum NEXUSVerificationOutcome: String, Decodable { case verified = "VERIFIED", failed = "FAILED", expired = "EXPIRED" }

public struct NexusMobileRegistration: Decodable, Equatable {
    public let nexusId: String
    public let credentialId: String
    public let credentialState: String
    public let keyAlgorithm: String
    public let keyVersion: Int
    public let attestationStatus: String
    /// Always `DEVICE_SIGNATURE`: the device signs its own requests.
    public let requestAuthentication: String?
    public let offlineServerPublicKeyPem: String?
}

public struct NexusRecoveryParameters: Decodable, Equatable {
    /// Recovery protocol version; this SDK implements protocol 2 only.
    public let protocolVersion: Int?
    public let kdf: String
    public let iterations: Int
    public let keyLength: Int
    public let salt: String
    /// Present in the setup parameters: the identity and credential the
    /// recovery key will be registered for.
    public let nexusId: String?
    public let credentialId: String?

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol"
        case kdf, iterations, keyLength, salt, nexusId, credentialId
    }
}

public struct NexusRecoverySession: Decodable, Equatable {
    public let sessionId: String
    public let nexusId: String
    public let nonce: String
    public let accessToken: String
    public let parameters: NexusRecoveryParameters
    /// The registered recovery public key and the recovery private key
    /// wrapped under the phrase (protocol 2).
    public let recoveryPublicKeyPem: String?
    public let wrappedRecoveryKey: String?
    public let expiresAt: Date
}

public struct NexusRecoveryResult: Decodable, Equatable {
    public let nexusId: String
    public let credentialId: String
    public let keyVersion: Int
    /// `DEVICE_SIGNATURE` when the device signs its own requests.
    public let requestAuthentication: String?
    public let offlineServerPublicKeyPem: String?
}

/// A transaction read from an offline QR code, verified and ready to show.
public struct NexusOfflineChallenge {
    /// The transaction exactly as it is confirmed; render the screen from this.
    public let transaction: NexusSignedTransaction
    let canonicalPayload: Data
}

struct VerifyResponse: Decodable { let status: NEXUSVerificationOutcome; let reason: String? }
struct ErrorResponse: Decodable { let error: String?; let serverTime: Int64? }

extension JSONDecoder {
    /// Auth Core sends RFC 3339 timestamps with milliseconds
    /// (`2026-09-26T10:00:00.000Z`), which `.iso8601` does not accept. Host
    /// apps should use this decoder for any NEXUS-SIGN payload they decode
    /// themselves, e.g. the `NexusRecoverySession` handed over by the bank backend.
    public static func nexus() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { dateDecoder in
            let raw = try dateDecoder.singleValueContainer().decode(String.self)
            guard let date = SignedPayload.parseTimestamp(raw) else {
                throw DecodingError.dataCorrupted(.init(codingPath: dateDecoder.codingPath, debugDescription: "Invalid RFC 3339 timestamp: \(raw)"))
            }
            return date
        }
        return decoder
    }
}

