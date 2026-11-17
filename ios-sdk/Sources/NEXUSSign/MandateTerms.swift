import CryptoKit
import Foundation

/// Parses the canonical terms of a payment mandate and refuses anything the
/// device must not show or sign: other domain (payment bytes), another mandate
/// or device, bytes that do not hash to termsHash or are not canonical, a
/// missing or unexpected field, a value breaking the display rules, an IBAN
/// with wrong check digits, or inconsistent limits and validity. Mirrors
/// `MandateTermsParser` in the Android SDK; both run the shared vectors in
/// `auth-core/test-vectors/mandate-terms-v1.json`.
enum MandateTermsParser {
    static let domain = "NEXUS-SIGN/MANDATE"
    private static let fields: Set<String> = [
        "protocol_version", "domain", "mandate_id", "nexus_id", "credential_id", "mandate_reference", "payee", "currency",
        "per_payment_limit_minor", "total_limit_minor", "frequency", "valid_from", "valid_until", "terms_version",
        "issued_at", "offer_expires_at", "nonce",
    ]
    private static let frequencies: Set<String> = ["WEEKLY", "MONTHLY", "QUARTERLY", "YEARLY"]
    private static let minorPattern = "^[1-9][0-9]{0,29}$"
    private static let currencyPattern = "^[A-Z]{3}$"
    private static let timestampPattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$"

    typealias Rejected = SignedPayload.Rejected

    static func parse(termsBase64: String, termsHash: String, mandateId: String, credentialId: String) throws -> NexusMandateTerms {
        guard let bytes = Data(base64Encoded: termsBase64) else { throw Rejected(reason: "invalid_json", detail: "termsBase64") }
        let hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        guard hash == termsHash else { throw Rejected(reason: "hash_mismatch", detail: "termsHash") }
        let o = try SignedPayload.parseCanonicalObject(bytes, allowNull: true)
        let keys = Set(o.keys)
        let missing = fields.subtracting(keys)
        if !missing.isEmpty { throw Rejected(reason: "missing_field", detail: missing.sorted().joined(separator: ", ")) }
        let unexpected = keys.subtracting(fields)
        if !unexpected.isEmpty { throw Rejected(reason: "unexpected_field", detail: unexpected.sorted().joined(separator: ", ")) }

        func str(_ key: String) throws -> String {
            guard case let .string(value)? = o[key] else { throw Rejected(reason: "invalid_value", detail: "\(key) must be a string") }
            return value
        }
        func shown(_ key: String) throws -> String {
            let value = try str(key)
            if SignedPayload.displayTextViolation(value) != nil { throw Rejected(reason: "display", detail: key) }
            return value
        }

        guard try str("protocol_version") == "1", try str("domain") == domain else {
            throw Rejected(reason: "wrong_domain", detail: "not mandate terms v1")
        }
        guard try str("mandate_id") == mandateId else { throw Rejected(reason: "mismatch", detail: "mandate_id") }
        guard try str("credential_id") == credentialId else { throw Rejected(reason: "wrong_device", detail: "the mandate is for another device") }

        guard case let .object(payeePairs)? = o["payee"] else { throw Rejected(reason: "invalid_value", detail: "payee must be an object") }
        if payeePairs.isEmpty { throw Rejected(reason: "invalid_value", detail: "payee is empty") }
        var payee: [String: String] = [:]
        for (key, value) in payeePairs {
            guard case let .string(text) = value else { throw Rejected(reason: "invalid_value", detail: "payee.\(key) must be a string") }
            if SignedPayload.displayTextViolation(text) != nil { throw Rejected(reason: "display", detail: "payee.\(key)") }
            // Finding D-02: no second account number outside the account fields.
            if !SignedPayload.accountKeys.contains(key) && SignedPayload.looksLikeIBAN(text) {
                throw Rejected(reason: "display", detail: "payee.\(key) looks like an account number")
            }
            payee[key] = text
        }
        if let iban = payee["iban"], !SignedPayload.isValidIBAN(iban) { throw Rejected(reason: "iban", detail: "payee.iban") }

        let currency = try str("currency")
        guard matches(currency, currencyPattern) else { throw Rejected(reason: "invalid_value", detail: "currency") }
        let perPayment = try str("per_payment_limit_minor")
        guard matches(perPayment, minorPattern) else { throw Rejected(reason: "invalid_value", detail: "per_payment_limit_minor") }
        let total: String?
        switch o["total_limit_minor"] {
        case .null?:
            total = nil
        case let .string(value)?:
            guard matches(value, minorPattern), !isLess(value, than: perPayment) else {
                throw Rejected(reason: "invalid_value", detail: "total_limit_minor")
            }
            total = value
        default:
            throw Rejected(reason: "invalid_value", detail: "total_limit_minor")
        }
        let frequency = try str("frequency")
        guard frequencies.contains(frequency) else { throw Rejected(reason: "invalid_value", detail: "frequency") }
        let validFrom = try str("valid_from")
        let validUntil = try str("valid_until")
        let issuedAt = try str("issued_at")
        let offerExpiresAt = try str("offer_expires_at")
        for (key, value) in [("valid_from", validFrom), ("valid_until", validUntil), ("issued_at", issuedAt), ("offer_expires_at", offerExpiresAt)] {
            guard matches(value, timestampPattern), SignedPayload.parseTimestamp(value) != nil else { throw Rejected(reason: "invalid_value", detail: key) }
        }
        guard let from = SignedPayload.parseTimestamp(validFrom), let until = SignedPayload.parseTimestamp(validUntil), until > from else {
            throw Rejected(reason: "invalid_value", detail: "valid_until")
        }
        return NexusMandateTerms(
            mandateId: mandateId, nexusId: try shown("nexus_id"), credentialId: credentialId, mandateReference: try shown("mandate_reference"),
            payee: payee, currency: currency, perPaymentLimitMinor: perPayment, totalLimitMinor: total, frequency: frequency,
            validFrom: validFrom, validUntil: validUntil, termsVersion: try shown("terms_version"), offerExpiresAt: offerExpiresAt)
    }

    private static func matches(_ value: String, _ pattern: String) -> Bool {
        value.range(of: pattern, options: .regularExpression) != nil
    }

    /// Compares two decimal integer strings without leading zeros (up to 30 digits).
    private static func isLess(_ a: String, than b: String) -> Bool {
        a.count != b.count ? a.count < b.count : a < b
    }
}
