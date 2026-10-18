import Foundation
import CryptoKit

/// The transaction exactly as the device will sign it.
///
/// Every value here is parsed from the canonical authorization bytes that go
/// into the signature, never from the convenience fields of the JSON response.
/// Host applications must render the confirmation screen from this value: it is
/// the only representation guaranteed to be what the customer's key signs
/// ("what you see is what you sign").
public struct NexusSignedTransaction: Equatable {
    public let authorizationId: String
    public let nexusId: String
    public let credentialId: String
    public let transactionReference: String
    public let operationType: String
    /// Integer amount in minor units, e.g. "125000" for 1250.00 PLN.
    public let amountMinor: String
    /// ISO 4217 currency code.
    public let currency: String
    public let beneficiary: [String: String]
    public let policyReference: String
    public let policyVersion: String
    /// RFC 3339 UTC timestamps exactly as signed.
    public let issuedAt: String
    public let expiresAt: String
    public let nonce: String

    /// Amount in major units using the currency's ISO 4217 minor-unit count,
    /// computed with integer string arithmetic (no floating point).
    public var formattedAmount: String {
        SignedPayload.formatMinorUnits(amountMinor, fractionDigits: SignedPayload.fractionDigits(currency: currency))
    }

    /// Beneficiary for display: the account identifier first (iban, account
    /// or account_number), then name and bic, then the other fields by key.
    public var beneficiaryDisplay: String { SignedPayload.beneficiaryDisplay(beneficiary) }

    /// Text of the Face ID / Touch ID prompt (FI-003). The first line carries
    /// the amount and the account identifier, so a long payee name cannot push
    /// the account out of the visible part of the prompt; the second line names
    /// the operation and the reference. Shared vectors fix the exact text.
    public var confirmationText: String {
        var text = "\(formattedAmount) \(currency)"
        let who = beneficiaryDisplay
        if !who.isEmpty { text += " → \(who)" }
        text += "\n\(operationType) • \(transactionReference)"
        return text
    }

    /// Expiry as a `Date`, parsed from the signed timestamp.
    public var expiresAtDate: Date? { SignedPayload.parseTimestamp(expiresAt) }
}

/// Response fields the SDK cross-checks against the signed bytes.
struct AuthorizationEnvelope: Equatable {
    var authorizationId: String
    var nexusId: String
    var credentialId: String?
    var transactionReference: String
    var operationType: String
    var amountMinor: String
    var currency: String
    var beneficiary: [String: String]
    var policyReference: String
    var policyVersion: String
    var issuedAt: Date
    var expiresAt: Date
    var canonicalPayloadHash: String
    var canonicalPayloadBase64: String
}

/// Strict parser for the v1 canonical authorization object.
///
/// The bytes are accepted only if re-serializing the parsed object with Auth
/// Core's canonicalization (recursively sorted keys, `JSON.stringify` string
/// escaping, no whitespace) reproduces them exactly. This rejects duplicate
/// keys, alternative escapings, whitespace, unsorted keys and trailing data,
/// any of which could let one parser show a value another does not sign.
/// Mirrors `SignedPayload` in the Android SDK; both run the shared vectors in
/// `auth-core/test-vectors/signed-payload-v1.json`.
enum SignedPayload {
    static let protocolVersion = "1"
    static let domain = "NEXUS-SIGN/TRANSACTION-AUTH"

    static let fields: Set<String> = [
        "amount_minor", "authorization_id", "beneficiary", "credential_id", "currency", "domain",
        "expires_at", "issued_at", "nexus_id", "nonce", "operation_type", "policy_reference",
        "policy_version", "protocol_version", "transaction_reference",
    ]

    struct Rejected: Error, Equatable {
        let reason: String
        let detail: String
    }

    indirect enum Value: Equatable {
        case string(String)
        case object([(key: String, value: Value)])

        static func == (lhs: Value, rhs: Value) -> Bool {
            switch (lhs, rhs) {
            case let (.string(a), .string(b)): return a == b
            case let (.object(a), .object(b)):
                return a.count == b.count && zip(a, b).allSatisfy { $0.key == $1.key && $0.value == $1.value }
            default: return false
            }
        }
    }

    // MARK: - Parsing

    static func parse(_ canonical: Data) throws -> NexusSignedTransaction {
        guard let text = String(data: canonical, encoding: .utf8) else {
            throw Rejected(reason: "invalid_json", detail: "payload is not valid UTF-8")
        }
        var reader = Reader(units: Array(text.utf16))
        let document = try reader.readDocument()
        guard case let .object(pairs) = document else {
            throw Rejected(reason: "invalid_json", detail: "top level is not an object")
        }
        guard encode(document) == canonical else {
            throw Rejected(reason: "not_canonical", detail: "bytes are not in canonical form")
        }

        var object: [String: Value] = [:]
        for pair in pairs { object[pair.key] = pair.value }
        let keys = Set(object.keys)
        let missing = fields.subtracting(keys)
        if !missing.isEmpty { throw Rejected(reason: "missing_field", detail: missing.sorted().joined(separator: ", ")) }
        let unexpected = keys.subtracting(fields)
        if !unexpected.isEmpty { throw Rejected(reason: "unexpected_field", detail: unexpected.sorted().joined(separator: ", ")) }

        func str(_ key: String) throws -> String {
            guard case let .string(value)? = object[key] else {
                throw Rejected(reason: "invalid_value", detail: "\(key) must be a string")
            }
            return value
        }

        guard case let .object(beneficiaryPairs)? = object["beneficiary"] else {
            throw Rejected(reason: "invalid_value", detail: "beneficiary must be an object")
        }
        var beneficiary: [String: String] = [:]
        for pair in beneficiaryPairs {
            // Same rule as Auth Core: integer-like or non-identifier keys would make
            // its JSON.stringify output differ from sorted order.
            guard matches(pair.key, beneficiaryKeyPattern) else {
                throw Rejected(reason: "invalid_value", detail: "beneficiary key")
            }
            guard case let .string(value) = pair.value else {
                throw Rejected(reason: "invalid_value", detail: "beneficiary.\(pair.key) must be a string")
            }
            beneficiary[pair.key] = value
        }

        let version = try str("protocol_version")
        let payloadDomain = try str("domain")
        guard version == protocolVersion, payloadDomain == domain else {
            throw Rejected(reason: "wrong_protocol", detail: "unsupported protocol_version/domain")
        }
        let amountMinor = try str("amount_minor")
        let currency = try str("currency")
        let issuedAt = try str("issued_at")
        let expiresAt = try str("expires_at")
        guard matches(amountMinor, amountPattern) else { throw Rejected(reason: "invalid_value", detail: "amount_minor") }
        guard matches(currency, currencyPattern) else { throw Rejected(reason: "invalid_value", detail: "currency") }
        guard matches(issuedAt, timestampPattern), matches(expiresAt, timestampPattern) else {
            throw Rejected(reason: "invalid_value", detail: "timestamps")
        }
        let authorizationID = try str("authorization_id")
        let credentialID = try str("credential_id")
        guard matches(authorizationID, uuidPattern), matches(credentialID, uuidPattern) else {
            throw Rejected(reason: "invalid_value", detail: "authorization_id/credential_id")
        }
        let nexusID = try str("nexus_id")
        guard matches(nexusID, nexusIDPattern) else { throw Rejected(reason: "invalid_value", detail: "nexus_id") }
        let nonceValue = try str("nonce")
        guard matches(nonceValue, noncePattern) else { throw Rejected(reason: "invalid_value", detail: "nonce") }
        for pair in pairs {
            if case let .string(text) = pair.value, !isDisplaySafe(text) {
                throw Rejected(reason: "invalid_value", detail: "\(pair.key) contains a control, format or separator character")
            }
        }
        if beneficiary.count > beneficiaryMaxFields {
            throw Rejected(reason: "invalid_value", detail: "more than \(beneficiaryMaxFields) beneficiary fields")
        }
        for (key, value) in beneficiary {
            if !isDisplaySafe(value) {
                throw Rejected(reason: "invalid_value", detail: "beneficiary.\(key) contains a control, format or separator character")
            }
            // UTF-16 code units, as Auth Core and the Android SDK count.
            if value.isEmpty || value.utf16.count > beneficiaryMaxValueLength {
                throw Rejected(reason: "invalid_value", detail: "beneficiary.\(key) must be 1 to \(beneficiaryMaxValueLength) characters")
            }
            if let first = value.unicodeScalars.first, let last = value.unicodeScalars.last,
               first.properties.generalCategory == .spaceSeparator || last.properties.generalCategory == .spaceSeparator {
                throw Rejected(reason: "invalid_value", detail: "beneficiary.\(key) has leading or trailing space")
            }
        }

        return NexusSignedTransaction(
            authorizationId: try str("authorization_id"),
            nexusId: try str("nexus_id"),
            credentialId: try str("credential_id"),
            transactionReference: try str("transaction_reference"),
            operationType: try str("operation_type"),
            amountMinor: amountMinor,
            currency: currency,
            beneficiary: beneficiary,
            policyReference: try str("policy_reference"),
            policyVersion: try str("policy_version"),
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            nonce: try str("nonce")
        )
    }

    /// Parses the signed bytes and requires every response field the host app
    /// might display to agree with them. Any disagreement means the customer
    /// would be shown something other than what is signed, so signing is refused.
    static func verify(_ envelope: AuthorizationEnvelope) throws -> NexusSignedTransaction {
        guard let bytes = Data(base64Encoded: envelope.canonicalPayloadBase64) else {
            throw Rejected(reason: "invalid_json", detail: "canonicalPayloadBase64 is not base64")
        }
        let signed = try parse(bytes)
        let hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()

        func check(_ field: String, _ ok: Bool) throws {
            if !ok { throw Rejected(reason: "response_mismatch", detail: field) }
        }
        try check("canonicalPayloadHash", hash == envelope.canonicalPayloadHash.lowercased())
        try check("authorizationId", signed.authorizationId == envelope.authorizationId)
        try check("nexusId", signed.nexusId == envelope.nexusId)
        try check("credentialId", envelope.credentialId == nil || signed.credentialId == envelope.credentialId)
        try check("transactionReference", signed.transactionReference == envelope.transactionReference)
        try check("operationType", signed.operationType == envelope.operationType)
        try check("amountMinor", signed.amountMinor == envelope.amountMinor)
        try check("currency", signed.currency == envelope.currency)
        try check("beneficiary", signed.beneficiary == envelope.beneficiary)
        try check("policyReference", signed.policyReference == envelope.policyReference)
        try check("policyVersion", signed.policyVersion == envelope.policyVersion)
        try check("issuedAt", parseTimestamp(signed.issuedAt) == envelope.issuedAt)
        try check("expiresAt", parseTimestamp(signed.expiresAt) == envelope.expiresAt)
        return signed
    }

    // MARK: - Display helpers

    static func formatMinorUnits(_ amountMinor: String, fractionDigits: Int) -> String {
        guard matches(amountMinor, amountPattern) else { return amountMinor }
        guard fractionDigits > 0 else { return amountMinor }
        let padding = max(0, fractionDigits + 1 - amountMinor.count)
        let padded = String(repeating: "0", count: padding) + amountMinor
        let split = padded.index(padded.endIndex, offsetBy: -fractionDigits)
        return String(padded[..<split]) + "." + String(padded[split...])
    }

    /// ISO 4217 minor units for the currencies that do not use two. A fixed
    /// table rather than `NumberFormatter`, which follows CLDR and differs
    /// from ISO 4217 for several currencies (RSD, IQD).
    private static let minorUnits: [String: Int] = {
        var table: [String: Int] = [:]
        for code in ["BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF"] { table[code] = 0 }
        for code in ["BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"] { table[code] = 3 }
        for code in ["CLF", "UYW"] { table[code] = 4 }
        return table
    }()

    /// ISO 4217 minor units; every other code uses 2.
    static func fractionDigits(currency: String) -> Int {
        minorUnits[currency] ?? 2
    }

    private static let displayUnsafeCategories: Set<Unicode.GeneralCategory> = [.control, .format, .lineSeparator, .paragraphSeparator]

    /// False for text with control, format (bidi, zero-width) or separator
    /// characters, which could make the prompt read differently from the
    /// signed value. Auth Core applies the same rule.
    static func isDisplaySafe(_ value: String) -> Bool {
        !value.unicodeScalars.contains { displayUnsafeCategories.contains($0.properties.generalCategory) }
    }

    /// ISO 20022 Max140Text, in UTF-16 code units; Auth Core applies the same limit.
    static let beneficiaryMaxValueLength = 140
    static let beneficiaryMaxFields = 16

    private static let accountKeys = ["iban", "account", "account_number"]

    static func beneficiaryDisplay(_ beneficiary: [String: String]) -> String {
        let account = accountKeys.first { beneficiary[$0] != nil }
        let ordered = [account, "name", "bic"].compactMap { $0 }.filter { beneficiary[$0] != nil }
        // Array.sorted on String compares Unicode scalars; keys are [a-z0-9_]
        // (checked above), where that equals the UTF-16 order the other
        // implementations use.
        let rest = beneficiary.keys.filter { !ordered.contains($0) }.sorted()
        return (ordered + rest).compactMap { beneficiary[$0] }.joined(separator: " · ")
    }

    static func parseTimestamp(_ value: String) -> Date? {
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = withFraction.date(from: value) { return date }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: value)
    }

    // MARK: - Canonical encoding
    // Mirrors JSON.stringify over recursively sorted keys.

    static func encode(_ value: Value) -> Data {
        var out: [UInt16] = []
        write(value, into: &out)
        return Data(String(decoding: out, as: UTF16.self).utf8)
    }

    private static func write(_ value: Value, into out: inout [UInt16]) {
        switch value {
        case let .string(s):
            writeString(s, into: &out)
        case let .object(pairs):
            out.append(0x7B) // {
            // Array.prototype.sort() orders keys by UTF-16 code units.
            let sorted = pairs.sorted { $0.key.utf16.lexicographicallyPrecedes($1.key.utf16) }
            for (index, pair) in sorted.enumerated() {
                if index > 0 { out.append(0x2C) } // ,
                writeString(pair.key, into: &out)
                out.append(0x3A) // :
                write(pair.value, into: &out)
            }
            out.append(0x7D) // }
        }
    }

    private static func writeString(_ s: String, into out: inout [UInt16]) {
        out.append(0x22)
        for unit in s.utf16 {
            switch unit {
            case 0x22: out.append(contentsOf: Array("\\\"".utf16))
            case 0x5C: out.append(contentsOf: Array("\\\\".utf16))
            case 0x08: out.append(contentsOf: Array("\\b".utf16))
            case 0x0C: out.append(contentsOf: Array("\\f".utf16))
            case 0x0A: out.append(contentsOf: Array("\\n".utf16))
            case 0x0D: out.append(contentsOf: Array("\\r".utf16))
            case 0x09: out.append(contentsOf: Array("\\t".utf16))
            case 0x00..<0x20: out.append(contentsOf: Array(String(format: "\\u%04x", UInt32(unit)).utf16))
            default: out.append(unit)
            }
        }
        out.append(0x22)
    }

    // MARK: - Patterns

    private static let amountPattern = "^(0|[1-9][0-9]{0,29})$"
    private static let currencyPattern = "^[A-Z]{3}$"
    private static let beneficiaryKeyPattern = "^[a-z][a-z0-9_]{0,63}$"
    private static let timestampPattern = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?Z$"
    // Protocol v1 formats: lowercase UUIDs, 9-digit NEXUS ID, 32-byte nonce in lowercase hex.
    private static let uuidPattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    private static let nexusIDPattern = "^[0-9]{9}$"
    private static let noncePattern = "^[0-9a-f]{64}$"

    private static func matches(_ value: String, _ pattern: String) -> Bool {
        value.range(of: pattern, options: .regularExpression) != nil
    }

    // MARK: - Reader

    /// Minimal RFC 8259 reader limited to objects and strings (the only types
    /// the v1 protocol uses). Works on UTF-16 code units, like Auth Core.
    private struct Reader {
        let units: [UInt16]
        var i = 0
        var depth = 0

        init(units: [UInt16]) { self.units = units }

        mutating func readDocument() throws -> Value {
            skipWhitespace()
            let value = try readValue()
            skipWhitespace()
            if i != units.count { throw Rejected(reason: "not_canonical", detail: "trailing data") }
            return value
        }

        private func peek() -> UInt16? { i < units.count ? units[i] : nil }

        private mutating func readValue() throws -> Value {
            switch peek() {
            case 0x7B?: return try readObject()
            case 0x22?: return .string(try readString())
            case 0x5B?: throw Rejected(reason: "invalid_json", detail: "arrays are not allowed")
            case nil: throw Rejected(reason: "invalid_json", detail: "unexpected end of input")
            default: throw Rejected(reason: "invalid_value", detail: "only strings and objects are allowed")
            }
        }

        private mutating func readObject() throws -> Value {
            depth += 1
            if depth > 2 { throw Rejected(reason: "invalid_value", detail: "nesting too deep") }
            i += 1 // {
            var pairs: [(key: String, value: Value)] = []
            var seen = Set<String>()
            skipWhitespace()
            if peek() == 0x7D { i += 1; depth -= 1; return .object(pairs) }
            while true {
                skipWhitespace()
                guard peek() == 0x22 else { throw Rejected(reason: "invalid_json", detail: "expected key") }
                let key = try readString()
                skipWhitespace()
                guard peek() == 0x3A else { throw Rejected(reason: "invalid_json", detail: "expected ':'") }
                i += 1
                skipWhitespace()
                let value = try readValue()
                guard seen.insert(key).inserted else { throw Rejected(reason: "duplicate_key", detail: key) }
                pairs.append((key: key, value: value))
                skipWhitespace()
                switch peek() {
                case 0x2C?: i += 1
                case 0x7D?: i += 1; depth -= 1; return .object(pairs)
                default: throw Rejected(reason: "invalid_json", detail: "expected ',' or '}'")
                }
            }
        }

        private mutating func readString() throws -> String {
            i += 1 // opening quote
            var out: [UInt16] = []
            while true {
                guard let c = peek() else { throw Rejected(reason: "invalid_json", detail: "unterminated string") }
                i += 1
                switch c {
                case 0x22:
                    // A lone surrogate from a \u escape decodes to U+FFFD here,
                    // so the canonical re-encoding check in parse() rejects it.
                    return String(decoding: out, as: UTF16.self)
                case 0x5C:
                    guard let e = peek() else { throw Rejected(reason: "invalid_json", detail: "bad escape") }
                    i += 1
                    switch e {
                    case 0x22: out.append(0x22)
                    case 0x5C: out.append(0x5C)
                    case 0x2F: out.append(0x2F)
                    case 0x62: out.append(0x08) // b
                    case 0x66: out.append(0x0C) // f
                    case 0x6E: out.append(0x0A) // n
                    case 0x72: out.append(0x0D) // r
                    case 0x74: out.append(0x09) // t
                    case 0x75: out.append(try readHex4()) // u
                    default: throw Rejected(reason: "invalid_json", detail: "bad escape")
                    }
                case 0x00..<0x20:
                    throw Rejected(reason: "invalid_json", detail: "unescaped control character")
                default:
                    out.append(c)
                }
            }
        }

        private mutating func readHex4() throws -> UInt16 {
            guard i + 4 <= units.count else { throw Rejected(reason: "invalid_json", detail: "short \\u escape") }
            var value: UInt16 = 0
            for unit in units[i..<(i + 4)] {
                let digit: UInt16
                switch unit {
                case 0x30...0x39: digit = unit - 0x30
                case 0x41...0x46: digit = unit - 0x41 + 10
                case 0x61...0x66: digit = unit - 0x61 + 10
                default: throw Rejected(reason: "invalid_json", detail: "bad \\u escape")
                }
                value = value * 16 + digit
            }
            i += 4
            return value
        }

        private mutating func skipWhitespace() {
            while let c = peek(), c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { i += 1 }
        }
    }
}
