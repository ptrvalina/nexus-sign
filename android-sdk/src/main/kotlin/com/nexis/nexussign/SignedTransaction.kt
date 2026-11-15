package com.nexis.nexussign

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.text.Normalizer

/**
 * The transaction exactly as the device will sign it.
 *
 * Every value here is parsed from the canonical authorization bytes that go
 * into the signature, never from the convenience fields of the JSON
 * response. Host applications must render the confirmation screen from this
 * object: it is the only representation that is guaranteed to be what the
 * customer's key signs ("what you see is what you sign").
 */
data class NexusSignedTransaction(
    val authorizationId: String,
    val nexusId: String,
    val credentialId: String,
    val transactionReference: String,
    val operationType: String,
    /** Integer amount in minor units, e.g. "125000" for 1250.00 PLN. */
    val amountMinor: String,
    /** ISO 4217 currency code. */
    val currency: String,
    val beneficiary: Map<String, String>,
    val policyReference: String,
    val policyVersion: String,
    /** RFC 3339 UTC timestamps exactly as signed. */
    val issuedAt: String,
    val expiresAt: String,
    val nonce: String,
) {
    /** Amount in major units using the currency's ISO 4217 minor-unit count,
     * computed with integer string arithmetic (no floating point). */
    fun formattedAmount(): String = SignedPayload.formatMinorUnits(amountMinor, SignedPayload.fractionDigits(currency))

    /** Beneficiary for display: well-known keys first, remaining keys sorted. */
    fun beneficiaryDisplay(): String = SignedPayload.beneficiaryDisplay(beneficiary)

    /**
     * Text of the biometric prompt. The first line carries the amount
     * and the account identifier, so a long payee name cannot push the account
     * out of the visible part of the prompt; the second line names the
     * operation and the reference. Shared vectors fix the exact text.
     */
    fun confirmationText(): String = buildString {
        append(formattedAmount()).append(' ').append(currency)
        val who = beneficiaryDisplay()
        if (who.isNotEmpty()) append(" → ").append(who)
        append('\n').append(operationType).append(" • ").append(transactionReference)
    }
}

/**
 * Response fields the SDK cross-checks against the signed bytes. Plain values
 * so the check stays independent of the HTTP/JSON layer and is unit-testable
 * on a JVM without Android.
 */
internal data class AuthorizationEnvelope(
    val authorizationId: String,
    val nexusId: String,
    val credentialId: String?,
    val transactionReference: String,
    val operationType: String,
    val amountMinor: String,
    val currency: String,
    val beneficiary: Map<String, String>,
    val policyReference: String,
    val policyVersion: String,
    val issuedAt: String,
    val expiresAt: String,
    val canonicalPayloadHash: String,
    val canonicalPayloadBase64: String,
)

/**
 * Strict parser for the v1 canonical authorization object.
 *
 * The bytes are accepted only if re-serializing the parsed object with Auth
 * Core's canonicalization (recursively sorted keys, `JSON.stringify` string
 * escaping, no whitespace) reproduces them exactly. This rejects duplicate
 * keys, alternative escapings, whitespace, unsorted keys and trailing data,
 * any of which could let one parser show a value another parser does not sign.
 */
internal object SignedPayload {
    const val PROTOCOL_VERSION = "1"
    const val DOMAIN = "NEXUS-SIGN/TRANSACTION-AUTH"

    val FIELDS: Set<String> = setOf(
        "amount_minor", "authorization_id", "beneficiary", "credential_id", "currency", "domain",
        "expires_at", "issued_at", "nexus_id", "nonce", "operation_type", "policy_reference",
        "policy_version", "protocol_version", "transaction_reference",
    )

    private val AMOUNT = Regex("^(0|[1-9][0-9]{0,29})$")
    private val CURRENCY = Regex("^[A-Z]{3}$")
    private val BENEFICIARY_KEY = Regex("^[a-z][a-z0-9_]{0,63}$")
    private val TIMESTAMP = Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?Z$")
    // Protocol v1 formats (authorization-protocol-v1.md): lowercase UUIDs,
    // 9-digit NEXUS ID, 32-byte nonce in lowercase hex.
    private val UUID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    private val NEXUS_ID = Regex("^[0-9]{9}$")
    private val NONCE = Regex("^[0-9a-f]{64}$")

    class Rejected(val reason: String, detail: String) : Exception("$reason: $detail")

    fun parse(canonical: ByteArray): NexusSignedTransaction {
        val text = decodeUtf8Strict(canonical)
        val parsed = JsonReader(text).readDocument()
        val obj = parsed as? Map<*, *> ?: throw Rejected("invalid_json", "top level is not an object")
        if (!encode(obj).contentEquals(canonical)) throw Rejected("not_canonical", "bytes are not in canonical form")

        val missing = FIELDS - obj.keys.map { it as String }.toSet()
        if (missing.isNotEmpty()) throw Rejected("missing_field", missing.sorted().joinToString())
        val unexpected = obj.keys.map { it as String }.toSet() - FIELDS
        if (unexpected.isNotEmpty()) throw Rejected("unexpected_field", unexpected.sorted().joinToString())

        fun str(key: String): String = obj[key] as? String ?: throw Rejected("invalid_value", "$key must be a string")
        val beneficiaryRaw = obj["beneficiary"] as? Map<*, *> ?: throw Rejected("invalid_value", "beneficiary must be an object")
        val beneficiary = beneficiaryRaw.entries.associate { (k, v) ->
            val key = k as String
            // Same rule as Auth Core: integer-like or non-identifier keys would make
            // its JSON.stringify output differ from sorted order.
            if (!BENEFICIARY_KEY.matches(key)) throw Rejected("invalid_value", "beneficiary key")
            key to (v as? String ?: throw Rejected("invalid_value", "beneficiary.$key must be a string"))
        }

        if (str("protocol_version") != PROTOCOL_VERSION || str("domain") != DOMAIN) {
            throw Rejected("wrong_protocol", "unsupported protocol_version/domain")
        }
        if (!AMOUNT.matches(str("amount_minor"))) throw Rejected("invalid_value", "amount_minor")
        if (!CURRENCY.matches(str("currency"))) throw Rejected("invalid_value", "currency")
        if (!TIMESTAMP.matches(str("issued_at")) || !TIMESTAMP.matches(str("expires_at"))) throw Rejected("invalid_value", "timestamps")
        if (!UUID.matches(str("authorization_id")) || !UUID.matches(str("credential_id"))) throw Rejected("invalid_value", "authorization_id/credential_id")
        if (!NEXUS_ID.matches(str("nexus_id"))) throw Rejected("invalid_value", "nexus_id")
        if (!NONCE.matches(str("nonce"))) throw Rejected("invalid_value", "nonce")
        for ((key, value) in obj) {
            if (value is String && !isDisplaySafe(value)) throw Rejected("invalid_value", "$key contains a control, format or separator character")
        }
        if (beneficiary.size > BENEFICIARY_MAX_FIELDS) throw Rejected("invalid_value", "more than $BENEFICIARY_MAX_FIELDS beneficiary fields")
        for ((key, value) in beneficiary) {
            if (value.isEmpty() || value.length > BENEFICIARY_MAX_VALUE_LENGTH) throw Rejected("invalid_value", "beneficiary.$key must be 1 to $BENEFICIARY_MAX_VALUE_LENGTH characters")
            displayTextViolation(value)?.let { throw Rejected("invalid_value", "beneficiary.$key: $it") }
            if (key == "iban" && !isValidIban(value)) throw Rejected("invalid_value", "beneficiary.iban is not a valid IBAN")
            if (key == "bic" && !BIC.matches(value)) throw Rejected("invalid_value", "beneficiary.bic is not a valid BIC")
        }
        for (key in listOf("transaction_reference", "operation_type")) {
            displayTextViolation(str(key))?.let { throw Rejected("invalid_value", "$key: $it") }
        }

        return NexusSignedTransaction(
            authorizationId = str("authorization_id"),
            nexusId = str("nexus_id"),
            credentialId = str("credential_id"),
            transactionReference = str("transaction_reference"),
            operationType = str("operation_type"),
            amountMinor = str("amount_minor"),
            currency = str("currency"),
            beneficiary = beneficiary,
            policyReference = str("policy_reference"),
            policyVersion = str("policy_version"),
            issuedAt = str("issued_at"),
            expiresAt = str("expires_at"),
            nonce = str("nonce"),
        )
    }

    /**
     * Parses the signed bytes and requires every response field the host app
     * might display to agree with them. A disagreement means Auth Core, or
     * something between it and the device, is showing the customer something
     * other than what would be signed, so signing is refused.
     */
    fun verify(envelope: AuthorizationEnvelope): NexusSignedTransaction {
        val bytes = try {
            java.util.Base64.getDecoder().decode(envelope.canonicalPayloadBase64)
        } catch (e: IllegalArgumentException) {
            throw Rejected("invalid_json", "canonicalPayloadBase64 is not base64")
        }
        val signed = parse(bytes)
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        fun check(field: String, ok: Boolean) { if (!ok) throw Rejected("response_mismatch", field) }
        check("canonicalPayloadHash", hash == envelope.canonicalPayloadHash.lowercase())
        check("authorizationId", signed.authorizationId == envelope.authorizationId)
        check("nexusId", signed.nexusId == envelope.nexusId)
        check("credentialId", envelope.credentialId == null || signed.credentialId == envelope.credentialId)
        check("transactionReference", signed.transactionReference == envelope.transactionReference)
        check("operationType", signed.operationType == envelope.operationType)
        check("amountMinor", signed.amountMinor == envelope.amountMinor)
        check("currency", signed.currency == envelope.currency)
        check("beneficiary", signed.beneficiary == envelope.beneficiary)
        check("policyReference", signed.policyReference == envelope.policyReference)
        check("policyVersion", signed.policyVersion == envelope.policyVersion)
        check("issuedAt", signed.issuedAt == envelope.issuedAt)
        check("expiresAt", signed.expiresAt == envelope.expiresAt)
        return signed
    }

    fun formatMinorUnits(amountMinor: String, fractionDigits: Int): String {
        require(AMOUNT.matches(amountMinor)) { "amountMinor must be a non-negative integer string" }
        if (fractionDigits <= 0) return amountMinor
        val padded = amountMinor.padStart(fractionDigits + 1, '0')
        val split = padded.length - fractionDigits
        return padded.substring(0, split) + "." + padded.substring(split)
    }

    /** ISO 4217 minor units for the currencies that do not use two. A fixed
     * table rather than java.util.Currency: on Android that class follows
     * CLDR, which differs from ISO 4217 for several currencies (RSD, IQD). */
    private val MINOR_UNITS: Map<String, Int> =
        listOf("BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF").associateWith { 0 } +
            listOf("BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND").associateWith { 3 } +
            listOf("CLF", "UYW").associateWith { 4 }

    /** ISO 4217 minor units; every other code uses 2. */
    fun fractionDigits(currency: String): Int = MINOR_UNITS[currency] ?: 2

    private val DISPLAY_UNSAFE_TYPES: Set<Int> = setOf(
        Character.CONTROL.toInt(), Character.FORMAT.toInt(),
        Character.LINE_SEPARATOR.toInt(), Character.PARAGRAPH_SEPARATOR.toInt(),
        Character.SURROGATE.toInt(),
    )

    /** False for text with control, format (bidi, zero-width) or separator
     * characters, which could make the prompt read differently from the
     * signed value. Auth Core applies the same rule. */
    fun isDisplaySafe(value: String): Boolean = value.codePoints().noneMatch { Character.getType(it) in DISPLAY_UNSAFE_TYPES }

    /** ISO 20022 Max140Text, in UTF-16 code units; Auth Core applies the same limit. */
    const val BENEFICIARY_MAX_VALUE_LENGTH = 140
    const val BENEFICIARY_MAX_FIELDS = 16

    private val IBAN = Regex("[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")
    private val BIC = Regex("[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?")

    /** Latin, Cyrillic, Greek, Armenian and Cherokee letters as fixed code point ranges, identical
     * in Auth Core, the iOS SDK and the sandbox, so the decision does not
     * depend on the Unicode version of the device's runtime. */
    private val CONFUSABLE_SCRIPTS = listOf(
        Regex("[A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u024F\u1E00-\u1EFF]"),
        Regex("[\u0400-\u052F]"),
        Regex("[\u0370-\u03FF\u1F00-\u1FFF]"),
        Regex("[\u0530-\u058F]"),
        Regex("[\u13A0-\u13FF\uAB70-\uABBF]"),
    )

    /**
     * The display text rules of authorization protocol v1 for values the
     * customer reads (beneficiary values, transaction_reference, operation_type):
     * NFC and no compatibility characters (NFKC-stable), only the ASCII space and
     * never doubled or at either end, only ASCII digits, and no mix of Latin,
     * Cyrillic, Greek, Armenian and Cherokee letters in one value. Returns the broken
     * rule, or null. Auth Core refuses to create an authorization that breaks
     * them; the device checks again because it trusts only the signed bytes.
     */
    fun displayTextViolation(value: String): String? {
        if (!isDisplaySafe(value)) return "control, format or separator character"
        if (!Normalizer.isNormalized(value, Normalizer.Form.NFC)) return "not in Unicode Normalization Form C"
        if (!Normalizer.isNormalized(value, Normalizer.Form.NFKC)) return "compatibility characters are not allowed"
        if (value.codePoints().anyMatch { Character.getType(it) == Character.SPACE_SEPARATOR.toInt() && it != 0x20 }) return "only the ASCII space is allowed"
        if (value.startsWith(' ') || value.endsWith(' ')) return "leading or trailing space"
        if (value.contains("  ")) return "repeated spaces"
        if (value.codePoints().anyMatch { Character.getType(it) == Character.DECIMAL_DIGIT_NUMBER.toInt() && it !in 0x30..0x39 }) return "only ASCII digits are allowed"
        if (CONFUSABLE_SCRIPTS.count { it.containsMatchIn(value) } > 1) return "Latin, Cyrillic, Greek, Armenian and Cherokee letters mixed in one value"
        return null
    }

    /** ISO 13616 IBAN in electronic format with valid check digits (mod 97). */
    fun isValidIban(value: String): Boolean {
        if (!IBAN.matches(value) || value.substring(2, 4).toInt() !in 2..98) return false
        var remainder = 0
        for (ch in value.substring(4) + value.substring(0, 4)) {
            remainder = if (ch in 'A'..'Z') (remainder * 100 + (ch - 'A' + 10)) % 97 else (remainder * 10 + (ch - '0')) % 97
        }
        return remainder == 1
    }

    private val ACCOUNT_KEYS = listOf("iban", "account", "account_number")

    /** Account identifier first (the first of iban, account, account_number),
     * then name and bic, then the other fields by key. */
    fun beneficiaryDisplay(beneficiary: Map<String, String>): String {
        val account = ACCOUNT_KEYS.firstOrNull { it in beneficiary }
        val ordered = listOfNotNull(account, "name", "bic").filter { it in beneficiary }
        val rest = beneficiary.keys.filter { it !in ordered }.sorted()
        return (ordered + rest).map { beneficiary.getValue(it) }.joinToString(" · ")
    }

    // --- Canonical encoding ---
    // Mirrors JSON.stringify over recursively sorted keys.

    fun encode(value: Any?): ByteArray = StringBuilder().also { write(it, value) }.toString().toByteArray(Charsets.UTF_8)

    private fun write(out: StringBuilder, value: Any?) {
        when (value) {
            is String -> writeString(out, value)
            is Map<*, *> -> {
                out.append('{')
                // String.compareTo orders by UTF-16 code units, like Array.prototype.sort().
                value.keys.map { it as String }.sorted().forEachIndexed { i, key ->
                    if (i > 0) out.append(',')
                    writeString(out, key)
                    out.append(':')
                    write(out, value[key])
                }
                out.append('}')
            }
            else -> throw Rejected("invalid_value", "only strings and objects are allowed")
        }
    }

    private fun writeString(out: StringBuilder, s: String) {
        out.append('"')
        for (c in s) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\b' -> out.append("\\b")
                c == '\u000C' -> out.append("\\f")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c < ' ' -> out.append("\\u").append(String.format("%04x", c.code))
                else -> out.append(c)
            }
        }
        out.append('"')
    }

    private fun decodeUtf8Strict(bytes: ByteArray): String = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (e: CharacterCodingException) {
        throw Rejected("invalid_json", "payload is not valid UTF-8")
    }

    /** Minimal RFC 8259 reader limited to objects and strings (the only types
     * the v1 protocol uses). Numbers, arrays, booleans and null are rejected;
     * duplicate keys are rejected explicitly. */
    private class JsonReader(private val s: String) {
        private var i = 0
        private var depth = 0

        fun readDocument(): Any {
            skipWs()
            val v = readValue()
            skipWs()
            if (i != s.length) throw Rejected("not_canonical", "trailing data")
            return v
        }

        private fun readValue(): Any = when (s.getOrNull(i)) {
            '{' -> readObject()
            '"' -> readString()
            '[' -> throw Rejected("invalid_json", "arrays are not allowed")
            null -> throw Rejected("invalid_json", "unexpected end of input")
            else -> throw Rejected("invalid_value", "only strings and objects are allowed")
        }

        private fun readObject(): Map<String, Any> {
            if (++depth > 2) throw Rejected("invalid_value", "nesting too deep")
            i++ // '{'
            val map = LinkedHashMap<String, Any>()
            skipWs()
            if (s.getOrNull(i) == '}') { i++; depth--; return map }
            while (true) {
                skipWs()
                if (s.getOrNull(i) != '"') throw Rejected("invalid_json", "expected key")
                val key = readString()
                skipWs()
                if (s.getOrNull(i) != ':') throw Rejected("invalid_json", "expected ':'")
                i++
                skipWs()
                val value = readValue()
                if (map.containsKey(key)) throw Rejected("duplicate_key", key)
                map[key] = value
                skipWs()
                when (s.getOrNull(i)) {
                    ',' -> i++
                    '}' -> { i++; depth--; return map }
                    else -> throw Rejected("invalid_json", "expected ',' or '}'")
                }
            }
        }

        private fun readString(): String {
            i++ // opening quote
            val sb = StringBuilder()
            while (true) {
                val c = s.getOrNull(i++) ?: throw Rejected("invalid_json", "unterminated string")
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        when (val e = s.getOrNull(i++)) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000C'); 'n' -> sb.append('\n')
                            'r' -> sb.append('\r'); 't' -> sb.append('\t')
                            'u' -> sb.append(readHex4())
                            else -> throw Rejected("invalid_json", "bad escape '\\$e'")
                        }
                    }
                    c < ' ' -> throw Rejected("invalid_json", "unescaped control character")
                    else -> sb.append(c)
                }
                // A lone surrogate from a \\u escape cannot be encoded as UTF-8,
                // so the canonical re-encoding check in parse() rejects it.
            }
        }

        private fun readHex4(): Char {
            if (i + 4 > s.length) throw Rejected("invalid_json", "short \\u escape")
            val hex = s.substring(i, i + 4)
            if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) throw Rejected("invalid_json", "bad \\u escape")
            i += 4
            return hex.toInt(16).toChar()
        }

        private fun skipWs() { while (i < s.length && s[i] in " \t\r\n") i++ }
    }
}
