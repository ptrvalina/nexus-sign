package com.nexis.nexussign

import java.security.MessageDigest
import java.util.Base64

/** The mandate terms as signed, parsed and checked by the SDK (payment mandates v1). */
data class NexusMandateTerms(
    val mandateId: String,
    val nexusId: String,
    val credentialId: String,
    val mandateReference: String,
    val payee: Map<String, String>,
    val currency: String,
    val perPaymentLimitMinor: String,
    val totalLimitMinor: String?,
    val frequency: String,
    val validFrom: String,
    val validUntil: String,
    val termsVersion: String,
    val offerExpiresAt: String,
) {
    /** The text of the biometric prompt, built from the signed terms only. */
    fun confirmationText(): String {
        val digits = SignedPayload.fractionDigits(currency)
        val lines = mutableListOf(
            "Recurring payments to",
            payee.keys.sorted().joinToString("\n") { "$it: ${payee.getValue(it)}" },
            "Up to ${SignedPayload.formatMinorUnits(perPaymentLimitMinor, digits)} $currency per payment, ${frequency.lowercase()}",
        )
        totalLimitMinor?.let { lines += "At most ${SignedPayload.formatMinorUnits(it, digits)} $currency in total" }
        lines += "Valid $validFrom – $validUntil"
        lines += "Mandate $mandateReference, conditions $termsVersion"
        return lines.joinToString("\n")
    }
}

/**
 * Parses the canonical terms of a payment mandate and refuses anything the
 * device must not show or sign: other domain (payment bytes), another mandate
 * or device, bytes that do not hash to termsHash or are not canonical, a
 * missing or unexpected field, a value breaking the display rules, an IBAN
 * with wrong check digits, or inconsistent limits and validity. Pure Kotlin,
 * so it runs in the JVM tests against auth-core/test-vectors/mandate-terms-v1.json.
 */
internal object MandateTermsParser {
    const val DOMAIN = "NEXUS-SIGN/MANDATE"
    private val FIELDS = setOf(
        "protocol_version", "domain", "mandate_id", "nexus_id", "credential_id", "mandate_reference", "payee", "currency",
        "per_payment_limit_minor", "total_limit_minor", "frequency", "valid_from", "valid_until", "terms_version",
        "issued_at", "offer_expires_at", "nonce",
    )
    private val FREQUENCIES = setOf("WEEKLY", "MONTHLY", "QUARTERLY", "YEARLY")
    private val MINOR = Regex("^[1-9][0-9]{0,29}$")
    private val CURRENCY = Regex("^[A-Z]{3}$")
    private val TIMESTAMP = Regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$")

    fun parse(termsBase64: String, termsHash: String, mandateId: String, credentialId: String): NexusMandateTerms {
        val bytes = try { Base64.getDecoder().decode(termsBase64) } catch (e: IllegalArgumentException) { throw SignedPayload.Rejected("invalid_json", "termsBase64") }
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        if (hash != termsHash) throw SignedPayload.Rejected("hash_mismatch", "termsHash")
        val o = SignedPayload.parseCanonicalObject(bytes, allowNull = true)
        val keys = o.keys.map { it as String }.toSet()
        (FIELDS - keys).takeIf { it.isNotEmpty() }?.let { throw SignedPayload.Rejected("missing_field", it.sorted().joinToString()) }
        (keys - FIELDS).takeIf { it.isNotEmpty() }?.let { throw SignedPayload.Rejected("unexpected_field", it.sorted().joinToString()) }
        fun str(key: String): String = o[key] as? String ?: throw SignedPayload.Rejected("invalid_value", "$key must be a string")
        fun shown(key: String): String = str(key).also { if (SignedPayload.displayTextViolation(it) != null) throw SignedPayload.Rejected("display", key) }

        if (str("protocol_version") != "1" || str("domain") != DOMAIN) throw SignedPayload.Rejected("wrong_domain", "not mandate terms v1")
        if (str("mandate_id") != mandateId) throw SignedPayload.Rejected("mismatch", "mandate_id")
        if (str("credential_id") != credentialId) throw SignedPayload.Rejected("wrong_device", "the mandate is for another device")
        val payeeRaw = o["payee"] as? Map<*, *> ?: throw SignedPayload.Rejected("invalid_value", "payee must be an object")
        if (payeeRaw.isEmpty()) throw SignedPayload.Rejected("invalid_value", "payee is empty")
        val payee = payeeRaw.entries.associate { (k, v) ->
            val key = k as String
            val value = v as? String ?: throw SignedPayload.Rejected("invalid_value", "payee.$key must be a string")
            if (SignedPayload.displayTextViolation(value) != null) throw SignedPayload.Rejected("display", "payee.$key")
            key to value
        }
        payee["iban"]?.let { if (!SignedPayload.isValidIban(it)) throw SignedPayload.Rejected("iban", "payee.iban") }
        val currency = str("currency").also { if (!CURRENCY.matches(it)) throw SignedPayload.Rejected("invalid_value", "currency") }
        val perPayment = str("per_payment_limit_minor").also { if (!MINOR.matches(it)) throw SignedPayload.Rejected("invalid_value", "per_payment_limit_minor") }
        val total = when (val t = o["total_limit_minor"]) {
            SignedPayload.JsonNull -> null
            is String -> t.also {
                if (!MINOR.matches(it) || it.toBigInteger() < perPayment.toBigInteger()) throw SignedPayload.Rejected("invalid_value", "total_limit_minor")
            }
            else -> throw SignedPayload.Rejected("invalid_value", "total_limit_minor")
        }
        val frequency = str("frequency").also { if (it !in FREQUENCIES) throw SignedPayload.Rejected("invalid_value", "frequency") }
        val validFrom = str("valid_from"); val validUntil = str("valid_until")
        for ((k, v) in listOf("valid_from" to validFrom, "valid_until" to validUntil, "issued_at" to str("issued_at"), "offer_expires_at" to str("offer_expires_at"))) {
            if (!TIMESTAMP.matches(v)) throw SignedPayload.Rejected("invalid_value", k)
        }
        // RFC 3339 UTC with the same precision compares in string order.
        if (java.time.Instant.parse(validUntil) <= java.time.Instant.parse(validFrom)) throw SignedPayload.Rejected("invalid_value", "valid_until")
        return NexusMandateTerms(
            mandateId = mandateId, nexusId = shown("nexus_id"), credentialId = credentialId, mandateReference = shown("mandate_reference"),
            payee = payee, currency = currency, perPaymentLimitMinor = perPayment, totalLimitMinor = total, frequency = frequency,
            validFrom = validFrom, validUntil = validUntil, termsVersion = shown("terms_version"), offerExpiresAt = str("offer_expires_at"),
        )
    }
}
