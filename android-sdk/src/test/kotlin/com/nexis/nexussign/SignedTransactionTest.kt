package com.nexis.nexussign

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Runs the shared WYSIWYS vectors (auth-core/test-vectors/signed-payload-v1.json,
 * copied to src/test/resources) through the Android parser. Plain JVM test;
 * no Android runtime needed.
 */
class SignedTransactionTest {

    private val vectors: Map<*, *> by lazy {
        val text = javaClass.classLoader!!.getResource("signed-payload-v1.json")!!.readText()
        TestJson.parse(text) as Map<*, *>
    }

    private fun b64(s: String): ByteArray = java.util.Base64.getDecoder().decode(s)

    @Test
    fun `valid vectors parse to the signed fields and re-encode byte for byte`() {
        val valid = vectors["valid"] as List<*>
        assertTrue(valid.isNotEmpty())
        for (raw in valid) {
            val v = raw as Map<*, *>
            val fields = v["fields"] as Map<*, *>
            val signed = SignedPayload.parse(b64(v["canonical_base64"] as String))
            assertEquals(v["name"].toString(), fields["amount_minor"], signed.amountMinor)
            assertEquals(v["name"].toString(), fields["currency"], signed.currency)
            assertEquals(v["name"].toString(), fields["beneficiary"], signed.beneficiary)
            assertEquals(v["name"].toString(), fields["transaction_reference"], signed.transactionReference)
            assertEquals(v["name"].toString(), fields["expires_at"], signed.expiresAt)
            assertEquals(v["name"].toString(), fields["policy_version"], signed.policyVersion)
        }
    }

    @Test
    fun `invalid vectors are rejected with the expected reason`() {
        val invalid = vectors["invalid"] as List<*>
        assertTrue(invalid.size >= 10)
        for (raw in invalid) {
            val v = raw as Map<*, *>
            try {
                SignedPayload.parse(b64(v["canonical_base64"] as String))
                fail("accepted invalid vector: ${v["name"]}")
            } catch (e: SignedPayload.Rejected) {
                assertEquals("reason for '${v["name"]}'", v["reason"], e.reason)
            }
        }
    }

    @Test
    fun `response fields that disagree with the signed bytes are refused`() {
        val block = vectors["response_mismatch"] as Map<*, *>
        val baseB64 = block["base_canonical_base64"] as String
        val signed = SignedPayload.parse(b64(baseB64))
        val good = envelopeFor(signed, baseB64, block["base_canonical_sha256"] as String)
        assertEquals(signed, SignedPayload.verify(good))

        for (raw in block["cases"] as List<*>) {
            val c = raw as Map<*, *>
            val tampered = when (c["field"]) {
                "amountMinor" -> good.copy(amountMinor = c["value"] as String)
                "currency" -> good.copy(currency = c["value"] as String)
                "beneficiary" -> good.copy(beneficiary = (c["value"] as Map<*, *>).entries.associate { (k, v) -> k as String to v as String })
                "transactionReference" -> good.copy(transactionReference = c["value"] as String)
                "expiresAt" -> good.copy(expiresAt = c["value"] as String)
                "authorizationId" -> good.copy(authorizationId = c["value"] as String)
                "canonicalPayloadHash" -> good.copy(canonicalPayloadHash = c["value"] as String)
                else -> error("unknown field ${c["field"]}")
            }
            try {
                SignedPayload.verify(tampered)
                fail("accepted mismatch: ${c["name"]}")
            } catch (e: SignedPayload.Rejected) {
                assertEquals("response_mismatch", e.reason)
            }
        }
    }

    @Test
    fun `amounts are formatted with integer arithmetic`() {
        for (raw in vectors["amount_formatting"] as List<*>) {
            val v = raw as Map<*, *>
            val digits = (v["fraction_digits"] as String).toInt()
            assertEquals(v["expected"], SignedPayload.formatMinorUnits(v["amount_minor"] as String, digits))
        }
        assertEquals(2, SignedPayload.fractionDigits("PLN"))
        assertEquals(0, SignedPayload.fractionDigits("JPY"))
        assertEquals(3, SignedPayload.fractionDigits("KWD"))
        // ISO 4217, where CLDR (and so Android's java.util.Currency) differs.
        assertEquals(2, SignedPayload.fractionDigits("RSD"))
        assertEquals(3, SignedPayload.fractionDigits("IQD"))
        assertEquals(4, SignedPayload.fractionDigits("CLF"))
    }

    @Test
    fun `prompt text and beneficiary display match the shared vectors`() {
        for (raw in vectors["valid"] as List<*>) {
            val v = raw as Map<*, *>
            val signed = SignedPayload.parse(b64(v["canonical_base64"] as String))
            assertEquals(v["name"].toString(), v["beneficiary_display"], signed.beneficiaryDisplay())
            assertEquals(v["name"].toString(), v["confirmation_text"], signed.confirmationText())
        }
        val block = vectors["response_mismatch"] as Map<*, *>
        val signed = SignedPayload.parse(b64(block["base_canonical_base64"] as String))
        assertEquals("1250.00 PLN\nIBAN: PL61109010140000071219812874\nName: Jan Kowalski\ntransfer • BANK-2026-000001", signed.confirmationText())
        // Translated labels label the same values in the same order.
        assertEquals("1250.00 PLN\nRachunek: PL61109010140000071219812874\nOdbiorca: Jan Kowalski\ntransfer • BANK-2026-000001",
            signed.confirmationText(NexusPromptLabels(iban = "Rachunek", name = "Odbiorca")))
    }

    private fun envelopeFor(s: NexusSignedTransaction, b64: String, sha: String) = AuthorizationEnvelope(
        authorizationId = s.authorizationId, nexusId = s.nexusId, credentialId = s.credentialId,
        transactionReference = s.transactionReference, operationType = s.operationType,
        amountMinor = s.amountMinor, currency = s.currency, beneficiary = s.beneficiary,
        policyReference = s.policyReference, policyVersion = s.policyVersion,
        issuedAt = s.issuedAt, expiresAt = s.expiresAt, canonicalPayloadHash = sha, canonicalPayloadBase64 = b64,
    )
}
