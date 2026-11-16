package com.nexis.nexussign

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * Runs the shared payment mandate terms vectors
 * (auth-core/test-vectors/mandate-terms-v1.json): the SDK accepts the terms
 * Auth Core builds, field for field, and refuses the others with the expected
 * reason before anything is shown or signed.
 */
class MandateTermsVectorsTest {
    private val vectors: Map<*, *> by lazy {
        TestJson.parse(javaClass.classLoader!!.getResource("mandate-terms-v1.json")!!.readText()) as Map<*, *>
    }

    private fun parse(v: Map<*, *>) = MandateTermsParser.parse(v["termsBase64"] as String, v["termsHash"] as String, v["mandateId"] as String, v["credentialId"] as String)

    @Test
    fun `valid terms parse to the signed fields`() {
        val valid = vectors["valid"] as List<*>
        assertEquals(3, valid.size)
        for (item in valid) {
            val v = item as Map<*, *>
            val expected = v["expected"] as Map<*, *>
            val terms = parse(v)
            assertEquals(v["name"].toString(), expected["per_payment_limit_minor"], terms.perPaymentLimitMinor)
            assertEquals(expected["total_limit_minor"], terms.totalLimitMinor)
            assertEquals(expected["payee"], terms.payee)
            assertEquals(expected["currency"], terms.currency)
            assertEquals(expected["frequency"], terms.frequency)
            assertEquals(expected["valid_until"], terms.validUntil)
            assertEquals(expected["mandate_reference"], terms.mandateReference)
        }
    }

    @Test
    fun `invalid terms are refused with the expected reason`() {
        val invalid = vectors["invalid"] as List<*>
        assertEquals(15, invalid.size)
        for (item in invalid) {
            val v = item as Map<*, *>
            try {
                parse(v)
                fail("accepted: ${v["name"]}")
            } catch (e: SignedPayload.Rejected) {
                assertEquals(v["name"].toString(), v["reason"], e.reason)
            }
        }
    }

    @Test
    fun `the prompt text comes from the signed terms`() {
        val terms = parse((vectors["valid"] as List<*>)[1] as Map<*, *>)
        val text = terms.confirmationText()
        assert(text.contains("Up to 150.00 EUR per payment, yearly")) { text }
        assert(text.contains("At most 1200.00 EUR in total")) { text }
        assert(text.contains("iban: DE89370400440532013000")) { text }
    }
}
