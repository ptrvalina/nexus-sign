package com.nexis.nexussign

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * The signing key fingerprint the SDK reports to the bank's app must be the
 * value the bank's check computes (bank-trust-v1.json, generated in Node.js).
 */
class BankTrustVectorsTest {
    private val vectors: Map<*, *> by lazy {
        TestJson.parse(javaClass.classLoader!!.getResource("bank-trust-v1.json")!!.readText()) as Map<*, *>
    }

    @Test fun `signing key fingerprints match the vectors`() {
        val cases = vectors["fingerprints"] as List<*>
        assertEquals(2, cases.size)
        for (case in cases) {
            case as Map<*, *>
            val pem = case["publicKeyPem"] as String
            val der = Base64.getDecoder().decode(pem.lines().filterNot { it.startsWith("-----") }.joinToString(""))
            // A Java EC public key encodes to the same SubjectPublicKeyInfo.
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
            assertArrayEquals(Base64.getDecoder().decode(case["spkiDerBase64"] as String), key.encoded)
            assertEquals(case["name"].toString(), case["signingKeySha256"], DeviceProtocol.signingKeyFingerprint(key.encoded))
        }
    }
}
