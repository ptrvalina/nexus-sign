package com.nexis.nexussign

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.KeyAgreement

/**
 * Device protocols v1 must match Auth Core and iOS byte for byte (vectors in
 * device-protocols-v1.json, generated independently in Node.js), or requests
 * would be rejected and offline codes would never match.
 */
class DeviceProtocolTest {
    private val vectors: Map<*, *> by lazy {
        val text = javaClass.classLoader!!.getResource("device-protocols-v1.json")!!.readText()
        TestJson.parse(text) as Map<*, *>
    }
    private val requests get() = (vectors["device_request"] as Map<*, *>)
    private val offline get() = (vectors["offline"] as Map<*, *>)

    private fun publicKey(pem: String): PublicKey =
        KeyFactory.getInstance("EC").generatePublic(
            X509EncodedKeySpec(Base64.getDecoder().decode(pem.lines().filterNot { it.startsWith("-----") }.joinToString(""))),
        )

    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun `request signing input matches the vectors and the sample signatures verify`() {
        val key = publicKey(requests["auth_public_key_pem"] as String)
        for (r in requests["requests"] as List<*>) {
            r as Map<*, *>
            val input = DeviceProtocol.requestSigningInput(
                r["method"] as String, r["path"] as String, r["timestamp"] as String, r["nonce"] as String,
                r["credential_id"] as String, (r["body"] as String).toByteArray(Charsets.UTF_8),
            )
            assertArrayEquals(r["name"] as String, Base64.getDecoder().decode(r["signing_input_base64"] as String), input)
            val verifier = Signature.getInstance("SHA256withECDSA").apply { initVerify(key); update(input) }
            assertTrue(r["name"] as String, verifier.verify(Base64.getDecoder().decode(r["sample_signature_der_base64"] as String)))
        }
    }

    @Test
    fun `ECDH, key derivation, tag and code match the vectors`() {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val devicePrivate = KeyFactory.getInstance("EC").generatePrivate(
            ECPrivateKeySpec(BigInteger(offline["device_private_scalar_hex"] as String, 16), params),
        )
        val shared = KeyAgreement.getInstance("ECDH").run {
            init(devicePrivate)
            doPhase(publicKey(offline["server_public_key_pem"] as String), true)
            generateSecret()
        }
        assertArrayEquals(hex(offline["shared_secret_hex"] as String), shared)

        val key = DeviceProtocol.deriveOfflineKey(shared, offline["credential_id"] as String)
        assertArrayEquals(hex(offline["offline_key_hex"] as String), key)

        for (c in offline["confirmations"] as List<*>) {
            c as Map<*, *>
            val qrBytes = DeviceProtocol.qrPayloadBytes(c["qr_payload"] as String)
            assertArrayEquals(Base64.getDecoder().decode(c["canonical_base64"] as String), qrBytes)
            val tag = DeviceProtocol.offlineTag(key, qrBytes)
            assertArrayEquals(Base64.getDecoder().decode(c["tag_base64"] as String), tag)
            assertEquals(c["code"], DeviceProtocol.offlineCode(tag))
            // The QR carries a payload the strict parser accepts.
            SignedPayload.parse(qrBytes)
        }
    }

    @Test
    fun `unknown QR formats are rejected`() {
        assertThrows(NEXUSSignError.AuthorizationPayloadInvalid::class.java) { DeviceProtocol.qrPayloadBytes("https://example.com") }
        assertThrows(NEXUSSignError.AuthorizationPayloadInvalid::class.java) { DeviceProtocol.qrPayloadBytes("NXS1.***") }
    }

    @Test
    fun `key attestation challenge matches the vector`() {
        val v = vectors["key_attestation"] as Map<*, *>
        assertArrayEquals(
            hex(v["key_attestation_challenge_hex"] as String),
            DeviceProtocol.keyAttestationChallenge(hex(v["enrolment_challenge_hex"] as String)),
        )
    }
}
