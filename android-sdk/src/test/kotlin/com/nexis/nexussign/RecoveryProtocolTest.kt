package com.nexis.nexussign

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Recovery protocol 2 must match iOS and Auth Core byte for byte (vectors in
 * recovery-v2.json, generated with Node.js), or a phrase set up on one
 * platform could not recover the identity on the other.
 */
class RecoveryProtocolTest {
    private val v: Map<*, *> by lazy {
        TestJson.parse(javaClass.classLoader!!.getResource("recovery-v2.json")!!.readText()) as Map<*, *>
    }
    private val proof get() = v["proof"] as Map<*, *>
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun str(key: String) = v[key] as String

    @Suppress("UNCHECKED_CAST")
    private val phrase get() = v["phrase"] as List<String>
    private val salt get() = Base64.getDecoder().decode(str("salt_b64"))
    private val iterations get() = str("iterations").toInt()
    private val recoverySpki get() = RecoveryProtocol.spkiFromPem(str("recovery_public_key_pem"))

    @Test
    fun `seed and wrapping key match the vectors`() {
        val seed = RecoveryProtocol.seed(phrase, salt, iterations)
        assertArrayEquals(hex(str("seed_hex")), seed)
        assertArrayEquals(hex(str("wrap_key_hex")), RecoveryProtocol.wrapKey(seed, str("nexus_id")))
    }

    @Test
    fun `the recovery key wraps to the vector bytes and unwraps back`() {
        val wrapKey = hex(str("wrap_key_hex"))
        val aad = RecoveryProtocol.associatedData(str("nexus_id"), recoverySpki)
        assertEquals(str("wrap_aad_utf8"), aad.toString(Charsets.UTF_8))
        val scalar = hex(str("recovery_private_scalar_hex"))
        val wrapped = RecoveryProtocol.wrap(scalar, wrapKey, aad, hex(str("wrap_iv_hex")))
        assertArrayEquals(Base64.getDecoder().decode(str("wrapped_recovery_key_b64")), wrapped)
        assertArrayEquals(scalar, RecoveryProtocol.unwrap(wrapped, wrapKey, aad))
    }

    @Test
    fun `a wrong phrase or another identity cannot open the wrapped key`() {
        val wrapped = Base64.getDecoder().decode(str("wrapped_recovery_key_b64"))
        @Suppress("UNCHECKED_CAST")
        val wrongPhrase = ((v["invalid"] as List<*>)[0] as Map<*, *>)["phrase"] as List<String>
        val wrongKey = RecoveryProtocol.wrapKey(RecoveryProtocol.seed(wrongPhrase, salt, iterations), str("nexus_id"))
        assertThrows(NEXUSSignError.InvalidRecoveryPhrase::class.java) {
            RecoveryProtocol.unwrap(wrapped, wrongKey, RecoveryProtocol.associatedData(str("nexus_id"), recoverySpki))
        }
        assertThrows(NEXUSSignError.InvalidRecoveryPhrase::class.java) {
            RecoveryProtocol.unwrap(wrapped, hex(str("wrap_key_hex")), RecoveryProtocol.associatedData("987654321", recoverySpki))
        }
    }

    @Test
    fun `setup and proof signing inputs match, and the vector proof verifies`() {
        val wrapped = Base64.getDecoder().decode(str("wrapped_recovery_key_b64"))
        val setup = RecoveryProtocol.setupSigningInput(str("nexus_id"), str("credential_id"), str("salt_b64"), recoverySpki, wrapped)
        assertEquals(str("setup_signing_input_utf8"), setup.toString(Charsets.UTF_8))
        val input = RecoveryProtocol.proofSigningInput(proof["session_id"] as String, proof["nonce_b64"] as String, str("nexus_id"),
            RecoveryProtocol.spkiFromPem(proof["new_signing_public_key_pem"] as String))
        assertEquals(proof["signing_input_utf8"], input.toString(Charsets.UTF_8))
        assertTrue(verifies(str("recovery_public_key_pem"), input, Base64.getDecoder().decode(proof["signature_der_b64"] as String)))
    }

    @Test
    fun `a key restored from its scalar signs for its public key`() {
        val restored = RecoveryProtocol.privateKey(hex(str("recovery_private_scalar_hex")))
        val data = "probe".toByteArray()
        assertTrue(verifies(str("recovery_public_key_pem"), data, RecoveryProtocol.sign(restored, data)))

        val fresh = RecoveryProtocol.newRecoveryKey()
        val scalar = RecoveryProtocol.scalar(fresh.private)
        assertEquals(32, scalar.size)
        val again = RecoveryProtocol.sign(RecoveryProtocol.privateKey(scalar), data)
        assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(fresh.public); update(data); verify(again) })
    }

    @Suppress("UNCHECKED_CAST")
    @Test
    fun `the phrase is normalized before derivation (protocol 1 vectors)`() {
        val v1 = (TestJson.parse(javaClass.classLoader!!.getResource("signed-payload-v1.json")!!.readText()) as Map<*, *>)["recovery"] as Map<*, *>
        val b64 = { k: String -> Base64.getDecoder().decode(v1["${k}_base64"] as String) }
        val iterations = (v1["iterations"] as String).toInt()
        assertArrayEquals(b64("verifier"), RecoveryProtocol.seed(v1["phrase"] as List<String>, b64("salt"), iterations))
        assertArrayEquals(b64("verifier"), RecoveryProtocol.seed(v1["phrase_unnormalized"] as List<String>, b64("salt"), iterations))
    }

    private fun verifies(publicKeyPem: String, data: ByteArray, signature: ByteArray): Boolean {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(RecoveryProtocol.spkiFromPem(publicKeyPem)))
        return Signature.getInstance("SHA256withECDSA").run { initVerify(key); update(data); verify(signature) }
    }
}
