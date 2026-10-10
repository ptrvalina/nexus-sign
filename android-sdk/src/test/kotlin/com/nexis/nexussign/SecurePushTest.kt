package com.nexis.nexussign

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec

/**
 * Secure push v1 must match Auth Core and iOS byte for byte (vectors in
 * secure-push-v1.json, generated independently in Node.js), or the app could
 * not open a single message.
 */
class SecurePushTest {
    private val vectors: Map<*, *> by lazy {
        TestJson.parse(javaClass.classLoader!!.getResource("secure-push-v1.json")!!.readText()) as Map<*, *>
    }
    private val agreement get() = vectors["key_agreement"] as Map<*, *>
    private val credentialId get() = agreement["credential_id"] as String
    private val pushKey get() = hex(agreement["push_key_hex"] as String)

    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** TestJson reads numbers as strings. */
    private fun envelope(value: Any?): NexusPushEnvelope {
        val m = value as Map<*, *>
        return NexusPushEnvelope((m["v"] as String).toInt(), m["id"] as String, m["cid"] as String, m["iv"] as String, m["ct"] as String)
    }

    @Test
    fun `key agreement matches the vectors`() {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val device = KeyFactory.getInstance("EC").generatePrivate(
            ECPrivateKeySpec(BigInteger(agreement["device_private_scalar_hex"] as String, 16), params),
        )
        val server = KeyFactory.getInstance("EC").generatePublic(
            X509EncodedKeySpec(Base64.getDecoder().decode((agreement["server_public_key_pem"] as String).lines().filterNot { it.startsWith("-----") }.joinToString(""))),
        )
        val shared = KeyAgreement.getInstance("ECDH").run {
            init(device)
            doPhase(server, true)
            generateSecret()
        }
        assertArrayEquals(hex(agreement["shared_secret_hex"] as String), shared)
        assertArrayEquals(pushKey, PushProtocol.derivePushKey(shared, credentialId))
        assertEquals(agreement["key_id"], PushProtocol.keyId(SecretKeySpec(pushKey, "HmacSHA256")))
    }

    @Test
    fun `every vector message opens, parses and has the vector receipt`() {
        for (m in vectors["messages"] as List<*>) {
            m as Map<*, *>
            val name = m["name"] as String
            val sealed = envelope(m["envelope"])
            val plaintext = PushProtocol.open(sealed, SecretKeySpec(pushKey, "AES"))
            assertEquals(name, m["plaintext_utf8"], plaintext.toString(Charsets.UTF_8))
            assertArrayEquals(name, (m["aad_utf8"] as String).toByteArray(Charsets.UTF_8), PushProtocol.associatedData(sealed.id, credentialId))
            assertEquals(name, m["receipt"], PushProtocol.receipt(SecretKeySpec(pushKey, "HmacSHA256"), sealed.id, credentialId))

            val message = PushMessages.parse(sealed, plaintext)
            assertEquals(name, sealed.id, message.messageId)
            assertEquals(name, credentialId, message.credentialId)
        }
    }

    @Test
    fun `the authorization request vector carries its authorization ID`() {
        val m = (vectors["messages"] as List<*>)[1] as Map<*, *>
        val sealed = envelope(m["envelope"])
        val message = PushMessages.parse(sealed, PushProtocol.open(sealed, SecretKeySpec(pushKey, "AES")))
        assertEquals(NexusPushCategory.AUTHORIZATION_REQUEST, message.category)
        assertEquals("00000000-0000-4000-8000-000000000001", message.authorizationId)
        assertEquals(Instant.parse("2026-10-01T09:31:00.000Z"), message.sentAt)
    }

    @Test
    fun `every invalid vector is refused`() {
        for (c in vectors["invalid"] as List<*>) {
            c as Map<*, *>
            assertThrows(c["name"] as String, NEXUSSignError.PushMessageInvalid::class.java) {
                PushProtocol.open(envelope(c["envelope"]), SecretKeySpec(pushKey, "AES"))
            }
        }
    }

    @Test
    fun `the envelope is read from the FCM data map only`() {
        val first = (vectors["messages"] as List<*>)[0] as Map<*, *>
        val sealed = envelope(first["envelope"])
        val wire = """{"v":1,"id":"${sealed.id}","cid":"${sealed.cid}","iv":"${sealed.iv}","ct":"${sealed.ct}"}"""
        assertEquals(sealed, PushMessages.envelopeOf(mapOf("nexus" to wire)))
        assertNull(PushMessages.envelopeOf(mapOf("title" to "Hello")))
        assertNull(PushMessages.envelopeOf(mapOf("nexus" to "not json")))
    }

    @Test
    fun `text with format characters is not shown`() {
        val content = "{\"v\":1,\"category\":\"GENERAL\",\"title\":\"Pay\u202Eme\",\"body\":\"\",\"authorizationId\":null,\"data\":{},\"sentAt\":\"2026-10-01T09:30:00.000Z\"}"
        val sealed = NexusPushEnvelope(1, "00000000-0000-4000-8000-0000000000c1", credentialId, "AAAAAAAAAAAAAAAA", "AAAA")
        assertThrows(NEXUSSignError.PushMessageInvalid::class.java) { PushMessages.parse(sealed, content.toByteArray(Charsets.UTF_8)) }
    }
}
