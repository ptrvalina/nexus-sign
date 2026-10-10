package com.nexis.nexussign

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Recovery protocol 2, identical on Android, iOS and Auth Core (vectors in
 * `recovery-v2.json`, specification in docs/protocol/recovery-protocol-v2.md):
 *
 *     seed    = PBKDF2-HMAC-SHA256(normalized phrase, salt, iterations, 32)
 *     wrapKey = HKDF-SHA256(seed, salt "NEXUS-SIGN/RECOVERY-WRAP/v2", info nexusId)
 *     wrapped = iv || AES-256-GCM(wrapKey, iv, recovery private scalar, associatedData)
 *
 * The recovery key pair is generated in memory (it must be restorable on a
 * new device, so it cannot live in the Keystore); its private half exists on
 * the device only while a phrase is set up or used, and Auth Core holds only
 * the public key and `wrapped`.
 */
internal object RecoveryProtocol {
    const val PROTOCOL = 2
    const val KDF = "PBKDF2-HMAC-SHA256"
    const val KEY_LENGTH = 32
    val ITERATION_RANGE = 100_000..5_000_000
    const val MIN_SALT_BYTES = 16
    private const val WRAP_SALT = "NEXUS-SIGN/RECOVERY-WRAP/v2"
    private const val IV_LENGTH = 12
    private const val TAG_BITS = 128
    private const val WRAPPED_LENGTH = IV_LENGTH + 32 + TAG_BITS / 8

    fun seed(phrase: List<String>, salt: ByteArray, iterations: Int): ByteArray {
        // The words are ASCII, so the char-based PBEKeySpec yields the same
        // bytes as the UTF-8 encoding used by the other implementations.
        val password = RecoveryPhrase.normalized(phrase).joinToString(" ").toCharArray()
        val spec = PBEKeySpec(password, salt, iterations, KEY_LENGTH * 8)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
            password.fill(' ')
        }
    }

    fun wrapKey(seed: ByteArray, nexusId: String): ByteArray =
        Hkdf.sha256(seed, WRAP_SALT.toByteArray(Charsets.UTF_8), nexusId.toByteArray(Charsets.UTF_8))

    fun associatedData(nexusId: String, recoveryPublicKeySpki: ByteArray): ByteArray =
        "NEXUS-SIGN/RECOVERY-KEY/v2\n$nexusId\n${sha256Hex(recoveryPublicKeySpki)}".toByteArray(Charsets.UTF_8)

    fun newRecoveryKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
            generateKeyPair()
        }

    /** The private scalar as 32 big-endian bytes. */
    fun scalar(privateKey: PrivateKey): ByteArray {
        val s = (privateKey as ECPrivateKey).s.toByteArray()
        return when {
            s.size == 32 -> s
            s.size > 32 -> s.copyOfRange(s.size - 32, s.size) // leading sign byte
            else -> ByteArray(32 - s.size) + s
        }
    }

    fun privateKey(scalar: ByteArray): PrivateKey {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, scalar), params))
    }

    fun wrap(scalar: ByteArray, wrapKey: ByteArray, associatedData: ByteArray, iv: ByteArray = ByteArray(IV_LENGTH).also { SecureRandom().nextBytes(it) }): ByteArray {
        require(scalar.size == 32 && iv.size == IV_LENGTH)
        val sealed = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(wrapKey, "AES"), GCMParameterSpec(TAG_BITS, iv))
            updateAAD(associatedData)
            doFinal(scalar)
        }
        return iv + sealed
    }

    /** The recovery private scalar; a wrong phrase fails the GCM tag. */
    fun unwrap(wrapped: ByteArray, wrapKey: ByteArray, associatedData: ByteArray): ByteArray {
        if (wrapped.size != WRAPPED_LENGTH) throw NEXUSSignError.ServerError(0, "Invalid wrapped recovery key")
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(wrapKey, "AES"), GCMParameterSpec(TAG_BITS, wrapped.copyOfRange(0, IV_LENGTH)))
                updateAAD(associatedData)
                doFinal(wrapped, IV_LENGTH, wrapped.size - IV_LENGTH)
            }
        } catch (e: AEADBadTagException) {
            throw NEXUSSignError.InvalidRecoveryPhrase
        }
    }

    /** Signed with the biometric signing key to register a recovery key. */
    fun setupSigningInput(nexusId: String, credentialId: String, saltBase64: String, recoveryPublicKeySpki: ByteArray, wrapped: ByteArray): ByteArray =
        listOf("NEXUS-SIGN/RECOVERY-SETUP/v2", nexusId, credentialId, saltBase64, sha256Hex(recoveryPublicKeySpki), sha256Hex(wrapped))
            .joinToString("\n").toByteArray(Charsets.UTF_8)

    /** Signed with the recovery key: binds the proof to the session and the new device key. */
    fun proofSigningInput(sessionId: String, nonceBase64: String, nexusId: String, newSigningKeySpki: ByteArray): ByteArray =
        listOf("NEXUS-SIGN/RECOVERY-PROOF/v2", sessionId, nonceBase64, nexusId, sha256Hex(newSigningKeySpki))
            .joinToString("\n").toByteArray(Charsets.UTF_8)

    /** SubjectPublicKeyInfo DER of a PEM public key. */
    fun spkiFromPem(pem: String): ByteArray =
        java.util.Base64.getDecoder().decode(pem.lineSequence().filterNot { it.startsWith("-----") }.joinToString("").trim())

    /** ECDSA P-256 / SHA-256, DER. */
    fun sign(privateKey: PrivateKey, input: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(input)
            sign()
        }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
