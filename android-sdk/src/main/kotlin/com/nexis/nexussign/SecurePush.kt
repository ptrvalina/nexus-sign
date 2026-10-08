package com.nexis.nexussign

import android.content.Context
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.security.KeyStore
import java.time.Instant
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Secure push v1, identical in Auth Core and the iOS SDK (vectors in
 * `secure-push-v1.json`; specification in docs/protocol/secure-push.md):
 *
 * - the push key, agreed once per device credential over ECDH P-256 and HKDF-SHA256;
 * - AES-256-GCM envelopes bound to the message and credential IDs;
 * - the delivery receipt, an HMAC under the push key;
 * - the key ID both sides compare at every token refresh.
 */
internal object PushProtocol {
    const val DOMAIN = "NEXUS-SIGN/PUSH/v1"
    const val RECEIPT_DOMAIN = "NEXUS-SIGN/PUSH-RECEIPT/v1"
    const val KEY_ID_DOMAIN = "NEXUS-SIGN/PUSH-KEY-ID/v1"
    private const val IV_LENGTH = 12
    private const val TAG_BITS = 128

    /** HKDF-SHA256 (RFC 5869), one output block, salt = domain, info = credential ID. */
    fun derivePushKey(sharedSecret: ByteArray, credentialId: String): ByteArray {
        require(sharedSecret.size == 32) { "ECDH shared secret must be 32 bytes" }
        return Hkdf.sha256(sharedSecret, DOMAIN.toByteArray(Charsets.UTF_8), credentialId.toByteArray(Charsets.UTF_8))
    }

    fun associatedData(messageId: String, credentialId: String): ByteArray =
        "$DOMAIN\n$messageId\n$credentialId".toByteArray(Charsets.UTF_8)

    fun receiptInput(messageId: String, credentialId: String): ByteArray =
        "$RECEIPT_DOMAIN\n$messageId\n$credentialId".toByteArray(Charsets.UTF_8)

    /** The plaintext of a sealed envelope; throws if anything was altered. */
    fun open(envelope: NexusPushEnvelope, key: SecretKey): ByteArray {
        if (envelope.v != 1) throw NEXUSSignError.PushMessageInvalid("unsupported_version")
        val iv = decodeBase64Url(envelope.iv)
        val sealed = decodeBase64Url(envelope.ct)
        if (iv == null || iv.size != IV_LENGTH || sealed == null || sealed.size <= TAG_BITS / 8) {
            throw NEXUSSignError.PushMessageInvalid("malformed_envelope")
        }
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
                updateAAD(associatedData(envelope.id, envelope.cid))
                doFinal(sealed)
            }
        } catch (e: Exception) {
            throw NEXUSSignError.PushMessageInvalid("decryption_failed")
        }
    }

    /** First 16 bytes of HMAC-SHA256(K, key ID domain), base64url. [macKey] is K as an HMAC key. */
    fun keyId(macKey: SecretKey): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(
            Mac.getInstance("HmacSHA256").run {
                init(macKey)
                doFinal(KEY_ID_DOMAIN.toByteArray(Charsets.UTF_8))
            }.copyOf(16),
        )

    fun receipt(macKey: SecretKey, messageId: String, credentialId: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(
            Mac.getInstance("HmacSHA256").run {
                init(macKey)
                doFinal(receiptInput(messageId, credentialId))
            },
        )

    private fun decodeBase64Url(text: String): ByteArray? =
        try {
            Base64.getUrlDecoder().decode(text)
        } catch (e: IllegalArgumentException) {
            null
        }
}

/** A sealed message as Auth Core sends it: in the FCM data under the key `nexus`. */
@Serializable
data class NexusPushEnvelope(val v: Int, val id: String, val cid: String, val iv: String, val ct: String)

enum class NexusPushCategory {
    AUTHORIZATION_REQUEST, INCOMING_PAYMENT, OUTGOING_PAYMENT, CARD_TRANSACTION, ACCOUNT, SECURITY, GENERAL,
}

/** A decrypted push message, ready to show. */
data class NexusPushMessage(
    val messageId: String,
    val category: NexusPushCategory,
    val title: String,
    val body: String,
    /** For [NexusPushCategory.AUTHORIZATION_REQUEST]: pass to `fetchAuthorization`.
     * The confirmation screen is built from the signed bytes, not from this push. */
    val authorizationId: String?,
    val data: Map<String, String>,
    val sentAt: Instant,
    internal val credentialId: String,
)

@Serializable
internal data class PushContent(
    val v: Int,
    val category: String,
    val title: String,
    val body: String,
    val authorizationId: String? = null,
    val data: Map<String, String> = emptyMap(),
    val sentAt: String,
)

internal object PushMessages {
    private val json = Json { ignoreUnknownKeys = true }
    private val UUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    /** The envelope in an FCM data map, or `null` for any other message. */
    fun envelopeOf(data: Map<String, String>): NexusPushEnvelope? =
        data["nexus"]?.let { runCatching { json.decodeFromString<NexusPushEnvelope>(it) }.getOrNull() }

    fun parse(envelope: NexusPushEnvelope, plaintext: ByteArray): NexusPushMessage {
        val content = runCatching { json.decodeFromString<PushContent>(plaintext.toString(Charsets.UTF_8)) }.getOrNull()
            ?: throw NEXUSSignError.PushMessageInvalid("invalid_content")
        val category = NexusPushCategory.entries.firstOrNull { it.name == content.category }
        val sentAt = runCatching { Instant.parse(content.sentAt) }.getOrNull()
        if (content.v != 1 || category == null || sentAt == null ||
            (content.authorizationId != null && !UUID.matches(content.authorizationId))
        ) {
            throw NEXUSSignError.PushMessageInvalid("invalid_content")
        }
        // Auth Core refuses such text; checked again because the app shows it.
        if (!SignedPayload.isDisplaySafe(content.title) || !SignedPayload.isDisplaySafe(content.body.replace('\n', ' '))) {
            throw NEXUSSignError.PushMessageInvalid("unsafe_text")
        }
        return NexusPushMessage(envelope.id, category, content.title, content.body, content.authorizationId, content.data, sentAt, envelope.cid)
    }

    fun isWellFormed(envelope: NexusPushEnvelope): Boolean = UUID.matches(envelope.id) && UUID.matches(envelope.cid)
}

/**
 * The push key in the Android Keystore, imported twice from the agreed
 * bytes, which then exist nowhere else on the device: as an AES-GCM key that
 * only decrypts, and as an HMAC key for receipts. Neither requires the
 * device to be unlocked, so a message arriving on a locked phone can be shown
 * and confirmed. The credential the key was agreed for is kept beside it.
 */
internal class PushKeyStore(context: Context, bankId: String) {
    private val encAlias = "com.nexis.nexussign.$bankId.push.enc"
    private val macAlias = "com.nexis.nexussign.$bankId.push.mac"
    private val prefs = context.applicationContext.getSharedPreferences("com.nexis.nexussign.$bankId.push", Context.MODE_PRIVATE)
    private val keyStore: KeyStore = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    } catch (e: Exception) {
        throw NEXUSSignError.KeystoreUnavailable(e)
    }

    fun credentialId(): String? = prefs.getString(CREDENTIAL_ID, null)?.takeIf { hasKeys() }

    private fun hasKeys(): Boolean = runCatching { keyStore.containsAlias(encAlias) && keyStore.containsAlias(macAlias) }.getOrDefault(false)

    fun install(key: ByteArray, credentialId: String) {
        try {
            delete()
            keyStore.setEntry(encAlias, KeyStore.SecretKeyEntry(SecretKeySpec(key, "AES")),
                KeyProtection.Builder(KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build())
            keyStore.setEntry(macAlias, KeyStore.SecretKeyEntry(SecretKeySpec(key, "HmacSHA256")),
                KeyProtection.Builder(KeyProperties.PURPOSE_SIGN).build())
            if (!prefs.edit().putString(CREDENTIAL_ID, credentialId).commit()) {
                throw IllegalStateException("could not persist the push key's credential")
            }
        } catch (e: Exception) {
            delete()
            throw NEXUSSignError.KeyOperationFailed(e)
        } finally {
            key.fill(0)
        }
    }

    /** Keys for messages sealed for [credentialId]; `null` if this device has none for it. */
    fun keysFor(credentialId: String): Pair<SecretKey, SecretKey>? {
        if (credentialId() != credentialId) return null
        return try {
            val enc = keyStore.getKey(encAlias, null) as? SecretKey ?: return null
            val mac = keyStore.getKey(macAlias, null) as? SecretKey ?: return null
            enc to mac
        } catch (e: Exception) {
            throw NEXUSSignError.KeyOperationFailed(e)
        }
    }

    fun delete() {
        runCatching { if (keyStore.containsAlias(encAlias)) keyStore.deleteEntry(encAlias) }
        runCatching { if (keyStore.containsAlias(macAlias)) keyStore.deleteEntry(macAlias) }
        prefs.edit().remove(CREDENTIAL_ID).commit()
    }

    private companion object {
        const val CREDENTIAL_ID = "credential_id"
    }
}
