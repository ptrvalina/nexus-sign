package com.nexis.nexussign

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Device protocols v1, identical in Auth Core and the iOS SDK (vectors in
 * `device-protocols-v1.json`):
 *
 * - request signing input for the device authentication key;
 * - offline confirmation key derivation, tag and 8-digit code;
 * - the offline QR payload format.
 */
internal object DeviceProtocol {
    const val REQUEST_DOMAIN = "NEXUS-SIGN/DEVICE-REQUEST/v1"
    const val OFFLINE_KDF_SALT = "NEXUS-SIGN/OFFLINE/v1"
    const val OFFLINE_CODE_DOMAIN = "NEXUS-SIGN/OFFLINE-CODE/v1"
    const val QR_PREFIX = "NXS1."
    /** Offline confirmation v2: the same bytes; the device also signs them
     * and uploads the signature later (deferred device signature). */
    const val QR_PREFIX_V2 = "NXS2."
    const val KEY_ATTESTATION_DOMAIN = "NEXUS-SIGN/KEY-ATTESTATION/v1"
    const val CODE_DIGITS = 8

    fun requestSigningInput(method: String, path: String, timestamp: String, nonce: String, credentialId: String, body: ByteArray): ByteArray =
        listOf(REQUEST_DOMAIN, method.uppercase(), path, timestamp, nonce, credentialId, hex(sha256(body)))
            .joinToString("\n")
            .toByteArray(Charsets.UTF_8)

    /** HKDF-SHA256 (RFC 5869) over the 32-byte ECDH secret, bound to the credential. */
    fun deriveOfflineKey(sharedSecret: ByteArray, credentialId: String): ByteArray {
        require(sharedSecret.size == 32) { "ECDH shared secret must be 32 bytes" }
        return Hkdf.sha256(sharedSecret, OFFLINE_KDF_SALT.toByteArray(Charsets.UTF_8), credentialId.toByteArray(Charsets.UTF_8))
    }

    /**
     * The Keystore attestation challenge of each enrolled key:
     * SHA-256("NEXUS-SIGN/KEY-ATTESTATION/v1" || 0x00 || enrolment challenge),
     * where the enrolment challenge is the BOOTSTRAP token's challenge or the
     * recovery session nonce. Auth Core checks the same value in the key's
     * attestation certificate (androidKeyAttestation.ts).
     */
    fun keyAttestationChallenge(enrolmentChallenge: ByteArray): ByteArray =
        sha256(KEY_ATTESTATION_DOMAIN.toByteArray(Charsets.UTF_8) + byteArrayOf(0) + enrolmentChallenge)

    /** The message the offline key authenticates: domain || 0x00 || SHA-256(payload). */
    fun offlineTagInput(canonicalPayload: ByteArray): ByteArray =
        OFFLINE_CODE_DOMAIN.toByteArray(Charsets.UTF_8) + byteArrayOf(0) + sha256(canonicalPayload)

    fun offlineTag(offlineKey: ByteArray, canonicalPayload: ByteArray): ByteArray =
        hmac(offlineKey, offlineTagInput(canonicalPayload))

    /** RFC 4226 dynamic truncation to 8 digits. */
    fun offlineCode(tag: ByteArray): String {
        val offset = tag[tag.size - 1].toInt() and 0x0f
        val binary = ((tag[offset].toInt() and 0x7f) shl 24) or
            ((tag[offset + 1].toInt() and 0xff) shl 16) or
            ((tag[offset + 2].toInt() and 0xff) shl 8) or
            (tag[offset + 3].toInt() and 0xff)
        return (binary % 100_000_000).toString().padStart(CODE_DIGITS, '0')
    }

    /** The canonical authorization bytes carried by an offline QR code. */
    /** 1 for `NXS1.`, 2 for `NXS2.`; anything else is refused. */
    fun qrPayloadVersion(qrPayload: String): Int {
        val text = qrPayload.trim()
        return when {
            text.startsWith(QR_PREFIX) -> 1
            text.startsWith(QR_PREFIX_V2) -> 2
            else -> throw NEXUSSignError.AuthorizationPayloadInvalid("invalid_qr", "unknown QR format")
        }
    }

    fun qrPayloadBytes(qrPayload: String): ByteArray {
        val text = qrPayload.trim()
        val prefix = if (qrPayloadVersion(text) == 2) QR_PREFIX_V2 else QR_PREFIX
        return try {
            Base64.getUrlDecoder().decode(text.removePrefix(prefix))
        } catch (e: IllegalArgumentException) {
            throw NEXUSSignError.AuthorizationPayloadInvalid("invalid_qr", "QR payload is not base64url")
        }
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
