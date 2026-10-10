package com.nexis.nexussign

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA256 (RFC 5869) with one output block of 32 bytes, the only length
 * the NEXUS-SIGN protocols derive: T(1) = HMAC(PRK, info || 0x01) with
 * PRK = HMAC(salt, ikm). Used for the offline key, the push key and the
 * recovery wrapping key; pinned by the shared vectors of each protocol.
 */
internal object Hkdf {
    fun sha256(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val prk = hmac(salt, ikm)
        return try {
            hmac(prk, info + byteArrayOf(1))
        } finally {
            prk.fill(0)
        }
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }
}
