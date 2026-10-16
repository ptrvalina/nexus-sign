package com.nexis.nexussign

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.MessageDigest
import java.util.Base64
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Requests a Google Play Integrity token whose nonce is bound to the
 * enrolment challenge and the new public key (see [NEXUSSignSDK.bootstrap]).
 * The token is decoded and checked by Auth Core, never on the device.
 */
internal class AttestationProvider(context: Context, private val cloudProjectNumber: Long?) {

    private val integrityManager = IntegrityManagerFactory.create(context.applicationContext)

    val isSupported: Boolean get() = cloudProjectNumber != null

    /** Nonce = base64url(SHA-256(clientData)), where clientData is
     * `challenge || 0x00 || public key PEM`. */
    suspend fun requestToken(clientData: ByteArray): String {
        val projectNumber = cloudProjectNumber
            ?: throw IllegalStateException("playIntegrityCloudProjectNumber is not configured")

        val digest = MessageDigest.getInstance("SHA-256").digest(clientData)
        val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)

        val request = IntegrityTokenRequest.builder()
            .setCloudProjectNumber(projectNumber)
            .setNonce(nonce)
            .build()

        return suspendCancellableCoroutine { continuation ->
            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { response -> continuation.resume(response.token()) }
                .addOnFailureListener { error -> continuation.resumeWithException(error) }
        }
    }
}
