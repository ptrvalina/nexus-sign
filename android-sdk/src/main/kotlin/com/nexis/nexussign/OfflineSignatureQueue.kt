package com.nexis.nexussign

import android.content.Context
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/**
 * Offline confirmation v2 (docs/protocol/offline-confirmation-v2-deferred-signature.md):
 * the device signatures made during offline confirmations, kept until Auth
 * Core has them. An item is written before the code is shown, so there is no
 * code without a stored signature. A signature is not secret (it approves
 * terms the customer saw), but it is kept in the app's private storage.
 */
@Serializable
internal data class PendingOfflineSignature(
    val authorizationId: String,
    /** Base64 DER ECDSA signature over the canonical bytes. */
    val signature: String,
    val createdAtEpochSeconds: Long,
)

/** Where the queue is persisted; the SDK uses private SharedPreferences. */
internal interface PendingSignatureStorage {
    fun read(): String?
    fun write(value: String)
}

internal class SharedPreferencesSignatureStorage(context: Context, bankId: String) : PendingSignatureStorage {
    private val prefs = context.applicationContext.getSharedPreferences("com.nexis.nexussign.$bankId.offline", Context.MODE_PRIVATE)
    override fun read(): String? = prefs.getString(KEY, null)
    override fun write(value: String) {
        // commit(), not apply(): the code is shown only after this returns.
        if (!prefs.edit().putString(KEY, value).commit()) throw NEXUSSignError.KeyOperationFailed(IllegalStateException("Could not store the offline signature"))
    }
    private companion object { const val KEY = "pending" }
}

/** What Auth Core answered for one upload. */
internal sealed class UploadOutcome {
    /** 200 VERIFIED / ALREADY_RECORDED or 202 RECEIVED: Auth Core has it. */
    object Accepted : UploadOutcome()
    /** 409 (nothing awaited), 422 (does not verify), 403/404 (not this device's):
     * retrying cannot succeed. */
    data class Refused(val statusCode: Int) : UploadOutcome()
    /** No answer, 429 or 5xx: kept and retried later. */
    object Retry : UploadOutcome()

    companion object {
        fun ofStatus(statusCode: Int): UploadOutcome = when {
            statusCode in 200..299 -> Accepted
            statusCode == 429 || statusCode >= 500 || statusCode == 401 -> Retry
            statusCode in 400..499 -> Refused(statusCode)
            else -> Retry
        }
    }
}

/** Result of one delivery round. */
data class OfflineSignatureDelivery(val delivered: Int, val refused: Int, val pending: Int)

internal class OfflineSignatureQueue(
    private val storage: PendingSignatureStorage,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val serializer = ListSerializer(PendingOfflineSignature.serializer())
    private val lock = Any()

    fun pending(): List<PendingOfflineSignature> = synchronized(lock) { load() }

    /** Adds or replaces the item for an authorization (one signature each). */
    fun add(authorizationId: String, signatureBase64: String) = synchronized(lock) {
        val items = load().filterNot { it.authorizationId == authorizationId } + PendingOfflineSignature(authorizationId, signatureBase64, clock())
        save(items)
    }

    /**
     * Uploads every item; removes those Auth Core accepted or definitively
     * refused, keeps the rest. Items older than [MAX_AGE_SECONDS] are dropped:
     * Auth Core no longer accepts them after its deadline (at most 30 days).
     */
    suspend fun deliver(upload: suspend (PendingOfflineSignature) -> UploadOutcome): OfflineSignatureDelivery {
        var delivered = 0
        var refused = 0
        val now = clock()
        for (item in pending()) {
            if (now - item.createdAtEpochSeconds > MAX_AGE_SECONDS) {
                remove(item)
                refused += 1
                continue
            }
            when (upload(item)) {
                UploadOutcome.Accepted -> { remove(item); delivered += 1 }
                is UploadOutcome.Refused -> { remove(item); refused += 1 }
                UploadOutcome.Retry -> Unit
            }
        }
        return OfflineSignatureDelivery(delivered, refused, pending().size)
    }

    private fun remove(item: PendingOfflineSignature) = synchronized(lock) {
        save(load().filterNot { it.authorizationId == item.authorizationId && it.signature == item.signature })
    }

    private fun load(): List<PendingOfflineSignature> =
        storage.read()?.let { runCatching { json.decodeFromString(serializer, it) }.getOrNull() } ?: emptyList()

    private fun save(items: List<PendingOfflineSignature>) = storage.write(json.encodeToString(serializer, items))

    companion object {
        /** Auth Core's longest signature deadline (OFFLINE_SIGNATURE_DEADLINE_HOURS ≤ 720). */
        const val MAX_AGE_SECONDS = 30L * 24 * 3600
    }
}
