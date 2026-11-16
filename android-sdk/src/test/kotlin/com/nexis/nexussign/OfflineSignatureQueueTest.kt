package com.nexis.nexussign

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

/** Offline confirmation v2: the pending signature queue and the QR prefixes. */
class OfflineSignatureQueueTest {
    private class MemoryStorage : PendingSignatureStorage {
        var value: String? = null
        override fun read(): String? = value
        override fun write(value: String) { this.value = value }
    }

    private val a = "00000000-0000-4000-8000-00000000000a"
    private val b = "00000000-0000-4000-8000-00000000000b"
    private val c = "00000000-0000-4000-8000-00000000000c"

    @Test
    fun keepsOnlyWhatAuthCoreHasNotTakenOrRefused() = runBlocking {
        val storage = MemoryStorage()
        val queue = OfflineSignatureQueue(storage) { 1_000 }
        queue.add(a, "c2lnLWE=")
        queue.add(b, "c2lnLWI=")
        queue.add(c, "c2lnLWM=")
        val answers = mapOf(a to 200, b to 503, c to 409)
        val result = queue.deliver { UploadOutcome.ofStatus(answers.getValue(it.authorizationId)) }
        assertEquals(OfflineSignatureDelivery(delivered = 1, refused = 1, pending = 1), result)
        assertEquals(listOf(b), queue.pending().map { it.authorizationId })
        // Persisted: a new queue over the same storage sees the same item.
        assertEquals(listOf(b), OfflineSignatureQueue(storage) { 1_000 }.pending().map { it.authorizationId })
    }

    @Test
    fun aLostAnswerKeepsTheItemAndTheRetryDeliversIt() = runBlocking {
        val queue = OfflineSignatureQueue(MemoryStorage()) { 1_000 }
        queue.add(a, "c2ln")
        assertEquals(1, queue.deliver { UploadOutcome.Retry }.pending)
        assertEquals(1, queue.deliver { UploadOutcome.ofStatus(202) }.delivered)
        assertTrue(queue.pending().isEmpty())
    }

    @Test
    fun statusClassification() {
        for (code in listOf(200, 202)) assertEquals(UploadOutcome.Accepted, UploadOutcome.ofStatus(code))
        for (code in listOf(400, 403, 404, 409, 422)) assertEquals(UploadOutcome.Refused(code), UploadOutcome.ofStatus(code))
        for (code in listOf(401, 429, 500, 502, 503)) assertEquals(UploadOutcome.Retry, UploadOutcome.ofStatus(code))
    }

    @Test
    fun oneSignaturePerAuthorizationAndOldItemsAreDropped() = runBlocking {
        var now = 1_000L
        val queue = OfflineSignatureQueue(MemoryStorage()) { now }
        queue.add(a, "Zmlyc3Q=")
        queue.add(a, "c2Vjb25k")
        assertEquals(listOf("c2Vjb25k"), queue.pending().map { it.signature })
        now += OfflineSignatureQueue.MAX_AGE_SECONDS + 1
        var uploads = 0
        val result = queue.deliver { uploads += 1; UploadOutcome.Accepted }
        assertEquals(0, uploads)
        assertEquals(OfflineSignatureDelivery(0, 1, 0), result)
    }

    @Test
    fun qrPrefixesVersionOneAndTwoCarryTheSameBytes() {
        val bytes = """{"a":"b"}""".toByteArray()
        val body = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        assertEquals(1, DeviceProtocol.qrPayloadVersion("NXS1.$body"))
        assertEquals(2, DeviceProtocol.qrPayloadVersion("NXS2.$body"))
        assertTrue(DeviceProtocol.qrPayloadBytes("NXS1.$body").contentEquals(bytes))
        assertTrue(DeviceProtocol.qrPayloadBytes("NXS2.$body").contentEquals(bytes))
        for (unknown in listOf("NXS3.$body", "nxs2.$body", body)) {
            try {
                DeviceProtocol.qrPayloadBytes(unknown)
                fail("accepted $unknown")
            } catch (e: NEXUSSignError.AuthorizationPayloadInvalid) {
                assertEquals("invalid_qr", e.reason)
            }
        }
    }
}
