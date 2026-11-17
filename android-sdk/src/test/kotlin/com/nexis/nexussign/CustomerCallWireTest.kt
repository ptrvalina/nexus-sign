package com.nexis.nexussign

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.time.Instant

/** Auth Core's answer to `GET /v1/mobile/customer-calls/{id}` (openapi.yaml: CustomerCallJoin) for the call engine. */
class CustomerCallWireTest {
    private fun body(state: String, extra: String = ""): JsonObject = Json.parseToJsonElement(
        """{"call":{"callId":"7d0c3a8e-1f2b-4c5d-8e9f-0a1b2c3d4e5f","nexusId":"123456789","credentialId":"3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b",
           "channel":"VIDEO","topic":"Card","conversationId":null,"state":"$state","operator":null,"createdAt":"2026-11-16T10:00:00.000Z",
           "expiresAt":"2026-11-16T10:05:00.000Z","answeredAt":null,"endedAt":null,"endedBy":null,"endReason":null},
           "iceServers":[{"urls":["stun:stun.bank.example:3478"]},{"urls":["turn:turn.bank.example:3478"],"username":"1:x","credential":"c"}]$extra}""",
    ).jsonObject

    @Test fun `a waiting call joins with its ICE servers and no operator yet`() {
        val info = CallWire.decodeCustomerCallJoin(body("WAITING"))
        assertEquals("7d0c3a8e-1f2b-4c5d-8e9f-0a1b2c3d4e5f", info.sessionId)
        assertEquals(VerificationChannel.VIDEO, info.channel)
        assertEquals(Instant.parse("2026-11-16T10:05:00Z"), info.expiresAt)
        assertEquals(2, info.iceServers.size)
        assertEquals("1:x", info.iceServers[1].username)
        assertFalse(info.operatorJoined)
    }

    @Test fun `an answered call reports the operator joined`() {
        assertTrue(CallWire.decodeCustomerCallJoin(body("CONNECTED")).operatorJoined)
    }

    @Test fun `a finished call is not joined`() {
        for (state in listOf("ENDED", "CANCELLED", "MISSED")) {
            try {
                CallWire.decodeCustomerCallJoin(body(state)); fail("joined a $state call")
            } catch (e: NEXUSSignError.ServerError) {
                assertEquals(409, e.statusCode)
            }
        }
    }

    @Test fun `a malformed answer is refused`() {
        try {
            CallWire.decodeCustomerCallJoin(Json.parseToJsonElement("""{"iceServers":[]}""").jsonObject); fail("accepted")
        } catch (e: NEXUSSignError.InvalidServerResponse) {
            // A dedicated error, not a fake HTTP 200 (finding D-11).
            assertEquals("unexpected response format", e.detail)
        }
    }
}
