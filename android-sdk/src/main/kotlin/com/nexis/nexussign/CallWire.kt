package com.nexis.nexussign

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.time.Instant

/** JSON of Auth Core's call routes (openapi.yaml: CallSignalRequest, CallSignal). */
internal object CallWire {
    fun encode(message: CallMessage, messageId: String): JsonObject = buildJsonObject {
        when (message) {
            is CallMessage.Offer -> { put("type", "offer"); put("payload", buildJsonObject { put("sdp", message.sdp) }) }
            is CallMessage.Answer -> { put("type", "answer"); put("payload", buildJsonObject { put("sdp", message.sdp) }) }
            is CallMessage.Candidate -> {
                put("type", "candidate")
                put("payload", buildJsonObject {
                    put("candidate", message.candidate.candidate)
                    message.candidate.sdpMid?.let { put("sdpMid", it) }
                    message.candidate.sdpMLineIndex?.let { put("sdpMLineIndex", it) }
                })
            }
            is CallMessage.Bye -> { put("type", "bye"); put("payload", buildJsonObject { put("reason", message.reason) }) }
        }
        put("messageId", messageId)
    }

    fun decodeBatch(body: JsonObject, after: Long): SignalBatch {
        val signals = (body["signals"] as? JsonArray ?: JsonArray(emptyList())).mapNotNull { element ->
            val o = element as? JsonObject ?: return@mapNotNull null
            val seq = o.long("seq") ?: return@mapNotNull null
            ReceivedSignal(seq, o.string("from") ?: "", decodeMessage(o.string("type"), o["payload"] as? JsonObject))
        }
        return SignalBatch(signals, body.long("next") ?: signals.maxOfOrNull { it.seq } ?: after)
    }

    private fun decodeMessage(type: String?, payload: JsonObject?): CallMessage? = when (type) {
        "offer" -> payload?.string("sdp")?.let { CallMessage.Offer(it) }
        "answer" -> payload?.string("sdp")?.let { CallMessage.Answer(it) }
        "candidate" -> payload?.string("candidate")?.let { CallMessage.Candidate(IceCandidateInit(it, payload.string("sdpMid"), payload.long("sdpMLineIndex")?.toInt())) }
        "bye" -> CallMessage.Bye(payload?.string("reason") ?: "bye")
        else -> null
    }

    fun decodeSession(body: JsonObject, authorizationId: String): VerificationSession = VerificationSession(
        sessionId = body.string("sessionId") ?: invalid(),
        authorizationId = authorizationId,
        channel = channel(body.string("channel")),
        expiresAt = instant(body.string("expiresAt")),
    )

    fun decodeJoin(body: JsonObject): VerificationCallInfo = VerificationCallInfo(
        sessionId = body.string("sessionId") ?: invalid(),
        channel = channel(body.string("channel")),
        expiresAt = instant(body.string("expiresAt")),
        iceServers = (body["iceServers"] as? JsonArray ?: JsonArray(emptyList())).mapNotNull { e ->
            val o = e as? JsonObject ?: return@mapNotNull null
            val urls = when (val u = o["urls"]) {
                is JsonArray -> u.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
                is JsonPrimitive -> listOf(u.content)
                else -> emptyList()
            }
            if (urls.isEmpty()) null else IceServer(urls, o.string("username"), o.string("credential"))
        },
        operatorJoined = (body["operatorJoined"] as? JsonPrimitive)?.content == "true",
    )

    /** `GET /v1/mobile/customer-calls/{id}`: `{call, iceServers}`. The operator has joined once the call is CONNECTED. */
    fun decodeCustomerCallJoin(body: JsonObject): VerificationCallInfo {
        val call = body["call"] as? JsonObject ?: invalid()
        val state = call.string("state")
        if (state != "WAITING" && state != "CONNECTED") throw NEXUSSignError.ServerError(409, "The call is $state")
        return decodeJoin(buildJsonObject {
            put("sessionId", call.string("callId") ?: invalid())
            put("channel", call.string("channel") ?: invalid())
            put("expiresAt", call.string("expiresAt") ?: invalid())
            body["iceServers"]?.let { put("iceServers", it) }
            put("operatorJoined", state == "CONNECTED")
        })
    }

    private fun channel(value: String?) = VerificationChannel.entries.firstOrNull { it.name == value } ?: invalid()
    private fun instant(value: String?) = runCatching { Instant.parse(value) }.getOrNull() ?: invalid()
    private fun invalid(): Nothing = throw NEXUSSignError.InvalidServerResponse("unexpected response format")

    private fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
    private fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.takeIf { !it.isString && it !is JsonNull }?.content?.toLongOrNull()
}
