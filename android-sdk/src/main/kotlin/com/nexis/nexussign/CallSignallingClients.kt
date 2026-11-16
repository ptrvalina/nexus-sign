package com.nexis.nexussign

/** [CallSignalling] for a call the customer started: the same call engine; [cancel] hangs up or stops waiting. */
internal class CustomerCallSignalling(override val sessionId: String, private val network: NetworkClient) : CallSignalling {
    override suspend fun join(): VerificationCallInfo = CallWire.decodeCustomerCallJoin(network.joinCustomerCall(sessionId))
    override suspend fun send(message: CallMessage, messageId: String) = network.sendCustomerCallSignal(sessionId, CallWire.encode(message, messageId))
    override suspend fun receive(after: Long, waitMillis: Long): SignalBatch =
        CallWire.decodeBatch(network.receiveCustomerCallSignals(sessionId, after, waitMillis.coerceAtMost(network.callPollWaitMillis)), after)
    override suspend fun cancel() = network.endCustomerCall(sessionId)
}

/** [CallSignalling] over device-signed requests to Auth Core. */
internal class DeviceCallSignalling(override val sessionId: String, private val network: NetworkClient) : CallSignalling {
    override suspend fun join(): VerificationCallInfo = CallWire.decodeJoin(network.joinCall(sessionId))
    override suspend fun send(message: CallMessage, messageId: String) = network.sendCallSignal(sessionId, CallWire.encode(message, messageId))
    override suspend fun receive(after: Long, waitMillis: Long): SignalBatch =
        CallWire.decodeBatch(network.receiveCallSignals(sessionId, after, waitMillis.coerceAtMost(network.callPollWaitMillis)), after)
    override suspend fun cancel() = network.cancelCall(sessionId)
}
