package com.nexis.nexussign

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

// Models of the customer's section, payment mandates and conversations with
// the bank (Auth Core /v1/mobile/devices, /history, /settings, /mandates,
// /conversations). The bank's app renders them in its own design.

@Serializable
data class NexusDevice(
    val credentialId: String,
    /** IOS, ANDROID or OTHER. */
    val platform: String,
    val securityLevel: String,
    val attestationStatus: String,
    /** ACTIVE or REVOKED. */
    val state: String,
    val enrolledAt: String,
    val revokedAt: String? = null,
    /** True for the device this SDK runs on. */
    val thisDevice: Boolean,
)

enum class NexusHistoryFilter(val wire: String) { ALL("all"), CONFIRMED("confirmed"), DECLINED("declined"), OPEN("open") }

@Serializable
data class NexusHistoryEntry(
    val authorizationId: String,
    val transactionReference: String,
    val operationType: String,
    val amountMinor: String,
    val currency: String,
    val beneficiary: Map<String, String>,
    val state: String,
    val reason: String? = null,
    val createdAt: String,
    val decidedAt: String? = null,
    val credentialId: String,
    /** True when a sealed evidence record exists for this payment. */
    val evidence: Boolean,
)

@Serializable
data class NexusSecurityEvent(val eventType: String, val at: String, val actor: String, val details: JsonObject = JsonObject(emptyMap()))

@Serializable
data class NexusNotification(
    val messageId: String, val category: String, val authorizationId: String? = null, val status: String,
    val createdAt: String, val deliveredAt: String? = null,
)

@Serializable
data class NexusChannels(val push: Boolean, val audio: Boolean, val video: Boolean)

/** Limits and channels; a relaxing change applies after the bank's hold (see effectiveAt). */
@Serializable
data class NexusCustomerSettings(
    val version: Int,
    val currency: String? = null,
    val perPaymentLimitMinor: String? = null,
    val dailyLimitMinor: String? = null,
    val videoCheckAboveMinor: String? = null,
    val channels: NexusChannels,
    val effectiveAt: String,
)

enum class NexusSuspendReason { LOST_DEVICE, SUSPECTED_FRAUD, OTHER }

/** A recurring payment mandate. Show it from [NexusMandateTerms], parsed from the signed bytes. */
@Serializable
data class NexusMandate(
    val mandateId: String,
    val nexusId: String,
    val credentialId: String,
    val mandateReference: String,
    val payee: Map<String, String>,
    val currency: String,
    val perPaymentLimitMinor: String,
    val totalLimitMinor: String? = null,
    val frequency: String,
    val validFrom: String,
    val validUntil: String,
    val termsVersion: String,
    val termsHash: String,
    val termsBase64: String,
    val offerExpiresAt: String,
    val state: String,
    val stateReason: String? = null,
    val signedAt: String? = null,
    val usedTotalMinor: String,
)

@Serializable
data class NexusConversationAttachment(val reference: String, val sha256: String, val mediaType: String, val fileName: String, val sizeBytes: Int)

@Serializable
data class NexusConversation(
    val conversationId: String,
    val nexusId: String,
    val topic: String,
    val authorizationId: String? = null,
    /** WITH_BOT, WAITING_FOR_AGENT, WITH_AGENT or CLOSED. */
    val state: String,
    val lastSequence: Int,
    val lastMessageHash: String? = null,
    val createdAt: String,
    val updatedAt: String,
    val closedAt: String? = null,
)

@Serializable
data class NexusConversationMessage(
    val messageId: String,
    val conversationId: String,
    val sequence: Int,
    /** CUSTOMER, BOT, AGENT or SYSTEM. */
    val senderType: String,
    val sender: String,
    val body: String,
    val attachment: NexusConversationAttachment? = null,
    val clientMessageId: String? = null,
    val previousHash: String? = null,
    val messageHash: String,
    val createdAt: String,
    val deliveredAt: String? = null,
    val readAt: String? = null,
)

@Serializable internal data class DeviceList(val devices: List<NexusDevice>)
@Serializable internal data class HistoryList(val authorizations: List<NexusHistoryEntry>)
@Serializable internal data class SecurityEventList(val events: List<NexusSecurityEvent>)
@Serializable internal data class NotificationList(val notifications: List<NexusNotification>)
@Serializable internal data class MandateList(val mandates: List<NexusMandate>)
@Serializable internal data class ConversationList(val conversations: List<NexusConversation>)
@Serializable internal data class ConversationThread(val conversation: NexusConversation, val messages: List<NexusConversationMessage>)
@Serializable internal data class ConversationOpened(val conversation: NexusConversation, val message: NexusConversationMessage)
@Serializable internal data class MessageSent(val message: NexusConversationMessage, val replayed: Boolean)
@Serializable internal data class DeviceRevoked(val credentialId: String, val state: String, val remainingActiveDevices: Int)
