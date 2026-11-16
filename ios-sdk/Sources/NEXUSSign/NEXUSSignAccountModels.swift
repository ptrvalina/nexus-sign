import Foundation

// Models of the customer's section, payment mandates and conversations with
// the bank (Auth Core /v1/mobile/devices, /history, /settings, /mandates,
// /conversations). The bank's app renders them in its own design.

public struct NexusDevice: Decodable, Equatable {
    public let credentialId: String
    /// IOS, ANDROID or OTHER.
    public let platform: String
    public let securityLevel: String
    public let attestationStatus: String
    /// ACTIVE or REVOKED.
    public let state: String
    public let enrolledAt: String
    public let revokedAt: String?
    /// True for the device this SDK runs on.
    public let thisDevice: Bool
}

public enum NexusHistoryFilter: String { case all, confirmed, declined, open }

public struct NexusHistoryEntry: Decodable, Equatable {
    public let authorizationId: String
    public let transactionReference: String
    public let operationType: String
    public let amountMinor: String
    public let currency: String
    public let beneficiary: [String: String]
    /// VERIFIED, REJECTED, CANCELLED, EXPIRED, OFFLINE_UNSIGNED, PENDING_USER or OFFLINE_PROVISIONAL.
    public let state: String
    public let reason: String?
    public let createdAt: String
    public let decidedAt: String?
    public let credentialId: String
    /// True when a sealed evidence record exists for this payment.
    public let evidence: Bool
}

public struct NexusSecurityEvent: Decodable, Equatable {
    public let eventType: String
    public let at: String
    /// BANK, DEVICE, OPERATOR or SYSTEM.
    public let actor: String
}

public struct NexusNotification: Decodable, Equatable {
    public let messageId: String
    public let category: String
    public let authorizationId: String?
    public let status: String
    public let createdAt: String
    public let deliveredAt: String?
}

public struct NexusChannels: Codable, Equatable {
    public var push: Bool
    public var audio: Bool
    public var video: Bool
    public init(push: Bool, audio: Bool, video: Bool) { self.push = push; self.audio = audio; self.video = video }
}

/// The customer's limits and channels. A change that relaxes them applies
/// after the bank's hold (24 h by default); tightening applies at once.
public struct NexusCustomerSettings: Decodable, Equatable {
    public let version: Int
    public let currency: String?
    public let perPaymentLimitMinor: String?
    public let dailyLimitMinor: String?
    public let videoCheckAboveMinor: String?
    public let channels: NexusChannels
    public let effectiveAt: String
}

public enum NexusSuspendReason: String { case lostDevice = "LOST_DEVICE", suspectedFraud = "SUSPECTED_FRAUD", other = "OTHER" }

/// A recurring payment mandate. Show it from `terms` (parsed from the signed
/// bytes), never from the convenience fields alone.
public struct NexusMandate: Decodable, Equatable {
    public let mandateId: String
    public let nexusId: String
    public let credentialId: String
    public let mandateReference: String
    public let payee: [String: String]
    public let currency: String
    public let perPaymentLimitMinor: String
    public let totalLimitMinor: String?
    /// WEEKLY, MONTHLY, QUARTERLY or YEARLY.
    public let frequency: String
    public let validFrom: String
    public let validUntil: String
    public let termsVersion: String
    public let termsHash: String
    public let termsBase64: String
    public let offerExpiresAt: String
    /// PENDING_SIGNATURE, ACTIVE, SUSPENDED, REVOKED, EXPIRED, DECLINED or WITHDRAWN.
    public let state: String
    public let stateReason: String?
    public let signedAt: String?
    public let usedTotalMinor: String
}

/// The mandate terms as signed, parsed and checked by the SDK.
public struct NexusMandateTerms: Equatable {
    public let mandateId: String
    public let nexusId: String
    public let credentialId: String
    public let mandateReference: String
    public let payee: [String: String]
    public let currency: String
    public let perPaymentLimitMinor: String
    public let totalLimitMinor: String?
    public let frequency: String
    public let validFrom: String
    public let validUntil: String
    public let termsVersion: String
    public let offerExpiresAt: String

    /// The text of the biometric prompt, built from the signed terms only.
    public var confirmationText: String {
        let digits = SignedPayload.fractionDigits(currency: currency)
        let limit = SignedPayload.formatMinorUnits(perPaymentLimitMinor, fractionDigits: digits)
        let payeeText = payee.keys.sorted().map { "\($0): \(payee[$0]!)" }.joined(separator: "\n")
        var lines = ["Recurring payments to", payeeText, "Up to \(limit) \(currency) per payment, \(frequency.lowercased())"]
        if let total = totalLimitMinor {
            lines.append("At most \(SignedPayload.formatMinorUnits(total, fractionDigits: digits)) \(currency) in total")
        }
        lines.append("Valid \(validFrom) – \(validUntil)")
        lines.append("Mandate \(mandateReference), conditions \(termsVersion)")
        return lines.joined(separator: "\n")
    }
}

public struct NexusConversationAttachment: Codable, Equatable {
    public let reference: String
    public let sha256: String
    public let mediaType: String
    public let fileName: String
    public let sizeBytes: Int
    public init(reference: String, sha256: String, mediaType: String, fileName: String, sizeBytes: Int) {
        self.reference = reference; self.sha256 = sha256; self.mediaType = mediaType; self.fileName = fileName; self.sizeBytes = sizeBytes
    }
}

public struct NexusConversation: Decodable, Equatable {
    public let conversationId: String
    public let nexusId: String
    public let topic: String
    public let authorizationId: String?
    /// WITH_BOT, WAITING_FOR_AGENT, WITH_AGENT or CLOSED.
    public let state: String
    public let lastSequence: Int
    public let lastMessageHash: String?
    public let createdAt: String
    public let updatedAt: String
    public let closedAt: String?
}

public struct NexusConversationMessage: Decodable, Equatable {
    public let messageId: String
    public let conversationId: String
    public let sequence: Int
    /// CUSTOMER, BOT, AGENT or SYSTEM.
    public let senderType: String
    public let sender: String
    public let body: String
    public let attachment: NexusConversationAttachment?
    public let clientMessageId: String?
    public let previousHash: String?
    public let messageHash: String
    public let createdAt: String
    public let deliveredAt: String?
    public let readAt: String?
}

struct DeviceList: Decodable { let devices: [NexusDevice] }
struct HistoryList: Decodable { let authorizations: [NexusHistoryEntry] }
struct SecurityEventList: Decodable { let events: [NexusSecurityEvent] }
struct NotificationList: Decodable { let notifications: [NexusNotification] }
struct MandateList: Decodable { let mandates: [NexusMandate] }
struct ConversationList: Decodable { let conversations: [NexusConversation] }
struct ConversationThread: Decodable { let conversation: NexusConversation; let messages: [NexusConversationMessage] }
struct ConversationOpened: Decodable { let conversation: NexusConversation; let message: NexusConversationMessage }
struct MessageSent: Decodable { let message: NexusConversationMessage; let replayed: Bool }
struct DeviceRevoked: Decodable { let credentialId: String; let state: String; let remainingActiveDevices: Int }
