import Foundation

// Client of the sandbox bank's app API (/app/v1/*, sandbox/bank/src/appApi.mjs).
// Everything the app shows comes from here; a payment is shown as done only
// when the bank reports the transaction as EXECUTED.

struct BankAPIError: LocalizedError {
    let status: Int
    let code: String
    let message: String
    var errorDescription: String? { message }
}

struct BankInfo: Decodable {
    struct Branding: Decodable { let name: String; let shortName: String; let notice: String }
    struct Support: Decodable { let phone: String; let email: String; let hours: String }
    let branding: Branding
    let currency: String
    let support: Support
}

struct Profile: Decodable {
    let id: String
    let login: String
    let displayName: String
    let nexusId: String?
    let credentialId: String?
    let deviceEnrolled: Bool
}

struct LoginResult: Decodable { let token: String; let customer: Profile }
struct BootstrapToken: Decodable { let token: String; let nexusId: String }

struct Account: Decodable, Identifiable, Hashable {
    let id: String
    let name: String
    let iban: String
    let currency: String
    let balanceMinor: Int
    let balance: String
    var shortNumber: String { "**** " + String(iban.suffix(4)) }
}

struct Card: Decodable, Identifiable, Hashable {
    let id: String
    let accountId: String
    let last4: String
    let brand: String
    let expires: String
    let status: String
}

struct BankTransaction: Decodable, Identifiable, Hashable {
    let id: String
    let reference: String
    let kind: String
    let state: String
    let sourceAccountId: String
    let beneficiaryName: String
    let beneficiaryIban: String
    let amountMinor: Int
    let feeMinor: Int
    let totalMinor: Int
    let currency: String
    let amount: String
    let fee: String
    let total: String
    let description: String
    let authorizationId: String?
    let authorizationExpiresAt: String?
    let failureReason: String?
    let receiptId: String?
    let createdAt: String

    var isFinal: Bool { ["EXECUTED", "REJECTED", "EXPIRED", "CANCELLED", "FAILED"].contains(state) }
    var stateTitle: String {
        switch state {
        case "EXECUTED": return "Выполнено"
        case "AUTHORIZATION_PENDING": return "Ждёт подтверждения"
        case "OFFLINE_PROVISIONAL": return "Код принят, ждём подпись"
        case "AUTHORIZING": return "Проверяется банком"
        case "REJECTED": return "Отклонено вами"
        case "EXPIRED": return "Срок истёк"
        case "CANCELLED": return "Отменено"
        case "FAILED": return "Отказ банка"
        default: return "Создано"
        }
    }
}

struct Quote: Decodable {
    let kind: String
    let amountMinor: Int
    let feeMinor: Int
    let totalMinor: Int
    let currency: String
    let beneficiaryName: String
    let beneficiaryIban: String
}

struct HistoryEntry: Decodable, Identifiable {
    let amountMinor: Int
    let currency: String
    let memo: String
    let createdAt: String
    let journalKind: String
    let transactionId: String?
    let reference: String?
    let beneficiaryName: String?
    let amount: String
    var id: String { "\(createdAt)-\(memo)-\(amountMinor)" }

    enum CodingKeys: String, CodingKey {
        case amountMinor = "amount_minor", currency, memo, createdAt = "created_at", journalKind = "kind"
        case transactionId = "transaction_id", reference, beneficiaryName = "beneficiary_name", amount
    }
}

struct Favorite: Decodable, Identifiable, Hashable { let id: String; let name: String; let iban: String }
struct Product: Decodable, Identifiable { let id: String; let kind: String; let title: String; let summary: String }

struct BankNotification: Decodable, Identifiable {
    let id: String
    let transactionId: String?
    let kind: String
    let title: String
    let body: String
    let state: String
    let createdAt: String
}

struct Receipt: Decodable {
    struct Party: Decodable { let name: String; let iban: String }
    struct Confirmation: Decodable { let authorizationId: String; let method: String; let evidenceHash: String; let chainSequence: Int? }
    let receiptId: String
    let bank: String
    let reference: String
    let executedAt: String
    let from: String
    let to: Party
    let amount: String
    let fee: String
    let total: String
    let confirmation: Confirmation
    let notice: String
}

struct OfflineChallengeInfo: Decodable { let transactionId: String; let authorizationId: String; let qrPayload: String; let expiresAt: String }

private struct PendingAnswer: Decodable { let transaction: BankTransaction? }
private struct ErrorAnswer: Decodable { let code: String?; let error: String? }

/// What the customer orders: to one of the bank's accounts, or to an IBAN.
struct PaymentOrder: Encodable {
    var sourceAccountId: String
    var destinationAccountId: String?
    var beneficiaryName: String?
    var beneficiaryIban: String?
    var amountMinor: Int
    var description: String?
}

final class BankAPI {
    let baseURL: URL
    var token: String?
    private let session: URLSession

    init(baseURL: URL, token: String?) {
        self.baseURL = baseURL
        self.token = token
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        session = URLSession(configuration: configuration)
    }

    private func request<T: Decodable>(_ method: String, _ path: String, body: Encodable? = nil, headers: [String: String] = [:]) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = method
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(AnyEncodable(body))
        }
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw BankAPIError(status: 0, code: "NETWORK", message: "Нет связи с банком: \(error.localizedDescription)")
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            let answer = try? JSONDecoder().decode(ErrorAnswer.self, from: data)
            throw BankAPIError(status: status, code: answer?.code ?? "HTTP_\(status)", message: answer?.error ?? "Банк ответил HTTP \(status)")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    func bankInfo() async throws -> BankInfo { try await request("GET", "app/v1/bank") }
    func login(login: String, password: String) async throws -> LoginResult {
        try await request("POST", "app/v1/session", body: ["login": login, "password": password])
    }
    func logout() async { let _: [String: Bool]? = try? await request("DELETE", "app/v1/session") }
    func profile() async throws -> Profile { try await request("GET", "app/v1/profile") }
    func bootstrapToken() async throws -> BootstrapToken { try await request("POST", "app/v1/enrolment/bootstrap-token", body: [String: String]()) }
    func completeEnrolment(credentialId: String) async throws -> Profile {
        try await request("POST", "app/v1/enrolment/complete", body: ["credentialId": credentialId])
    }
    func accounts() async throws -> [Account] { try await request("GET", "app/v1/accounts") }
    func history(accountId: String) async throws -> [HistoryEntry] { try await request("GET", "app/v1/accounts/\(accountId)/history") }
    func cards() async throws -> [Card] { try await request("GET", "app/v1/cards") }
    func cardAction(cardId: String, action: String) async throws -> Card { try await request("POST", "app/v1/cards/\(cardId)/\(action)", body: [String: String]()) }
    func favorites() async throws -> [Favorite] { try await request("GET", "app/v1/favorites") }
    func addFavorite(name: String, iban: String) async throws -> Favorite { try await request("POST", "app/v1/favorites", body: ["name": name, "iban": iban]) }
    func products() async throws -> [Product] { try await request("GET", "app/v1/products") }
    func notifications() async throws -> [BankNotification] { try await request("GET", "app/v1/notifications") }
    func markRead(_ id: String) async { let _: [String: Bool]? = try? await request("POST", "app/v1/notifications/\(id)/read", body: [String: String]()) }
    func quote(_ order: PaymentOrder) async throws -> Quote { try await request("POST", "app/v1/transactions/quote", body: order) }
    func create(_ order: PaymentOrder, idempotencyKey: String) async throws -> BankTransaction {
        try await request("POST", "app/v1/transactions", body: order, headers: ["Idempotency-Key": idempotencyKey])
    }
    func transactions() async throws -> [BankTransaction] { try await request("GET", "app/v1/transactions") }
    func transaction(_ id: String) async throws -> BankTransaction { try await request("GET", "app/v1/transactions/\(id)") }
    func cancel(_ id: String) async throws -> BankTransaction { try await request("POST", "app/v1/transactions/\(id)/cancel", body: [String: String]()) }
    func receipt(_ id: String) async throws -> Receipt { try await request("GET", "app/v1/transactions/\(id)/receipt") }
    func offlineChallenge(_ id: String) async throws -> OfflineChallengeInfo { try await request("GET", "app/v1/transactions/\(id)/offline-challenge") }
    func pendingAuthorization() async throws -> BankTransaction? {
        let answer: PendingAnswer = try await request("GET", "app/v1/pending-authorization")
        return answer.transaction
    }
}

private struct AnyEncodable: Encodable {
    let value: Encodable
    init(_ value: Encodable) { self.value = value }
    func encode(to encoder: Encoder) throws { try value.encode(to: encoder) }
}

enum Money {
    /// "50", "50.5", "50,50" → 5050 minor units; nil when not a valid positive amount.
    static func minor(from text: String) -> Int? {
        let cleaned = text.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: ",", with: ".")
        let parts = cleaned.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count <= 2, let whole = Int(parts[0].isEmpty ? "0" : String(parts[0])), whole >= 0 else { return nil }
        var cents = 0
        if parts.count == 2 {
            let fraction = String(parts[1])
            guard fraction.count <= 2, fraction.allSatisfy(\.isNumber) else { return nil }
            cents = Int(fraction.padding(toLength: 2, withPad: "0", startingAt: 0)) ?? 0
        }
        let total = whole * 100 + cents
        return total > 0 ? total : nil
    }

    static func format(_ minor: Int, _ currency: String) -> String {
        let sign = minor < 0 ? "-" : ""
        let value = abs(minor)
        var whole = String(value / 100)
        var grouped = ""
        while whole.count > 3 {
            grouped = " " + whole.suffix(3) + grouped
            whole = String(whole.dropLast(3))
        }
        return "\(sign)\(whole)\(grouped).\(String(format: "%02d", value % 100)) \(currency)"
    }
}
