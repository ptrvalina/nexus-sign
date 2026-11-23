import Foundation
import Network
import Security
import NEXUSSign

/// A confirmation the customer has to review: the bank's transaction and the
/// terms the SDK verified against the exact bytes it will sign.
struct PendingConfirmation: Identifiable {
    let transaction: BankTransaction
    let authorization: NexusAuthorization
    let signed: NexusSignedTransaction
    var id: String { transaction.id }
}

/// Where a payment the customer just confirmed stands, as reported by the bank.
enum PaymentProgress: Equatable {
    case waiting(BankTransaction)
    case done(BankTransaction)
    case failed(BankTransaction)
}

@MainActor
final class AppModel: ObservableObject {
    static let serverKey = "sandbox.server"

    @Published var serverAddress = UserDefaults.standard.string(forKey: AppModel.serverKey) ?? "https://192.168.0.118:8191"
    @Published private(set) var bank: BankInfo?
    @Published private(set) var profile: Profile?
    @Published private(set) var accounts: [Account] = []
    @Published private(set) var cards: [Card] = []
    @Published private(set) var transactions: [BankTransaction] = []
    @Published private(set) var favorites: [Favorite] = []
    @Published private(set) var products: [Product] = []
    @Published private(set) var notifications: [BankNotification] = []
    @Published var confirmation: PendingConfirmation?
    @Published var progress: PaymentProgress?
    @Published var offlineCode: (code: String, reference: String)?
    @Published var message: String?
    @Published private(set) var busy = false

    private(set) var api: BankAPI?
    private(set) var sdk: NEXUSSignSDK?
    private var polling: Task<Void, Never>?
    private var dismissedConfirmations = Set<String>()
    private let pathMonitor = NWPathMonitor()

    var isLoggedIn: Bool { profile != nil }
    var currency: String { bank?.currency ?? accounts.first?.currency ?? "MDL" }
    var unreadCount: Int { notifications.filter { $0.state != "READ" }.count }

    init() {
        // Back online: a signature made offline goes out at once.
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard path.status == .satisfied else { return }
            Task { @MainActor in await self?.deliverOfflineSignatures() }
        }
        pathMonitor.start(queue: DispatchQueue(label: "VoxTelBank.path"))
        if let url = URL(string: serverAddress), Self.acceptable(url), let token = Keychain.read("session") {
            connect(url: url, token: token)
            Task { await restoreSession() }
        }
    }

    // MARK: Session

    /// The SDK accepts https, or plain http only to this machine (simulator).
    static func acceptable(_ url: URL) -> Bool {
        guard let host = url.host, !host.isEmpty else { return false }
        return url.scheme == "https" || (url.scheme == "http" && ["127.0.0.1", "localhost"].contains(host))
    }

    private func connect(url: URL, token: String?) {
        let api = BankAPI(baseURL: url, token: token)
        self.api = api
        sdk = NEXUSSignSDK(config: NEXUSSignConfig(
            bankID: "voxtel-sandbox",
            baseURL: url,
            sessionToken: { _ in try await api.bootstrapToken().token },
            recoverySetupPromptText: "Подтвердите новую фразу восстановления",
            promptLabels: NexusPromptLabels(iban: "IBAN", account: "Счёт", accountNumber: "Номер счёта", name: "Получатель", bic: "BIC")
        ))
    }

    private func restoreSession() async {
        do {
            bank = try await api?.bankInfo()
            profile = try await api?.profile()
            await refresh()
            startPolling()
        } catch {
            Keychain.delete("session")
            profile = nil
        }
    }

    func login(login: String, password: String) async {
        let address = serverAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: address), Self.acceptable(url) else {
            message = "Адрес банка должен начинаться с https:// (например https://192.168.0.118:8191)."
            return
        }
        busy = true
        defer { busy = false }
        UserDefaults.standard.set(address, forKey: Self.serverKey)
        connect(url: url, token: nil)
        do {
            bank = try await api?.bankInfo()
            guard let result = try await api?.login(login: login.lowercased(), password: password) else { return }
            api?.token = result.token
            Keychain.write("session", result.token)
            profile = result.customer
            await refresh()
            startPolling()
        } catch {
            show(error)
        }
    }

    func logout() async {
        polling?.cancel()
        await api?.logout()
        Keychain.delete("session")
        profile = nil
        accounts = []
        cards = []
        transactions = []
        confirmation = nil
        progress = nil
    }

    /// Creates the keys in the Secure Enclave (SDK) and tells the bank which device it is.
    func enrolDevice() async {
        guard let sdk, let api else { return }
        busy = true
        defer { busy = false }
        do {
            let registration = try await sdk.bootstrap()
            profile = try await api.completeEnrolment(credentialId: registration.credentialId)
            message = "Телефон подключён к NEXUS-SIGN. Операции подтверждаются ключом этого iPhone."
        } catch {
            show(error)
        }
    }

    var deviceRegistered: Bool { ((try? sdk?.isRegistered()) ?? false) && (profile?.deviceEnrolled ?? false) }

    // MARK: Data

    func refresh() async {
        guard let api else { return }
        do {
            async let accounts = api.accounts()
            async let cards = api.cards()
            async let transactions = api.transactions()
            async let favorites = api.favorites()
            async let products = api.products()
            async let notifications = api.notifications()
            self.accounts = try await accounts
            self.cards = try await cards
            self.transactions = try await transactions
            self.favorites = try await favorites
            self.products = try await products
            self.notifications = try await notifications
        } catch {
            show(error)
        }
    }

    func account(_ id: String) -> Account? { accounts.first { $0.id == id } }

    func cardAction(_ card: Card, _ action: String) async {
        do {
            _ = try await api?.cardAction(cardId: card.id, action: action)
            cards = try await api?.cards() ?? cards
        } catch { show(error) }
    }

    func addFavorite(name: String, iban: String) async {
        do {
            _ = try await api?.addFavorite(name: name, iban: iban)
            favorites = try await api?.favorites() ?? favorites
            message = "Сохранено в избранное."
        } catch { show(error) }
    }

    func markNotificationsRead() async {
        for n in notifications where n.state != "READ" { await api?.markRead(n.id) }
        notifications = (try? await api?.notifications()) ?? notifications
    }

    // MARK: Payments

    func quote(_ order: PaymentOrder) async throws -> Quote {
        guard let api else { throw BankAPIError(status: 0, code: "NO_SESSION", message: "Войдите в приложение") }
        return try await api.quote(order)
    }

    /// Sends the order to the bank, then opens the NEXUS-SIGN confirmation
    /// with the terms the SDK checked against the bytes it will sign.
    func submit(_ order: PaymentOrder, idempotencyKey: String) async {
        guard let api else { return }
        busy = true
        defer { busy = false }
        do {
            let transaction = try await api.create(order, idempotencyKey: idempotencyKey)
            guard transaction.state == "AUTHORIZATION_PENDING" else {
                progress = .failed(transaction)
                return
            }
            try await present(transaction)
        } catch {
            show(error)
        }
    }

    private func present(_ transaction: BankTransaction) async throws {
        guard let sdk, let id = transaction.authorizationId else { return }
        let authorization = try await sdk.fetchAuthorization(authorizationID: id)
        confirmation = PendingConfirmation(transaction: transaction, authorization: authorization, signed: try authorization.signedTransaction())
    }

    /// Opens the confirmation of a transaction that is still waiting (from the history).
    func reopen(_ transaction: BankTransaction) async throws {
        dismissedConfirmations.remove(transaction.id)
        try await present(transaction)
    }

    /// Face ID / Touch ID and the Secure Enclave signature; then the bank decides and executes.
    func approve() async {
        guard let sdk, let pending = confirmation else { return }
        busy = true
        defer { busy = false }
        do {
            let outcome = try await sdk.approve(authorization: pending.authorization)
            confirmation = nil
            switch outcome {
            case .verified:
                progress = .waiting(pending.transaction)
                await follow(pending.transaction.id)
            case .failed:
                message = "Auth Core не принял подпись."
            case .expired:
                message = "Срок подтверждения истёк."
            }
        } catch {
            show(error)
        }
    }

    func decline(_ reason: NexusDeclineReason) async {
        guard let sdk, let pending = confirmation else { return }
        dismissedConfirmations.insert(pending.id)
        confirmation = nil
        do {
            try await sdk.decline(authorization: pending.authorization, reason: reason)
            await follow(pending.transaction.id)
        } catch { show(error) }
    }

    /// Closes the confirmation without deciding; the bank can still be asked later.
    func postpone() {
        if let id = confirmation?.id { dismissedConfirmations.insert(id) }
        confirmation = nil
    }

    func cancel(_ transaction: BankTransaction) async {
        do {
            _ = try await api?.cancel(transaction.id)
            await refresh()
        } catch { show(error) }
    }

    /// Follows the transaction at the bank until it is executed or refused.
    func follow(_ transactionId: String) async {
        guard let api else { return }
        for _ in 0..<60 {
            if let t = try? await api.transaction(transactionId) {
                if t.state == "EXECUTED" { progress = .done(t); break }
                if t.isFinal { progress = .failed(t); break }
                progress = .waiting(t)
            }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
        await refresh()
    }

    func receipt(_ transactionId: String) async -> Receipt? {
        do { return try await api?.receipt(transactionId) } catch { show(error); return nil }
    }

    // MARK: Offline (QR) confirmation

    /// Online: the QR content for this payment. Offline: the SDK checks it,
    /// asks for Face ID and returns the 8-digit code; the signature waits on
    /// the phone and is sent as soon as there is network.
    func confirmOffline() async {
        guard let sdk, let api, let pending = confirmation else { return }
        busy = true
        defer { busy = false }
        do {
            let info = try await api.offlineChallenge(pending.transaction.id)
            let challenge = try sdk.readOfflineChallenge(qrPayload: info.qrPayload)
            let code = try await sdk.confirmOffline(challenge)
            confirmation = nil
            dismissedConfirmations.insert(pending.id)
            offlineCode = ("\(code.prefix(4)) \(code.suffix(4))", pending.transaction.reference)
        } catch {
            show(error)
        }
    }

    func deliverOfflineSignatures() async {
        guard let sdk else { return }
        let delivery = await sdk.submitPendingOfflineSignatures()
        if delivery.delivered > 0 {
            offlineCode = nil
            message = "Подпись офлайн-подтверждения отправлена в банк."
            await refresh()
        } else if delivery.refused > 0 {
            offlineCode = nil
            message = "Банк не принял подпись офлайн-подтверждения: операция не будет выполнена."
        }
    }

    // MARK: Polling

    private func startPolling() {
        polling?.cancel()
        polling = Task { [weak self] in
            var tick = 0
            while !Task.isCancelled {
                await self?.poll(refreshData: tick % 5 == 0)
                tick += 1
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    private func poll(refreshData: Bool) async {
        guard isLoggedIn, let api else { return }
        await deliverOfflineSignatures()
        if refreshData { await refresh() }
        guard confirmation == nil, !busy, deviceRegistered else { return }
        if let waiting = try? await api.pendingAuthorization(), !dismissedConfirmations.contains(waiting.id) {
            try? await present(waiting)
        }
    }

    func show(_ error: Error) {
        message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
    }
}

/// The bank session token, in the Keychain of this app only.
enum Keychain {
    private static func query(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "voxtel-sandbox-bank", kSecAttrAccount as String: key]
    }
    static func write(_ key: String, _ value: String) {
        delete(key)
        var attributes = query(key)
        attributes[kSecValueData as String] = Data(value.utf8)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(attributes as CFDictionary, nil)
    }
    static func read(_ key: String) -> String? {
        var q = query(key)
        q[kSecReturnData as String] = true
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    static func delete(_ key: String) { SecItemDelete(query(key) as CFDictionary) }
}
