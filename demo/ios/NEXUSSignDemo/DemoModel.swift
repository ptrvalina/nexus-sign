import Foundation
import Network
import NEXUSSign
import NEXUSSignCalls

/// Enrols this iPhone with Auth Core, shows the payment the demo bank sends
/// and signs it. The SDK creates the keys in the Secure Enclave; signing asks
/// for Face ID or Touch ID.
@MainActor
final class DemoModel: ObservableObject {
    @Published var serverAddress: String = UserDefaults.standard.string(forKey: DemoModel.addressKey) ?? ""
    @Published var pairingCode: String = ""
    @Published private(set) var connected = false
    @Published private(set) var registered = false
    @Published private(set) var busy = false
    @Published private(set) var payment: NexusSignedTransaction?
    /// The call the bank asks for before signing (ADR 0017), and whether the operator recorded VERIFIED.
    @Published private(set) var requiredCall: VerificationChannel?
    @Published private(set) var callVerified = false
    @Published var call: VerificationCallModel?
    /// Offline confirmation: the QR content fetched while online, and the code shown after Face ID / Touch ID.
    @Published private(set) var offlineQR: String?
    @Published private(set) var offlineCode: String?
    /// The payment the shown offline code belongs to, and where its signature is.
    @Published private(set) var offlineReference: String?
    @Published private(set) var offlineDelivery: String?
    @Published private(set) var status = "Введите адрес сервера (https://IP-компьютера:8443) и код сопряжения со страницы демо-банка, затем нажмите «Подключиться»."

    private static let addressKey = "serverAddress"
    private var sdk: NEXUSSignSDK?
    private var bank: DemoBank?
    private var authorization: NexusAuthorization?
    private var polling: Task<Void, Never>?
    private var pollNow: CheckedContinuation<Void, Never>?
    private var pollGeneration = 0
    private let pathMonitor = NWPathMonitor()
    private var online = true

    init() {
        // When the phone leaves airplane mode the waiting offline signature is
        // sent at once, without waiting for the next poll.
        pathMonitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in
                guard let self else { return }
                let nowOnline = path.status == .satisfied
                defer { self.online = nowOnline }
                if nowOnline && !self.online { self.wakePolling() }
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "NEXUSSignDemo.path"))
    }

    deinit { pathMonitor.cancel() }

    /// The app came back to the foreground: deliver and look for payments now.
    func becameActive() { wakePolling() }

    func connect() {
        let text = serverAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: text), url.scheme == "https", let host = url.host, !host.isEmpty else {
            status = "Адрес должен начинаться с https:// (например https://192.168.1.23:8443)."
            return
        }
        let code = pairingCode.filter(\.isNumber)
        guard code.count == 8 else {
            status = "Введите 8-значный код сопряжения со страницы демо-банка."
            return
        }
        UserDefaults.standard.set(text, forKey: Self.addressKey)
        let bank = DemoBank(baseURL: url, pairingCode: code)
        self.bank = bank
        sdk = NEXUSSignSDK(config: NEXUSSignConfig(
            bankID: "local-bank",
            baseURL: url,
            sessionToken: { _ in try await bank.bootstrapToken() },
            recoverySetupPromptText: "Подтвердите новую фразу восстановления"
        ))
        connected = true
        registered = (try? sdk?.isRegistered()) ?? false
        authorization = nil
        payment = nil
        offlineQR = nil
        offlineCode = nil
        offlineReference = nil
        offlineDelivery = nil
        status = registered
            ? "Телефон зарегистрирован. Ожидаю платёж от банка…"
            : "Подключено. Нажмите «Зарегистрировать телефон»: ключи будут созданы в Secure Enclave."
        startPolling()
    }

    func register() {
        guard let sdk, let bank else { return }
        Task {
            busy = true
            authorization = nil
            payment = nil
            status = "Регистрация: создаю ключи в Secure Enclave…"
            defer { busy = false }
            do {
                let registration = try await sdk.bootstrap()
                try await bank.registered(credentialID: registration.credentialId)
                registered = true
                status = """
                Телефон зарегистрирован.
                NEXUS ID: \(registration.nexusId)
                Устройство: \(registration.credentialId)
                Аттестация: \(registration.attestationStatus)

                Отправьте платёж со страницы демо-банка на компьютере.
                """
            } catch {
                show(error)
            }
        }
    }

    func approve() {
        guard let sdk, let authorization else { return }
        Task {
            busy = true
            defer {
                busy = false
                self.authorization = nil
                payment = nil
            }
            do {
                switch try await sdk.approve(authorization: authorization) {
                case .verified: status = "Платёж подтверждён подписью Secure Enclave. Банк получил доказательство, заверенное в HSM."
                case .failed: status = "Сервер не принял подпись."
                case .expired: status = "Срок подтверждения истёк."
                }
            } catch {
                show(error)
            }
        }
    }

    /// Asks for microphone (and camera) right before the call, opens the
    /// session and shows the call screen; the terms come from the signed bytes.
    func startCall() {
        guard let sdk, let authorization, let channel = requiredCall, let payment else { return }
        Task {
            guard await CallPermissions.request(for: channel) else {
                status = "Без доступа к микрофону (и камере для видео) звонок невозможен."
                return
            }
            busy = true
            do {
                let session = try await sdk.openVerificationCall(authorization: authorization, channel: channel)
                let model = try VerificationCallModel(sdk: sdk, session: session, terms: payment.confirmationText)
                call = model
                model.start()
                while !model.state.isEnded { try? await Task.sleep(nanoseconds: 200_000_000) }
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                call = nil
                switch model.state {
                case .ended(.decided(let verified)):
                    callVerified = verified
                    status = verified ? "Сотрудник подтвердил проверку. Теперь подтвердите платёж Face ID / Touch ID." : "Проверка в звонке не пройдена: банк отклонил платёж."
                case .ended(let reason):
                    status = "Звонок завершён без результата (\(reason)). Можно позвонить ещё раз (до трёх попыток)."
                default:
                    break
                }
            } catch {
                call = nil
                show(error)
            }
            busy = false
        }
    }

    /// Step 1, online: the QR content of the waiting payment.
    func fetchOfflineQR() {
        guard let bank else { return }
        Task {
            busy = true
            defer { busy = false }
            do {
                offlineQR = try await bank.offlineChallenge()
                offlineCode = nil
                status = "QR получен. Включите авиарежим, затем нажмите «Показать офлайн-код»."
            } catch {
                show(error)
            }
        }
    }

    /// Step 2, without network: the SDK checks the QR, asks for Face ID / Touch
    /// ID with the transaction and returns the 8-digit code; the signature waits
    /// in the SDK until the phone is online again.
    func showOfflineCode() {
        guard let sdk, let qr = offlineQR else { return }
        Task {
            busy = true
            defer { busy = false }
            do {
                let challenge = try sdk.readOfflineChallenge(qrPayload: qr)
                let code = try await sdk.confirmOffline(challenge)
                offlineCode = "\(code.prefix(4)) \(code.suffix(4))"
                offlineReference = challenge.transaction.transactionReference
                offlineDelivery = challenge.requiresDeviceSignature ? "Подпись сохранена на телефоне и ждёт сети." : nil
                offlineQR = nil
                authorization = nil
                payment = nil
                status = "Введите код \(offlineCode ?? "") на странице демо-банка. Затем выключите авиарежим: приложение отправит подпись, и банк увидит платёж подтверждённым."
            } catch {
                show(error)
            }
        }
    }

    func createRecoveryPhrase() {
        guard let sdk else { return }
        Task {
            busy = true
            defer { busy = false }
            do {
                let words = try await sdk.generateRecoveryPhrase()
                let lines = stride(from: 0, to: words.count, by: 4).map { words[$0..<min($0 + 4, words.count)].joined(separator: "   ") }
                status = "Фраза восстановления. Запишите её: она не покидает телефон.\n\n" + lines.joined(separator: "\n")
            } catch {
                show(error)
            }
        }
    }

    private func startPolling() {
        polling?.cancel()
        resumePolling() // the old loop wakes, sees the cancellation and ends
        polling = Task { [weak self] in
            while !Task.isCancelled {
                await self?.poll()
                await self?.waitForNextPoll(seconds: 3)
            }
        }
    }

    /// Sleeps until the next poll, or until `wakePolling()` (network back, app in front).
    private func waitForNextPoll(seconds: UInt64) async {
        pollGeneration &+= 1
        let generation = pollGeneration
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            pollNow = continuation
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
                // A timer of an earlier wait must not cut a later one short.
                guard let self, self.pollGeneration == generation else { return }
                self.resumePolling()
            }
        }
    }

    private func wakePolling() { resumePolling() }

    private func resumePolling() {
        let continuation = pollNow
        pollNow = nil
        continuation?.resume()
    }

    /// Asks the demo bank whether a payment is waiting and loads it through the SDK,
    /// which checks every displayed field against the exact bytes it will sign.
    private func poll() async {
        guard let sdk, let bank, !busy, registered else { return }
        // Offline confirmations: signatures made without network go out as soon
        // as there is one. Every outcome is shown: a signature Auth Core refused
        // will never confirm the payment, and the customer must know that.
        let delivery = await sdk.submitPendingOfflineSignatures()
        if delivery.delivered > 0 {
            offlineCode = nil
            offlineDelivery = nil
            status = "Подпись офлайн-подтверждения\(offlineReference.map { " (\($0))" } ?? "") принята Auth Core. Итог — на странице демо-банка."
            offlineReference = nil
        }
        if delivery.refused > 0 {
            offlineCode = nil
            offlineDelivery = nil
            status = "Auth Core не принял подпись офлайн-подтверждения\(offlineReference.map { " (\($0))" } ?? "")"
                + " — HTTP \(delivery.lastRefusalStatusCode.map { String($0) } ?? "?")\(delivery.lastRefusalMessage.map { ": \($0)" } ?? "")."
                + " Платёж этой подписью не подтвердится: отправьте новый платёж."
            offlineReference = nil
        }
        if delivery.pending > 0 {
            offlineDelivery = "Подпись ждёт отправки (\(delivery.pending)): \(delivery.lastRetryReason ?? "нет сети"). Уйдёт сама, как только появится связь."
        }
        guard authorization == nil else { return }
        let pending: (authorizationID: String, call: VerificationChannel?)?
        do {
            pending = try await bank.pending()
        } catch {
            // Shown instead of silently waiting; while a code is on screen the
            // instruction stays in the offline section.
            if offlineCode == nil { show(error) }
            return
        }
        guard let pending else { return }
        do {
            let loaded = try await sdk.fetchAuthorization(authorizationID: pending.authorizationID)
            if offlineCode != nil && offlineDelivery == nil {
                // An earlier offline code whose signature is already with Auth Core.
                offlineCode = nil
                offlineReference = nil
            }
            authorization = loaded
            payment = try loaded.signedTransaction()
            requiredCall = pending.call
            callVerified = false
            status = pending.call == nil
                ? "Банк просит подтвердить платёж. Проверьте сумму и получателя."
                : "Банк просит сначала проверить платёж в звонке с сотрудником, затем подтвердить его Face ID / Touch ID."
        } catch {
            show(error)
        }
    }

    private func show(_ error: Error) {
        guard let error = error as? NEXUSSignError else {
            status = "Нет связи с демо-банком: \(error.localizedDescription). Запущен ли демо-банк, верны ли адрес и код сопряжения?"
            return
        }
        switch error {
        case .authenticationDenied: status = "Подтверждение отменено."
        case .noAuthenticationMethodEnrolled: status = "Установите код-пароль и настройте Face ID или Touch ID."
        case .biometryUnavailable: status = "Face ID или Touch ID недоступны."
        case .biometryLockedOut: status = "Биометрия заблокирована после неудачных попыток. Разблокируйте iPhone кодом и повторите."
        case .notRegistered: status = "Сначала зарегистрируйте телефон."
        case .authorizationExpired: status = "Срок подтверждения истёк. Отправьте новый платёж."
        case .authorizationPayloadInvalid(let reason, _): status = "Данные платежа не совпадают с подписываемыми (\(reason)). Ничего не подписано."
        case .credentialInvalidated: status = "Биометрия на iPhone изменилась, ключ аннулирован. Зарегистрируйте телефон заново."
        case .secureEnclaveUnavailable: status = "Secure Enclave недоступен (симулятор?). Запустите на настоящем iPhone."
        case .serverError(let statusCode, let message):
            status = statusCode == 401
                ? "Сервер не знает это устройство (база создана заново). Нажмите «Зарегистрировать телефон заново»."
                : "Сервер отклонил запрос (\(statusCode)): \(message ?? "")"
        case .networkUnavailable: status = "Нет связи с сервером. Запущены ли Auth Core и демо-банк, и верен ли адрес?"
        default: status = error.localizedDescription
        }
    }
}
