import Foundation
import NEXUSSign

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
    @Published private(set) var status = "Введите адрес сервера (https://IP-компьютера:8443) и код сопряжения со страницы демо-банка, затем нажмите «Подключиться»."

    private static let addressKey = "serverAddress"
    private var sdk: NEXUSSignSDK?
    private var bank: DemoBank?
    private var authorization: NexusAuthorization?
    private var polling: Task<Void, Never>?

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
        polling = Task { [weak self] in
            while !Task.isCancelled {
                await self?.poll()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    /// Asks the demo bank whether a payment is waiting and loads it through the SDK,
    /// which checks every displayed field against the exact bytes it will sign.
    private func poll() async {
        guard let sdk, let bank, !busy, authorization == nil, registered else { return }
        guard let id = try? await bank.pendingAuthorizationID() else { return }
        do {
            let loaded = try await sdk.fetchAuthorization(authorizationID: id)
            authorization = loaded
            payment = try loaded.signedTransaction()
            status = "Банк просит подтвердить платёж. Проверьте сумму и получателя."
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
