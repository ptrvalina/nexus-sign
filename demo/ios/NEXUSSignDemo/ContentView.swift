import SwiftUI
import NEXUSSignCalls

struct ContentView: View {
    @StateObject private var model = DemoModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationView {
            Form {
                Section {
                    Text("Платёж подписывается ключом, который создан в Secure Enclave этого iPhone и не покидает его.")
                        .font(.footnote)
                }
                Section("Сервер") {
                    TextField("https://192.168.1.23:8443", text: $model.serverAddress)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                    TextField("Код сопряжения (8 цифр)", text: $model.pairingCode)
                        .keyboardType(.numberPad)
                    Button("Подключиться") { model.connect() }
                        .disabled(model.busy)
                }
                Section {
                    Button(model.registered ? "Зарегистрировать телефон заново" : "Зарегистрировать телефон") { model.register() }
                        .disabled(model.busy || !model.connected)
                }
                if let payment = model.payment {
                    Section("Платёж на подтверждение") {
                        Text("\(payment.formattedAmount) \(payment.currency)").font(.title2.bold())
                        Text(payment.beneficiaryDisplay)
                        Text("Референс: \(payment.transactionReference)").font(.footnote)
                        if let channel = model.requiredCall {
                            Button(channel == .video ? "Видеозвонок с сотрудником банка" : "Аудиозвонок с сотрудником банка") { model.startCall() }
                                .disabled(model.busy || model.callVerified)
                        }
                        Button("Подтвердить Face ID / Touch ID") { model.approve() }
                            .disabled(model.busy || (model.requiredCall != nil && !model.callVerified))
                        if model.requiredCall == nil {
                            Button("Офлайн: получить QR") { model.fetchOfflineQR() }
                                .disabled(model.busy)
                            Button("Показать офлайн-код (без сети)") { model.showOfflineCode() }
                                .disabled(model.busy || model.offlineQR == nil)
                        }
                    }
                }
                if model.offlineCode != nil || model.offlineDelivery != nil {
                    Section("Офлайн-подтверждение") {
                        if let code = model.offlineCode {
                            Text(code).font(.largeTitle.monospacedDigit().bold())
                        }
                        if let reference = model.offlineReference {
                            Text("Референс: \(reference)").font(.footnote)
                        }
                        if let delivery = model.offlineDelivery {
                            Text(delivery).font(.footnote).foregroundColor(.secondary)
                        }
                    }
                }
                Section {
                    Button("Создать фразу восстановления") { model.createRecoveryPhrase() }
                        .disabled(model.busy || !model.registered)
                }
                Section("Статус") {
                    Text(model.status).textSelection(.enabled)
                }
            }
            .navigationTitle("NEXUS-SIGN · демо")
        }
        .navigationViewStyle(.stack)
        .onChange(of: scenePhase) { phase in
            if phase == .active { model.becameActive() }
        }
        .fullScreenCover(isPresented: Binding(get: { model.call != nil }, set: { if !$0 { model.call = nil } })) {
            if let call = model.call { VerificationCallView(model: call) }
        }
    }
}
