import SwiftUI

struct LoginView: View {
    @EnvironmentObject var model: AppModel
    @State private var login = ""
    @State private var password = ""
    @State private var showPassword = false
    @State private var showServer = false

    var body: some View {
        VStack(spacing: 16) {
            Spacer().frame(height: 40)
            LogoMark()
            Spacer().frame(height: 30)
            Text("Вход").font(.largeTitle.weight(.bold))
            TextField("Email/логин", text: $login)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .padding(14).background(RoundedRectangle(cornerRadius: 12).stroke(Color.gray.opacity(0.3)))
            HStack {
                Group {
                    if showPassword { TextField("Пароль", text: $password) } else { SecureField("Пароль", text: $password) }
                }
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                Button { showPassword.toggle() } label: { Image(systemName: showPassword ? "eye.slash" : "eye").foregroundColor(Theme.muted) }
            }
            .padding(14).background(RoundedRectangle(cornerRadius: 12).stroke(Color.gray.opacity(0.3)))
            Button("Адрес банка: \(model.serverAddress)") { showServer = true }
                .font(.footnote).foregroundColor(Theme.accent).lineLimit(1)
            Spacer()
            PrimaryButton(title: "Продолжить", busy: model.busy) {
                Task { await model.login(login: login, password: password) }
            }
            .disabled(login.isEmpty || password.isEmpty)
            Text("Демонстрационный банк: тестовые средства, вымышленные клиенты.")
                .font(.caption).foregroundColor(Theme.muted).multilineTextAlignment(.center)
        }
        .padding(24)
        .background(Color.white.ignoresSafeArea())
        .sheet(isPresented: $showServer) { ServerSheet() }
    }
}

struct ServerSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("https://192.168.0.118:8191", text: $model.serverAddress)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                } header: {
                    Text("Адрес песочницы банка")
                } footer: {
                    Text("Порт устройств песочницы (sandbox/bin/sandbox up печатает его). По Wi‑Fi нужен https:// и доверенный сертификат песочницы.")
                }
            }
            .navigationTitle("Сервер")
            .toolbar { Button("Готово") { dismiss() } }
        }
    }
}
