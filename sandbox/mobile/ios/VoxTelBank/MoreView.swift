import SwiftUI

struct MoreView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(model.profile?.displayName ?? "").font(.headline)
                        Text("Ваш личный аккаунт · \(model.profile?.login ?? "")").font(.footnote).foregroundColor(Theme.muted)
                    }
                    .padding(.vertical, 6)
                }
                Section {
                    NavigationLink { LifeView() } label: { Label("Life", systemImage: "gift") }
                    NavigationLink { SettingsView() } label: { Label("Настройки и безопасность", systemImage: "gearshape") }
                    NavigationLink { NotificationsList() } label: { Label("Уведомления", systemImage: "bell") }
                    NavigationLink { AboutView() } label: { Label("О программе", systemImage: "info.circle") }
                    NavigationLink { SupportView() } label: { Label("Служба поддержки", systemImage: "headphones") }
                }
                Section {
                    Button(role: .destructive) { Task { await model.logout() } } label: { Label("Выход", systemImage: "rectangle.portrait.and.arrow.right") }
                }
            }
            .navigationTitle("Ещё")
        }
    }
}

struct LifeView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                ForEach(model.products) { ProductTile(product: $0).frame(maxWidth: .infinity) }
            }
            .padding(16)
        }
        .navigationTitle("Life")
    }
}

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        List {
            Section("NEXUS-SIGN на этом iPhone") {
                KeyValueRow(key: "Состояние", value: model.deviceRegistered ? "Подключён" : "Не подключён")
                KeyValueRow(key: "NEXUS ID", value: model.profile?.nexusId ?? "—")
                KeyValueRow(key: "Устройство", value: String((model.profile?.credentialId ?? "—").prefix(13)))
                Text("Ключ подписи хранится в Secure Enclave и не покидает телефон. Каждая операция подтверждается Face ID / Touch ID.").font(.footnote).foregroundColor(Theme.muted)
                Button("Подключить телефон заново") { Task { await model.enrolDevice() } }
            }
            Section("Сервер песочницы") {
                Text(model.serverAddress).font(.footnote.monospaced())
            }
        }
        .navigationTitle("Настройки")
    }
}

struct AboutView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        List {
            KeyValueRow(key: "Приложение", value: "\(model.bank?.branding.name ?? "Demo Bank") 1.0")
            KeyValueRow(key: "Защита операций", value: "NEXUS-SIGN SDK")
            Text(model.bank?.branding.notice ?? "Демонстрационный банк.").font(.footnote).foregroundColor(Theme.muted)
        }
        .navigationTitle("О программе")
    }
}

struct SupportView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        List {
            KeyValueRow(key: "Телефон", value: model.bank?.support.phone ?? "—")
            KeyValueRow(key: "Email", value: model.bank?.support.email ?? "—")
            KeyValueRow(key: "Часы работы", value: model.bank?.support.hours ?? "—")
        }
        .navigationTitle("Служба поддержки")
    }
}
