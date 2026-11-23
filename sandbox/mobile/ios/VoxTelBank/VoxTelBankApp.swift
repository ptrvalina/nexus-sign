import SwiftUI

@main
struct VoxTelBankApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .tint(Theme.accent)
        }
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            if model.isLoggedIn {
                if model.deviceRegistered { MainTabs() } else { EnrolView() }
            } else {
                LoginView()
            }
        }
        .sheet(item: $model.confirmation) { pending in
            ConfirmationSheet(pending: pending).environmentObject(model)
        }
        .fullScreenCover(isPresented: Binding(get: { model.progress != nil }, set: { if !$0 { model.progress = nil } })) {
            ProgressScreen().environmentObject(model)
        }
        .fullScreenCover(isPresented: Binding(get: { model.offlineCode != nil }, set: { if !$0 { model.offlineCode = nil } })) {
            OfflineCodeScreen().environmentObject(model)
        }
        .alert("VoxTel", isPresented: Binding(get: { model.message != nil }, set: { if !$0 { model.message = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.message ?? "")
        }
        .onChange(of: scenePhase) { phase in
            if phase == .active { Task { await model.deliverOfflineSignatures() } }
        }
    }
}

struct MainTabs: View {
    var body: some View {
        TabView {
            HomeView().tabItem { Label("Главная", systemImage: "house") }
            PaymentsView().tabItem { Label("Платежи", systemImage: "creditcard") }
            HistoryView().tabItem { Label("История", systemImage: "clock") }
            ProductsView().tabItem { Label("Продукты", systemImage: "square.stack") }
            MoreView().tabItem { Label("Ещё", systemImage: "line.3.horizontal") }
        }
    }
}

/// After the first login: the phone gets its NEXUS-SIGN keys inside the bank app.
struct EnrolView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            LogoMark(size: 72)
            Text("Подключите этот iPhone").font(.title2.weight(.bold))
            Text("Операции в \(model.bank?.branding.shortName ?? "банке") подтверждаются ключом, который создаётся в Secure Enclave этого телефона и никогда его не покидает. Понадобится Face ID или Touch ID.")
                .multilineTextAlignment(.center).foregroundColor(Theme.muted).padding(.horizontal, 24)
            Spacer()
            PrimaryButton(title: "Подключить телефон", busy: model.busy) { Task { await model.enrolDevice() } }
            SecondaryButton(title: "Выйти") { Task { await model.logout() } }
        }
        .padding(20)
        .background(Theme.headerGradient.ignoresSafeArea())
    }
}
