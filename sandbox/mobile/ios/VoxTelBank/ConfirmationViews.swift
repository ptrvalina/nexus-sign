import SwiftUI
import NEXUSSign

/// "Подтвердите перевод": what the customer approves is what the SDK read from
/// the exact bytes it signs (amount, payee, commission, reference), not the
/// bank's list view.
struct ConfirmationSheet: View {
    @EnvironmentObject var model: AppModel
    let pending: PendingConfirmation
    @State private var askDecline = false

    var body: some View {
        VStack(spacing: 16) {
            Capsule().fill(Color.gray.opacity(0.3)).frame(width: 40, height: 5).padding(.top, 8)
            LogoMark(size: 48)
            Text("Подтвердите \(pending.signed.operationType == "transfer" ? "перевод" : "платёж") в \(model.bank?.branding.shortName ?? "банке")")
                .font(.title3.weight(.bold)).multilineTextAlignment(.center)
            Text("\(pending.signed.formattedAmount) \(pending.signed.currency)").font(.system(size: 32, weight: .bold))
            CardBox {
                if let name = pending.signed.beneficiary["name"] { KeyValueRow(key: "Получатель", value: name); Divider() }
                if let iban = pending.signed.beneficiary["iban"] { KeyValueRow(key: "IBAN", value: iban); Divider() }
                if let fee = pending.signed.beneficiary["fee"] { KeyValueRow(key: "Комиссия", value: fee); Divider() }
                KeyValueRow(key: "Референс", value: pending.signed.transactionReference)
            }
            Text("Данные выше прочитаны из того, что подписывает ключ телефона. Если они отличаются от вашего заказа — не подтверждайте.")
                .font(.caption).foregroundColor(Theme.muted).multilineTextAlignment(.center)
            Spacer(minLength: 0)
            PrimaryButton(title: "Подтвердить", busy: model.busy) { Task { await model.approve() } }
            Button("Нет интернета? Код для банка") { Task { await model.confirmOffline() } }
                .font(.subheadline).foregroundColor(Theme.accent).disabled(model.busy)
            HStack(spacing: 10) {
                SecondaryButton(title: "Это не я", role: .destructive) { askDecline = true }
                SecondaryButton(title: "Позже") { model.postpone() }
            }
        }
        .padding(20)
        .background(Theme.headerGradient.ignoresSafeArea())
        .interactiveDismissDisabled(model.busy)
        .confirmationDialog("Отклонить операцию?", isPresented: $askDecline, titleVisibility: .visible) {
            Button("Это не я", role: .destructive) { Task { await model.decline(.notMe) } }
            Button("Неверные данные", role: .destructive) { Task { await model.decline(.wrongDetails) } }
            Button("Отмена", role: .cancel) {}
        }
    }
}

/// Waiting for the bank's decision, then success or refusal, as the bank reports it.
struct ProgressScreen: View {
    @EnvironmentObject var model: AppModel
    @State private var receipt: Receipt?
    @State private var saved = false

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            switch model.progress {
            case .waiting(let t):
                ProgressView().scaleEffect(1.6).tint(Theme.accent).padding(.bottom, 10)
                Text("Ожидание подтверждения").font(.title2.weight(.bold))
                Text(t.state == "AUTHORIZING" ? "Банк проверяет подпись и доказательство…" : "Банк обрабатывает операцию…")
                    .foregroundColor(Theme.muted)
            case .done(let t):
                Circle().fill(Theme.cardGradient).frame(width: 84, height: 84)
                    .overlay(Image(systemName: "checkmark").font(.system(size: 36, weight: .bold)).foregroundColor(.white))
                Text("Переведено успешно").foregroundColor(Theme.ink)
                Text(t.amount).font(.system(size: 34, weight: .bold))
                Text("На счёт **** \(t.beneficiaryIban.suffix(4))").foregroundColor(Theme.muted)
                HStack(spacing: 24) {
                    action("doc.text", "Квитанция") { Task { receipt = await model.receipt(t.id) } }
                    action(saved ? "star.fill" : "star", "В избранное") {
                        guard !saved else { return }
                        saved = true
                        Task { await model.addFavorite(name: t.beneficiaryName, iban: t.beneficiaryIban) }
                    }
                }
                .padding(.top, 10)
            case .failed(let t):
                Circle().fill(Theme.deep).frame(width: 84, height: 84)
                    .overlay(Image(systemName: "xmark").font(.system(size: 34, weight: .bold)).foregroundColor(.white))
                Text(t.stateTitle).font(.title2.weight(.bold))
                Text(t.failureReason ?? "Операция не выполнена.").font(.footnote).foregroundColor(Theme.muted).multilineTextAlignment(.center)
            case .none:
                EmptyView()
            }
            Spacer()
            if case .waiting = model.progress {} else {
                PrimaryButton(title: "Готово") { model.progress = nil }
            }
        }
        .padding(24)
        .background(Theme.headerGradient.ignoresSafeArea())
        .sheet(item: Binding(get: { receipt.map { IdentifiedReceipt(receipt: $0) } }, set: { if $0 == nil { receipt = nil } })) { ReceiptView(receipt: $0.receipt) }
    }

    private func action(_ icon: String, _ title: String, _ run: @escaping () -> Void) -> some View {
        Button(action: run) {
            VStack(spacing: 8) {
                Image(systemName: icon).font(.system(size: 22)).foregroundColor(Theme.deep)
                    .frame(width: 56, height: 56).background(Theme.accentSoft).clipShape(Circle())
                Text(title).font(.caption).foregroundColor(Theme.ink)
            }
        }
    }
}

struct IdentifiedReceipt: Identifiable { let receipt: Receipt; var id: String { receipt.receiptId } }

struct ReceiptView: View {
    let receipt: Receipt
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            List {
                Section {
                    KeyValueRow(key: "Банк", value: receipt.bank)
                    KeyValueRow(key: "Референс", value: receipt.reference)
                    KeyValueRow(key: "Исполнено", value: receipt.executedAt.shortDate)
                    KeyValueRow(key: "Со счёта", value: receipt.from)
                    KeyValueRow(key: "Получатель", value: receipt.to.name)
                    KeyValueRow(key: "IBAN", value: receipt.to.iban)
                    KeyValueRow(key: "Сумма", value: receipt.amount)
                    KeyValueRow(key: "Комиссия", value: receipt.fee)
                    KeyValueRow(key: "Итого", value: receipt.total)
                }
                Section("Подтверждение NEXUS-SIGN") {
                    KeyValueRow(key: "Способ", value: receipt.confirmation.method == "DEVICE_SIGNATURE" ? "Подпись ключом телефона" : receipt.confirmation.method)
                    KeyValueRow(key: "Авторизация", value: receipt.confirmation.authorizationId)
                    KeyValueRow(key: "Доказательство", value: String(receipt.confirmation.evidenceHash.prefix(24)) + "…")
                    if let sequence = receipt.confirmation.chainSequence { KeyValueRow(key: "Запись в цепочке", value: "№\(sequence)") }
                }
                Section { Text(receipt.notice).font(.footnote).foregroundColor(Theme.muted) }
            }
            .navigationTitle("Квитанция")
            .toolbar {
                ShareLink(item: text)
                Button("Готово") { dismiss() }
            }
        }
    }
    private var text: String {
        "\(receipt.bank)\nКвитанция \(receipt.reference)\n\(receipt.executedAt)\nСо счёта: \(receipt.from)\nПолучатель: \(receipt.to.name), \(receipt.to.iban)\nСумма: \(receipt.amount)\nКомиссия: \(receipt.fee)\nИтого: \(receipt.total)\nДоказательство: \(receipt.confirmation.evidenceHash)\n\(receipt.notice)"
    }
}

/// The 8-digit code made without network; the customer gives it to the bank
/// (branch, call centre: in the sandbox, the console's transaction page).
struct OfflineCodeScreen: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "wifi.slash").font(.system(size: 40)).foregroundColor(Theme.deep)
            Text("Код подтверждения").font(.title2.weight(.bold))
            Text(model.offlineCode?.code ?? "").font(.system(size: 44, weight: .bold, design: .monospaced))
            Text("Операция \(model.offlineCode?.reference ?? "")").font(.footnote).foregroundColor(Theme.muted)
            Text("Назовите этот код сотруднику банка (в песочнице — введите его в консоли банка на странице операции). Банк исполнит операцию только когда получит и подпись телефона: она отправится сама, как только появится интернет.")
                .font(.subheadline).foregroundColor(Theme.muted).multilineTextAlignment(.center)
            Spacer()
            PrimaryButton(title: "Готово") { model.offlineCode = nil }
        }
        .padding(24)
        .background(Theme.headerGradient.ignoresSafeArea())
    }
}
