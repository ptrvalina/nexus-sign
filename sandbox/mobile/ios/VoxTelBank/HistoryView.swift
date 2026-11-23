import SwiftUI

struct HistoryView: View {
    @EnvironmentObject var model: AppModel
    @State private var filter = "Все"

    var body: some View {
        NavigationStack {
            List {
                Picker("", selection: $filter) {
                    ForEach(["Все", "Выполнено", "В процессе", "Отказы"], id: \.self) { Text($0) }
                }
                .pickerStyle(.segmented)
                .listRowBackground(Color.clear)
                ForEach(filtered) { t in
                    NavigationLink(value: t) { TransactionRow(transaction: t) }
                }
            }
            .overlay { if filtered.isEmpty { Text("Операций нет").foregroundColor(Theme.muted) } }
            .refreshable { await model.refresh() }
            .navigationTitle("История")
            .navigationDestination(for: BankTransaction.self) { TransactionView(transaction: $0) }
        }
    }

    private var filtered: [BankTransaction] {
        switch filter {
        case "Выполнено": return model.transactions.filter { $0.state == "EXECUTED" }
        case "В процессе": return model.transactions.filter { !$0.isFinal }
        case "Отказы": return model.transactions.filter { $0.isFinal && $0.state != "EXECUTED" }
        default: return model.transactions
        }
    }
}

/// One transaction as the bank records it, with the receipt once executed.
struct TransactionView: View {
    @EnvironmentObject var model: AppModel
    @State var transaction: BankTransaction
    @State private var receipt: Receipt?

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text(transaction.total).font(.system(size: 30, weight: .bold))
                    StateLabel(transaction: transaction)
                }
                .padding(.vertical, 6)
            }
            Section {
                KeyValueRow(key: "Получатель", value: transaction.beneficiaryName)
                KeyValueRow(key: "IBAN", value: transaction.beneficiaryIban)
                KeyValueRow(key: "Сумма", value: transaction.amount)
                KeyValueRow(key: "Комиссия", value: transaction.fee)
                KeyValueRow(key: "Референс", value: transaction.reference)
                KeyValueRow(key: "Создана", value: transaction.createdAt.shortDate)
                if !transaction.description.isEmpty { KeyValueRow(key: "Назначение", value: transaction.description) }
                if let reason = transaction.failureReason { KeyValueRow(key: "Причина", value: reason) }
            }
            if transaction.state == "EXECUTED" {
                Section { Button("Квитанция") { Task { receipt = await model.receipt(transaction.id) } } }
            }
            if transaction.state == "AUTHORIZATION_PENDING" {
                Section {
                    Button("Подтвердить сейчас") { Task { try? await model.reopen(transaction) } }
                    Button("Отменить операцию", role: .destructive) { Task { await model.cancel(transaction); await reload() } }
                }
            }
        }
        .navigationTitle(transaction.reference)
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await reload() }
        .task { await reload() }
        .sheet(item: Binding(get: { receipt.map { IdentifiedReceipt(receipt: $0) } }, set: { if $0 == nil { receipt = nil } })) { ReceiptView(receipt: $0.receipt) }
    }

    private func reload() async {
        if let fresh = try? await model.api?.transaction(transaction.id) { transaction = fresh }
    }
}

/// A current account: balance, its card and its ledger history.
struct AccountView: View {
    @EnvironmentObject var model: AppModel
    let account: Account
    @State private var history: [HistoryEntry] = []

    var body: some View {
        List {
            Section {
                AccountCard(account: model.account(account.id) ?? account, card: card).listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
            }
            if let card {
                Section {
                    HStack(spacing: 12) {
                        cardButton("snowflake", card.status == "FROZEN" ? "Разморозить" : "Заморозить") {
                            Task { await model.cardAction(card, card.status == "FROZEN" ? "unfreeze" : "freeze") }
                        }
                        cardButton("lock", "Блокировать") { Task { await model.cardAction(card, "block") } }
                    }
                    .disabled(card.status == "BLOCKED")
                    if card.status != "ACTIVE" { Text(card.status == "FROZEN" ? "Карта заморожена" : "Карта заблокирована").font(.footnote).foregroundColor(Theme.negative) }
                }
            }
            Section {
                NavigationLink { TransferView(mode: .iban) } label: { Label("Новый платёж/перевод", systemImage: "doc.text") }
                NavigationLink { RequisitesView(account: account) } label: { Label("Банковские реквизиты", systemImage: "building.columns") }
            }
            Section("История счёта") {
                ForEach(history) { entry in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(entry.beneficiaryName ?? (entry.journalKind == "OPENING" ? "Начальный остаток (тестовые средства)" : entry.memo)).font(.subheadline)
                            Text(entry.createdAt.shortDate).font(.caption).foregroundColor(Theme.muted)
                        }
                        Spacer()
                        Text(entry.amountMinor > 0 ? "+ " + entry.amount : entry.amount)
                            .font(.subheadline.weight(.semibold)).foregroundColor(entry.amountMinor > 0 ? Theme.positive : Theme.negative)
                    }
                }
            }
        }
        .navigationTitle(account.name)
        .navigationBarTitleDisplayMode(.inline)
        .task { history = (try? await model.api?.history(accountId: account.id)) ?? [] }
    }

    private var card: Card? { model.cards.first { $0.accountId == account.id } }

    private func cardButton(_ icon: String, _ title: String, _ run: @escaping () -> Void) -> some View {
        Button(action: run) {
            VStack(spacing: 6) {
                Image(systemName: icon).frame(width: 48, height: 48).background(Theme.accentSoft).clipShape(Circle()).foregroundColor(Theme.deep)
                Text(title).font(.caption).foregroundColor(Theme.ink)
            }
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderless)
    }
}

struct RequisitesView: View {
    @EnvironmentObject var model: AppModel
    let account: Account
    var body: some View {
        List {
            KeyValueRow(key: "Получатель", value: model.profile?.displayName ?? "")
            KeyValueRow(key: "IBAN", value: account.iban)
            KeyValueRow(key: "Валюта", value: account.currency)
            KeyValueRow(key: "Банк", value: model.bank?.branding.name ?? "")
            ShareLink(item: "\(model.profile?.displayName ?? "")\nIBAN \(account.iban)\n\(model.bank?.branding.name ?? "")") { Label("Поделиться", systemImage: "square.and.arrow.up") }
        }
        .navigationTitle("Реквизиты")
    }
}
