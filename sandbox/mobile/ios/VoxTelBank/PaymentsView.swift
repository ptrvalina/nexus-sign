import SwiftUI

struct PaymentsView: View {
    @EnvironmentObject var model: AppModel
    @State private var search = ""

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    HStack {
                        Image(systemName: "magnifyingglass").foregroundColor(Theme.muted)
                        TextField("Поиск по избранному", text: $search)
                    }
                    .padding(12).background(RoundedRectangle(cornerRadius: 12).stroke(Color.gray.opacity(0.3)))

                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "Избранное")
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 10) {
                                ForEach(filteredFavorites) { favorite in
                                    NavigationLink { TransferView(mode: .iban, favorite: favorite) } label: { Tile(icon: "star", title: favorite.name) }
                                }
                                if filteredFavorites.isEmpty { Text("Сохраните получателя после перевода.").font(.footnote).foregroundColor(Theme.muted) }
                            }
                        }
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "Платежи")
                        HStack(spacing: 10) {
                            NavigationLink { TransferView(mode: .iban) } label: { Tile(icon: "doc.text", title: "Новый платёж") }
                            NavigationLink { TransferView(mode: .iban, presetName: "Казначейство (тест)", presetIban: "MD65RN000000000000000555") } label: { Tile(icon: "building.columns", title: "Платёж в бюджет") }
                        }
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "Переводы")
                        HStack(spacing: 10) {
                            NavigationLink { TransferView(mode: .ownAccount) } label: { Tile(icon: "arrow.left.arrow.right", title: "Между своими счетами") }
                            NavigationLink { TransferView(mode: .iban) } label: { Tile(icon: "person", title: "По номеру счёта (IBAN)") }
                        }
                    }
                }
                .padding(16)
            }
            .background(Theme.background.ignoresSafeArea())
            .navigationTitle("Платежи")
        }
    }

    private var filteredFavorites: [Favorite] {
        search.isEmpty ? model.favorites : model.favorites.filter { $0.name.localizedCaseInsensitiveContains(search) || $0.iban.contains(search.uppercased()) }
    }
}

enum TransferMode { case iban, ownAccount }

struct TransferView: View {
    @EnvironmentObject var model: AppModel
    let mode: TransferMode
    var favorite: Favorite? = nil
    var presetName: String? = nil
    var presetIban: String? = nil

    @State private var sourceId = ""
    @State private var destinationId = ""
    @State private var name = ""
    @State private var iban = ""
    @State private var amount = ""
    @State private var note = ""
    @State private var quote: Quote?
    @State private var order: PaymentOrder?
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Отправитель").font(.footnote).foregroundColor(Theme.muted)
                AccountPicker(accounts: model.accounts, selection: $sourceId)
                Text("Получатель").font(.footnote).foregroundColor(Theme.muted)
                if mode == .ownAccount {
                    AccountPicker(accounts: model.accounts.filter { $0.id != sourceId }, selection: $destinationId)
                } else {
                    VStack(spacing: 10) {
                        field("Имя получателя", text: $name)
                        field("IBAN получателя", text: $iban).textInputAutocapitalization(.characters)
                    }
                }
                HStack {
                    TextField("Сумма перевода", text: $amount).keyboardType(.decimalPad)
                    Text(model.currency).foregroundColor(Theme.muted)
                }
                .padding(14).background(RoundedRectangle(cornerRadius: 12).stroke(Color.gray.opacity(0.3)))
                field("Назначение (необязательно)", text: $note)
                if let error { Text(error).font(.footnote).foregroundColor(Theme.negative) }
            }
            .padding(16)
        }
        .safeAreaInset(edge: .bottom) {
            PrimaryButton(title: "Оплатить", busy: loading) { Task { await prepare() } }
                .padding(16).background(Theme.background)
        }
        .background(Theme.background.ignoresSafeArea())
        .navigationTitle(mode == .ownAccount ? "Между своими счетами" : "Перевод по IBAN")
        .navigationBarTitleDisplayMode(.inline)
        .navigationDestination(isPresented: Binding(get: { quote != nil }, set: { if !$0 { quote = nil } })) {
            if let quote, let order { ReviewView(order: order, quote: quote) }
        }
        .onAppear {
            if sourceId.isEmpty { sourceId = model.accounts.first?.id ?? "" }
            if destinationId.isEmpty { destinationId = model.accounts.first { $0.id != sourceId }?.id ?? "" }
            if let favorite, name.isEmpty { name = favorite.name; iban = favorite.iban }
            if let presetName, name.isEmpty { name = presetName; iban = presetIban ?? "" }
        }
    }

    private func field(_ title: String, text: Binding<String>) -> some View {
        TextField(title, text: text).autocorrectionDisabled()
            .padding(14).background(RoundedRectangle(cornerRadius: 12).stroke(Color.gray.opacity(0.3)))
    }

    private func prepare() async {
        error = nil
        guard let minor = Money.minor(from: amount) else { error = "Введите сумму, например 50 или 50.25"; return }
        var order = PaymentOrder(sourceAccountId: sourceId, amountMinor: minor, description: note.isEmpty ? nil : note)
        if mode == .ownAccount {
            guard !destinationId.isEmpty else { error = "Нужен второй счёт"; return }
            order.destinationAccountId = destinationId
        } else {
            order.beneficiaryName = name.trimmingCharacters(in: .whitespaces)
            order.beneficiaryIban = iban.replacingOccurrences(of: " ", with: "").uppercased()
        }
        loading = true
        defer { loading = false }
        do {
            quote = try await model.quote(order)
            self.order = order
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}

struct AccountPicker: View {
    let accounts: [Account]
    @Binding var selection: String
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 10) {
                ForEach(accounts) { account in
                    Button { selection = account.id } label: {
                        HStack(spacing: 10) {
                            BrandBadge(text: "MDL")
                            VStack(alignment: .leading, spacing: 2) {
                                Text(account.name).font(.subheadline.weight(.medium)).foregroundColor(Theme.ink)
                                Text(account.shortNumber).font(.caption).foregroundColor(Theme.muted)
                            }
                            Text(account.balance).font(.subheadline.weight(.semibold)).foregroundColor(Theme.ink)
                        }
                        .padding(12)
                        .background(Color.white)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .overlay(RoundedRectangle(cornerRadius: 14).stroke(selection == account.id ? Theme.accent : Color.clear, lineWidth: 2))
                    }
                }
            }
        }
    }
}

/// Review before sending: amount, commission and total exactly as the bank quoted them.
struct ReviewView: View {
    @EnvironmentObject var model: AppModel
    let order: PaymentOrder
    let quote: Quote
    @State private var idempotencyKey = UUID().uuidString

    var body: some View {
        VStack(spacing: 0) {
            Text(Money.format(quote.amountMinor, quote.currency)).font(.system(size: 34, weight: .bold)).padding(.vertical, 24)
            CardBox {
                party("Отправитель", model.account(order.sourceAccountId).map { "\($0.name) (\($0.shortNumber))" } ?? "")
                Divider()
                party("Получатель", "\(quote.beneficiaryName) (**** \(quote.beneficiaryIban.suffix(4)))")
                Divider()
                KeyValueRow(key: "Сумма перевода", value: Money.format(quote.amountMinor, quote.currency))
                Divider()
                KeyValueRow(key: "Комиссия", value: Money.format(quote.feeMinor, quote.currency))
                Divider()
                KeyValueRow(key: "Итоговая сумма", value: Money.format(quote.totalMinor, quote.currency))
            }
            Text("После нажатия банк попросит подтвердить операцию ключом этого iPhone (Face ID / Touch ID).")
                .font(.footnote).foregroundColor(Theme.muted).multilineTextAlignment(.center).padding(.top, 14)
            Spacer()
            PrimaryButton(title: "Подтвердить", busy: model.busy) {
                Task { await model.submit(order, idempotencyKey: idempotencyKey) }
            }
        }
        .padding(16)
        .background(Theme.headerGradient.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
    }

    private func party(_ title: String, _ value: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.caption).foregroundColor(Theme.muted)
                Text(value).font(.subheadline)
            }
            Spacer()
            BrandBadge(text: "MDL")
        }
        .padding(.vertical, 10)
    }
}
