import SwiftUI

struct HomeView: View {
    @EnvironmentObject var model: AppModel
    @State private var segment = "Счета"
    @State private var showNotifications = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    header
                    summary
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "Мои продукты")
                        Picker("", selection: $segment) {
                            ForEach(["Счета", "Кредиты", "Депозиты", "Страхование"], id: \.self) { Text($0) }
                        }
                        .pickerStyle(.segmented)
                        if segment == "Счета" {
                            TabView {
                                ForEach(model.accounts) { account in
                                    NavigationLink(value: account) { AccountCard(account: account, card: model.cards.first { $0.accountId == account.id }) }
                                        .buttonStyle(.plain).padding(.horizontal, 2)
                                }
                            }
                            .tabViewStyle(.page(indexDisplayMode: .automatic))
                            .frame(height: 190)
                        } else {
                            CardBox { Text("Нет продуктов в этой категории. Каталог — во вкладке «Продукты».").font(.subheadline).foregroundColor(Theme.muted) }
                        }
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "Быстрые действия")
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 10) {
                                NavigationLink { TransferView(mode: .iban) } label: { Tile(icon: "doc.text", title: "Новый платёж") }
                                NavigationLink { TransferView(mode: .ownAccount) } label: { Tile(icon: "arrow.left.arrow.right", title: "Между своими счетами") }
                                ForEach(model.favorites) { favorite in
                                    NavigationLink { TransferView(mode: .iban, favorite: favorite) } label: { Tile(icon: "star", title: favorite.name) }
                                }
                            }
                        }
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "Транзакции")
                        CardBox {
                            if model.transactions.isEmpty {
                                Text("Операций пока нет.").font(.subheadline).foregroundColor(Theme.muted)
                            }
                            ForEach(model.transactions.prefix(4)) { t in
                                NavigationLink(value: t) { TransactionRow(transaction: t) }.buttonStyle(.plain)
                                if t.id != model.transactions.prefix(4).last?.id { Divider() }
                            }
                        }
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "Предложения")
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 10) { ForEach(model.products) { ProductTile(product: $0) } }
                        }
                    }
                    if let notice = model.bank?.branding.notice {
                        Text(notice).font(.caption).foregroundColor(Theme.muted)
                    }
                }
                .padding(16)
            }
            .background(Theme.headerGradient.ignoresSafeArea())
            .refreshable { await model.refresh() }
            .navigationDestination(for: Account.self) { AccountView(account: $0) }
            .navigationDestination(for: BankTransaction.self) { TransactionView(transaction: $0) }
            .sheet(isPresented: $showNotifications) { NotificationsView() }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Circle().fill(Theme.accent.opacity(0.25)).frame(width: 40, height: 40)
                .overlay(Text(String(model.profile?.displayName.prefix(1) ?? "?")).font(.headline).foregroundColor(Theme.deep))
            Text(model.profile?.displayName ?? "").font(.headline)
            Spacer()
            Button { showNotifications = true } label: {
                Image(systemName: model.unreadCount > 0 ? "bell.badge" : "bell").font(.system(size: 17))
                    .frame(width: 38, height: 38).background(Color.white).clipShape(RoundedRectangle(cornerRadius: 10))
            }
            .foregroundColor(Theme.ink)
        }
    }

    private var summary: some View {
        HStack(spacing: 10) {
            CardBox {
                Text("Всего на счетах").font(.caption).foregroundColor(Theme.muted)
                Text(Money.format(model.accounts.reduce(0) { $0 + $1.balanceMinor }, model.currency)).font(.headline).padding(.top, 4)
            }
            CardBox {
                Text("Ждут подтверждения").font(.caption).foregroundColor(Theme.muted)
                Text("\(model.transactions.filter { $0.state == "AUTHORIZATION_PENDING" }.count)").font(.headline).padding(.top, 4)
            }
        }
    }
}

struct AccountCard: View {
    let account: Account
    let card: Card?
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text(account.name).font(.subheadline).foregroundColor(.white.opacity(0.9))
                Spacer()
                Text(card?.brand ?? "СЧЁТ").font(.headline.weight(.heavy)).italic().foregroundColor(.white)
            }
            Spacer()
            Text(account.balance).font(.system(size: 30, weight: .bold)).foregroundColor(.white)
            HStack {
                Text(card.map { "**** \($0.last4)" } ?? account.shortNumber)
                Spacer()
                if let card { Text(card.expires) }
            }
            .font(.footnote).foregroundColor(.white.opacity(0.85))
        }
        .padding(18)
        .frame(height: 170)
        .background(Theme.cardGradient)
        .clipShape(RoundedRectangle(cornerRadius: 18))
    }
}

struct TransactionRow: View {
    let transaction: BankTransaction
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: transaction.kind == "INTERNAL_TRANSFER" ? "arrow.left.arrow.right" : "cart")
                .frame(width: 36, height: 36).background(Theme.background).clipShape(RoundedRectangle(cornerRadius: 10))
                .foregroundColor(Theme.ink)
            VStack(alignment: .leading, spacing: 3) {
                Text(transaction.beneficiaryName).font(.subheadline.weight(.medium)).lineLimit(1)
                Text("**** \(transaction.beneficiaryIban.suffix(4)) · \(transaction.createdAt.shortDate)").font(.caption).foregroundColor(Theme.muted)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 3) {
                Text("- " + transaction.total).font(.subheadline.weight(.semibold))
                    .foregroundColor(transaction.state == "EXECUTED" ? Theme.negative : Theme.muted)
                StateLabel(transaction: transaction)
            }
        }
        .padding(.vertical, 8)
        .contentShape(Rectangle())
    }
}

struct ProductTile: View {
    let product: Product
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Image(systemName: icon).font(.system(size: 26)).foregroundColor(.white)
            Spacer()
            Text(product.title).font(.footnote.weight(.semibold)).foregroundColor(.white).lineLimit(2)
        }
        .padding(12)
        .frame(width: 150, height: 120, alignment: .topLeading)
        .background(LinearGradient(colors: [Theme.deep.opacity(0.85), Theme.accent.opacity(0.8)], startPoint: .top, endPoint: .bottom))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }
    private var icon: String {
        switch product.kind { case "CARD": return "creditcard"; case "LOAN": return "car"; default: return "banknote" }
    }
}

struct NotificationsView: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            NotificationsList().toolbar { Button("Готово") { dismiss() } }
        }
    }
}

struct NotificationsList: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        List(model.notifications) { n in
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(n.title).font(.subheadline.weight(n.state == "READ" ? .regular : .semibold))
                    Spacer()
                    Text(n.createdAt.shortDate).font(.caption).foregroundColor(Theme.muted)
                }
                Text(n.body).font(.footnote).foregroundColor(Theme.muted)
            }
        }
        .overlay { if model.notifications.isEmpty { Text("Уведомлений нет").foregroundColor(Theme.muted) } }
        .navigationTitle("Уведомления")
        .task { await model.markNotificationsRead() }
    }
}
