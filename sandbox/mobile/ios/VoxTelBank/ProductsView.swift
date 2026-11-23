import SwiftUI

struct ProductsView: View {
    @EnvironmentObject var model: AppModel
    @State private var segment = "Счета"

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    Picker("", selection: $segment) {
                        ForEach(["Счета", "Кредиты", "Депозиты", "Страхование"], id: \.self) { Text($0) }
                    }
                    .pickerStyle(.segmented)
                    if segment == "Счета" {
                        ForEach(model.accounts) { account in
                            NavigationLink(value: account) {
                                CardBox {
                                    HStack(spacing: 12) {
                                        BrandBadge(text: model.cards.first { $0.accountId == account.id }?.brand ?? "MDL")
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text(account.name).font(.subheadline.weight(.medium)).foregroundColor(Theme.ink)
                                            Text(account.shortNumber).font(.caption).foregroundColor(Theme.muted)
                                        }
                                        Spacer()
                                        Text(account.balance).font(.subheadline.weight(.semibold)).foregroundColor(Theme.ink)
                                    }
                                }
                            }
                        }
                    } else {
                        ForEach(model.products.filter { kind(of: $0) == segment }) { product in
                            CardBox {
                                Text(product.title).font(.headline)
                                Text(product.summary).font(.footnote).foregroundColor(Theme.muted).padding(.top, 4)
                            }
                        }
                        if model.products.filter({ kind(of: $0) == segment }).isEmpty {
                            Text("В демо-банке нет продуктов этой категории.").font(.footnote).foregroundColor(Theme.muted)
                        }
                    }
                }
                .padding(16)
            }
            .background(Theme.background.ignoresSafeArea())
            .navigationTitle("Продукты")
            .navigationDestination(for: Account.self) { AccountView(account: $0) }
        }
    }

    private func kind(of product: Product) -> String {
        switch product.kind { case "LOAN": return "Кредиты"; case "DEPOSIT": return "Депозиты"; case "INSURANCE": return "Страхование"; default: return "Счета" }
    }
}
