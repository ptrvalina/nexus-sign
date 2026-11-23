import SwiftUI

// Visual language of the mockups (sandbox/design/mockups): teal accent,
// light mint backgrounds, white rounded cards, a dark teal card gradient.
enum Theme {
    static let accent = Color(red: 0.24, green: 0.75, blue: 0.66)      // #3DBFA8
    static let accentSoft = Color(red: 0.86, green: 0.95, blue: 0.93)  // tiles
    static let deep = Color(red: 0.12, green: 0.35, blue: 0.35)        // #1E5A5A
    static let background = Color(red: 0.97, green: 0.98, blue: 0.98)
    static let mint = Color(red: 0.90, green: 0.97, blue: 0.96)
    static let ink = Color(red: 0.08, green: 0.12, blue: 0.14)
    static let muted = Color(red: 0.45, green: 0.50, blue: 0.53)
    static let negative = Color(red: 0.88, green: 0.36, blue: 0.27)
    static let positive = Color(red: 0.13, green: 0.62, blue: 0.47)

    static let cardGradient = LinearGradient(colors: [deep, Color(red: 0.18, green: 0.55, blue: 0.52), accent.opacity(0.85)], startPoint: .topLeading, endPoint: .bottomTrailing)
    static let headerGradient = LinearGradient(colors: [mint, background], startPoint: .top, endPoint: .bottom)
}

struct PrimaryButton: View {
    let title: String
    var busy = false
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            ZStack {
                Text(title).font(.body.weight(.semibold)).opacity(busy ? 0 : 1)
                if busy { ProgressView().tint(.white) }
            }
            .frame(maxWidth: .infinity, minHeight: 52)
            .background(Theme.accent)
            .foregroundColor(.white)
            .clipShape(RoundedRectangle(cornerRadius: 14))
        }
        .disabled(busy)
    }
}

struct SecondaryButton: View {
    let title: String
    var role: ButtonRole? = nil
    let action: () -> Void
    var body: some View {
        Button(role: role, action: action) {
            Text(title).font(.body.weight(.medium))
                .frame(maxWidth: .infinity, minHeight: 48)
                .background(Theme.accentSoft)
                .foregroundColor(role == .destructive ? Theme.negative : Theme.deep)
                .clipShape(RoundedRectangle(cornerRadius: 14))
        }
    }
}

struct CardBox<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .padding(14)
            .background(Color.white)
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .shadow(color: Theme.deep.opacity(0.06), radius: 8, y: 2)
    }
}

struct BrandBadge: View {
    let text: String
    var body: some View {
        Text(text).font(.system(size: 11, weight: .heavy)).italic()
            .foregroundColor(Theme.deep)
            .frame(width: 44, height: 32)
            .background(Color.white)
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.accentSoft))
    }
}

struct SectionHeader: View {
    let title: String
    var action: String? = nil
    var onAction: (() -> Void)? = nil
    var body: some View {
        HStack {
            Text(title).font(.title3.weight(.bold)).foregroundColor(Theme.ink)
            Spacer()
            if let action, let onAction { Button(action, action: onAction).font(.subheadline).foregroundColor(Theme.accent) }
        }
    }
}

struct Tile: View {
    let icon: String
    let title: String
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Image(systemName: icon).font(.system(size: 18)).foregroundColor(Theme.accent)
                .frame(width: 36, height: 36).background(Color.white).clipShape(RoundedRectangle(cornerRadius: 10))
            Text(title).font(.footnote.weight(.medium)).foregroundColor(Theme.ink).multilineTextAlignment(.leading).lineLimit(2)
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(width: 112, height: 112, alignment: .topLeading)
        .background(Theme.accentSoft)
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }
}

struct LogoMark: View {
    var size: CGFloat = 56
    var body: some View {
        ZStack {
            Circle().fill(Theme.accent)
            Image(systemName: "checkmark.shield.fill").font(.system(size: size * 0.45, weight: .bold)).foregroundColor(.white)
        }
        .frame(width: size, height: size)
    }
}

struct StateLabel: View {
    let transaction: BankTransaction
    var body: some View {
        Text(transaction.stateTitle).font(.caption.weight(.semibold))
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(color.opacity(0.15)).foregroundColor(color)
            .clipShape(Capsule())
    }
    private var color: Color {
        switch transaction.state {
        case "EXECUTED": return Theme.positive
        case "AUTHORIZATION_PENDING", "OFFLINE_PROVISIONAL", "AUTHORIZING", "CREATED": return .orange
        case "CANCELLED": return Theme.muted
        default: return Theme.negative
        }
    }
}

struct KeyValueRow: View {
    let key: String
    let value: String
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(key).foregroundColor(Theme.ink)
            Spacer(minLength: 12)
            Text(value).foregroundColor(Theme.muted).multilineTextAlignment(.trailing)
        }
        .font(.subheadline)
        .padding(.vertical, 12)
    }
}

private let isoParser: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
}()

private let shortFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = Locale(identifier: "ru_RU")
    f.dateFormat = "dd.MM HH:mm"
    return f
}()

extension String {
    /// "2026-11-23T17:15:03.123Z" → "23.11 20:15" in the phone's time zone.
    var shortDate: String {
        guard let date = isoParser.date(from: self) ?? ISO8601DateFormatter().date(from: self) else { return self }
        return shortFormatter.string(from: date)
    }
}
