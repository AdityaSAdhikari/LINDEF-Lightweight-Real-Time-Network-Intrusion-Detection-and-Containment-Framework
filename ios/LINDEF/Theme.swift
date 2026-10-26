import SwiftUI
import UIKit

/// The "paper" look shared with the desktop app and the LINDEF poster:
/// white paper, dark ink, thin rules, serif headings, pale section tints.
enum Paper {
    static let paper = Color(light: 0xFFFFFF, dark: 0x17191C)
    static let paper2 = Color(light: 0xF6F7F8, dark: 0x1E2124)
    static let ink = Color(light: 0x1B1F24, dark: 0xE7E9EC)
    static let ink2 = Color(light: 0x4A535D, dark: 0xB4BBC3)
    static let ink3 = Color(light: 0x707A85, dark: 0x8B939C)
    static let rule = Color(light: 0xCFD5DB, dark: 0x353A40)
    static let ruleStrong = Color(light: 0x1B1F24, dark: 0xC9CED4)
    static let accent = Color(light: 0x23517F, dark: 0x8FB6E0)
    static let accentInk = Color(light: 0xFFFFFF, dark: 0x10161D)
    static let ok = Color(light: 0x3D7A55, dark: 0x74B48C)
    static let bad = Color(light: 0xB42318, dark: 0xF2776B)

    // Section tints, taken from the poster's panel colors.
    static let blue = Color(light: 0xDDE9F5, dark: 0x1F2B37)
    static let green = Color(light: 0xE2EFD9, dark: 0x213026)
    static let lavender = Color(light: 0xE9E2F4, dark: 0x2A2537)
    static let rose = Color(light: 0xF5DFDC, dark: 0x352423)
    static let peach = Color(light: 0xFBE6D4, dark: 0x36291F)
    static let butter = Color(light: 0xFAF0CC, dark: 0x33301D)

    static func severity(_ level: String?) -> Color {
        switch level {
        case "LOW": return Color(light: 0x3D7A55, dark: 0x74B48C)
        case "MEDIUM", "UNKNOWN": return Color(light: 0xA5670F, dark: 0xE0A24A)
        case "HIGH": return Color(light: 0xC2410C, dark: 0xF08A4B)
        case "CRITICAL": return Color(light: 0xB42318, dark: 0xF2776B)
        default: return Color(light: 0x87909A, dark: 0x8B939C)
        }
    }

    static func serif(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .serif)
    }
}

extension Color {
    init(light: UInt32, dark: UInt32) {
        self.init(UIColor { traits in
            UIColor(hex: traits.userInterfaceStyle == .dark ? dark : light)
        })
    }
}

extension UIColor {
    convenience init(hex: UInt32) {
        self.init(red: CGFloat((hex >> 16) & 0xFF) / 255,
                  green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255,
                  alpha: 1)
    }
}

// MARK: - Shared pieces

/// A ruled box with a tinted, serif-titled header, like a poster panel.
struct PaperSection<Content: View>: View {
    let title: String
    var aside: String? = nil
    let tint: Color
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(Paper.serif(18, .semibold)).foregroundStyle(Paper.ink)
                Spacer(minLength: 8)
                if let aside {
                    Text(aside).font(.footnote).foregroundStyle(Paper.ink2).multilineTextAlignment(.trailing)
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 9)
            .background(tint)
            Rectangle().fill(Paper.rule).frame(height: 1)
            content
        }
        .background(Paper.paper)
        .overlay(Rectangle().stroke(Paper.rule, lineWidth: 1))
    }
}

/// A colored square plus the severity word.
struct SeverityLabel: View {
    let level: String?

    var body: some View {
        HStack(spacing: 5) {
            RoundedRectangle(cornerRadius: 2).fill(Paper.severity(level)).frame(width: 9, height: 9)
            Text(Words.severity(level)).font(.footnote).foregroundStyle(Paper.ink)
        }
    }
}

/// Rows inside a section, separated by thin rules.
struct RuledRow<Content: View>: View {
    var last = false
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            content.padding(.horizontal, 14).padding(.vertical, 10)
            if !last { Rectangle().fill(Paper.rule).frame(height: 1) }
        }
    }
}

struct PaperButtonStyle: ButtonStyle {
    var primary = false
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.subheadline.weight(.medium))
            .padding(.horizontal, 14).padding(.vertical, 8)
            .frame(maxWidth: .infinity)
            .foregroundStyle(primary ? Paper.accentInk : Paper.ink)
            .background(primary ? Paper.accent : Paper.paper)
            .overlay(RoundedRectangle(cornerRadius: 3).stroke(primary ? Paper.accent : Paper.ruleStrong, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 3))
            .opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.4)
    }
}

/// Plain words for the codes the agent sends.
enum Words {
    static var attackLabels: [String: String] = [:]    // from the agent
    static var responseLabels: [String: String] = [:]

    private static func pretty(_ code: String) -> String {
        let spaced = code.replacingOccurrences(of: "_", with: " ")
        return spaced.prefix(1).uppercased() + spaced.dropFirst()
    }

    static func attack(_ code: String) -> String { attackLabels[code] ?? pretty(code) }
    static func response(_ code: String) -> String { responseLabels[code] ?? pretty(code) }

    static func severity(_ level: String?) -> String {
        switch level {
        case "LOW": return "Low"
        case "MEDIUM": return "Medium"
        case "HIGH": return "High"
        case "CRITICAL": return "Critical"
        case "UNKNOWN": return "Unknown"
        default: return "None"
        }
    }

    static func action(_ code: String) -> String {
        ["BLOCK_IP": "Block", "THROTTLE_IP": "Throttle", "ISOLATE_HOST": "Isolate host"][code] ?? code
    }

    static func actionPast(_ code: String) -> String {
        ["BLOCK_IP": "Blocked", "THROTTLE_IP": "Throttled", "ISOLATE_HOST": "Isolated"][code] ?? code
    }

    static func article(_ word: String) -> String {
        word.range(of: "^([aeiou]|http|ftp|xterm)", options: [.regularExpression, .caseInsensitive]) != nil ? "an" : "a"
    }

    static func plural(_ n: Int, _ word: String) -> String {
        "\(n.formatted()) \(word)\(n == 1 ? "" : "s")"
    }

    static func address(_ ip: String?, _ port: String?) -> String {
        guard let ip else { return "Unknown" }
        return port.map { "\(ip):\($0)" } ?? ip
    }

    static func clock(_ epoch: Int) -> String {
        Date(timeIntervalSince1970: TimeInterval(epoch)).formatted(date: .omitted, time: .standard)
    }

    static func ago(_ epoch: Int) -> String {
        let seconds = max(0, Int(Date().timeIntervalSince1970) - epoch)
        if seconds < 60 { return "\(seconds)s ago" }
        if seconds < 3600 { return "\(seconds / 60) min ago" }
        return clock(epoch)
    }

    static func until(_ epoch: Int?) -> String {
        guard let epoch else { return "Until lifted" }
        let seconds = max(0, epoch - Int(Date().timeIntervalSince1970))
        return seconds >= 60 ? "Ends in \((seconds + 59) / 60) min" : "Ends in \(seconds)s"
    }
}
