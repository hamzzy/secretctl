import SwiftUI
import SecretctlKit

/// Shared presentation vocabulary.
///
/// Two conventions are load-bearing rather than decorative:
///
/// - Every status indicator pairs a glyph with a word. Nothing in this app
///   means something only by being green or only by being red.
/// - Broker-verified fields and agent-supplied text are drawn differently and
///   labelled as such, so an agent cannot write a `reason` that reads like
///   system chrome.

extension Color {
    static let verifiedAccent = Color.accentColor
}

/// A small uppercase section heading, as used throughout the popover.
struct SectionHeading: View {
    let title: String

    var body: some View {
        Text(title)
            .font(.system(size: 10, weight: .semibold))
            .kerning(0.6)
            .foregroundStyle(.secondary)
            .textCase(.uppercase)
            .accessibilityAddTraits(.isHeader)
    }
}

/// A labelled fact the broker verified. The label is quiet, the value is not.
struct VerifiedField: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 13, weight: .medium, design: monospaced ? .monospaced : .default))
                .textSelection(.enabled)
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }
}

/// Text the agent wrote.
///
/// Rendered as an attributed quotation with an explicit "provided by the agent"
/// caption. The agent controls this string; the framing makes clear that
/// secretctl does not vouch for it.
struct AgentProvidedText: View {
    let agentName: String
    let text: String

    /// Clamped so a long reason cannot push the buttons off-screen or bury the
    /// verified facts above it.
    private var clamped: String {
        text.count > 400 ? String(text.prefix(400)) + "…" : text
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 4) {
                Image(systemName: "quote.opening")
                    .font(.system(size: 9))
                Text("Provided by \(agentName), not verified by secretctl")
                    .font(.system(size: 10))
            }
            .foregroundStyle(.secondary)

            Text(clamped)
                .font(.system(size: 12))
                .italic()
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.leading, 10)
                .overlay(alignment: .leading) {
                    Rectangle()
                        .fill(Color.secondary.opacity(0.35))
                        .frame(width: 2)
                }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Reason provided by \(agentName), not verified by secretctl: \(clamped)")
    }
}

/// A risk level, as a shape plus a word.
struct RiskBadge: View {
    let risk: RiskLevel

    private var symbol: String {
        switch risk {
        case .low: return "circle"
        case .medium: return "triangle"
        case .high: return "exclamationmark.triangle.fill"
        case .critical: return "exclamationmark.octagon.fill"
        }
    }

    private var tint: Color {
        switch risk {
        case .low: return .secondary
        case .medium: return .orange
        case .high: return .orange
        case .critical: return .red
        }
    }

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: symbol).font(.system(size: 10))
            Text(risk.label).font(.system(size: 11, weight: .medium))
        }
        .foregroundStyle(tint)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Risk level: \(risk.label)")
    }
}

/// A confirmed-or-not line, e.g. the browser protection list.
struct ConfirmationRow: View {
    let text: String
    var confirmed = true

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: confirmed ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.system(size: 10))
                .foregroundStyle(confirmed ? Color.green : Color.red)
            Text(text)
                .font(.system(size: 11))
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(confirmed ? "Confirmed" : "Not confirmed"): \(text)")
    }
}

/// One step in an operation's progress list.
struct StepRow: View {
    let step: OperationStep

    private var symbol: String {
        switch step.state {
        case .pending: return "circle"
        case .active: return "circle.dotted"
        case .done: return "checkmark.circle.fill"
        case .failed: return "xmark.circle.fill"
        }
    }

    private var tint: Color {
        switch step.state {
        case .pending: return .secondary
        case .active: return .accentColor
        case .done: return .green
        case .failed: return .red
        }
    }

    private var spokenState: String {
        switch step.state {
        case .pending: return "not started"
        case .active: return "in progress"
        case .done: return "completed"
        case .failed: return "failed"
        }
    }

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol)
                .font(.system(size: 11))
                .foregroundStyle(tint)
                // The glyph swap is the row's entire message, so it gets a
                // real symbol transition rather than an abrupt replacement.
                .contentTransition(.symbolEffect(.replace.offUp))
            Text(step.label)
                .font(.system(size: 12))
                .foregroundStyle(step.state == .pending ? .secondary : .primary)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(step.label): \(spokenState)")
    }
}

/// "2m", "18m", "3d" — relative timestamps in the compact style the popover
/// uses.
enum RelativeTime {
    static func short(_ date: Date, now: Date = Date()) -> String {
        let interval = max(0, now.timeIntervalSince(date))
        switch interval {
        case ..<60: return "now"
        case ..<3600: return "\(Int(interval / 60))m"
        case ..<86400: return "\(Int(interval / 3600))h"
        default: return "\(Int(interval / 86400))d"
        }
    }

    static func spoken(_ date: Date, now: Date = Date()) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: now)
    }

    static func day(_ date: Date) -> String {
        date.formatted(.dateTime.month(.abbreviated).day())
    }

    static func full(_ date: Date) -> String {
        date.formatted(.dateTime.month(.wide).day().year())
    }
}

/// Host without scheme or port, for compact display. The full origin is always
/// shown somewhere on the approval surface — this is only ever a shortening for
/// lists, never for the thing being authorized.
enum OriginDisplay {
    static func host(_ origin: String) -> String {
        guard let url = URL(string: origin), let host = url.host() else { return origin }
        return host
    }
}
