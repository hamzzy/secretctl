import SwiftUI
import SecretctlKit

/// The menu-bar popover.
///
/// Deliberately not a dashboard: a header, what is happening right now, a short
/// recent list, standing authorizations, and a way out to the bigger windows.
/// Anything that needs real estate lives in Activity, and anything that needs
/// trust lives in the approval window.
struct PopoverView: View {
    @EnvironmentObject private var store: BrokerStore
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let onReview: (AuthorizationRequest) -> Void
    let onOpenActivity: () -> Void
    let onOpenSettings: () -> Void
    let onQuit: () -> Void

    @State private var grants: [Grant] = []
    /// Drives the one-time cascade of the recent list. Decorative: the rows are
    /// present and hit-testable from the first frame regardless.
    @State private var hasSettled = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if !store.pending.isEmpty { pendingSection }
                    currentSection
                    recentSection
                    standingSection
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
            }
            .frame(maxHeight: 380)

            Divider()
            footer
        }
        .frame(width: 320)
        .task {
            await loadGrants()
            withAnimation(nil) { hasSettled = true }
        }
        .onChange(of: store.status.activeGrants) { _, _ in Task { await loadGrants() } }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .center, spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text("secretctl")
                    .font(.system(size: 13, weight: .semibold))
                Text(headerSubtitle)
                    .font(.system(size: 11))
                    .foregroundStyle(store.protection.isAlarming ? Color.red : Color.secondary)
                    .contentTransition(.identity)
                    .id(headerSubtitle)
                    .transition(Motion.contentSwap)
            }
            Spacer()
            Image(systemName: StatusGlyph.symbolName(for: store.protection))
                .font(.system(size: 13))
                .foregroundStyle(store.protection.isAlarming ? Color.red : Color.accentColor)
                .symbolEffect(
                    .pulse,
                    options: reduceMotion ? .nonRepeating : .repeating,
                    isActive: !reduceMotion && store.protection == .sensitiveOperation
                )
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .animation(Motion.enter(), value: headerSubtitle)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(store.protection.accessibilityDescription)
    }

    private var headerSubtitle: String {
        if store.protection == .disconnected && !store.hasConnectedOnce {
            return "Connecting…"
        }
        return store.protection.headline
    }

    // MARK: - Sections

    private var pendingSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionHeading(title: store.pending.count == 1 ? "Waiting for you" : "Waiting for you (\(store.pending.count))")
            ForEach(store.pending) { request in
                Button { onReview(request) } label: {
                    HStack(spacing: 8) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(request.agentName) → \(OriginDisplay.host(request.origin))")
                                .font(.system(size: 12, weight: .medium))
                            Text(request.actionLabel)
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("Review")
                            .font(.system(size: 11, weight: .medium))
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.accentColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
                    .contentShape(RoundedRectangle(cornerRadius: 6))
                }
                .buttonStyle(PressableStyle())
                .accessibilityLabel("Review request from \(request.agentName) for \(request.actionLabel) at \(OriginDisplay.host(request.origin))")
            }
        }
    }

    @ViewBuilder
    private var currentSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionHeading(title: "Current")

            // Keyed on protection state, not on the operation, so a step
            // advancing inside one operation updates in place instead of
            // re-entering the whole block.
            currentContent
                .id(store.protection)
                .transition(Motion.contentSwap)
        }
        .animation(Motion.enter(), value: store.protection)
    }

    @ViewBuilder
    private var currentContent: some View {
        Group {
            if let operation = store.activeOperation {
                ActiveOperationSummary(operation: operation)
            } else if store.protection == .protectionInterrupted {
                InterruptionNotice(onDetails: onOpenActivity)
            } else if store.protection == .outcomeUncertain {
                UncertainOutcomeNotice(onDetails: onOpenActivity)
            } else if store.protection == .completedEvidenceLost {
                EvidenceLostNotice(onDetails: onOpenActivity)
            } else if store.protection == .disconnected {
                DisconnectedNotice(failure: store.lastFailure, connecting: !store.hasConnectedOnce)
            } else if store.protection.isAlarming {
                // A state that wants attention but has no bespoke panel yet.
                // Being vague is bad; saying "nothing is happening" would be
                // false, which is worse.
                VStack(alignment: .leading, spacing: 6) {
                    Label(store.protection.headline, systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(.orange)
                    Text(store.protection.accessibilityDescription)
                        .font(.system(size: 11))
                        .fixedSize(horizontal: false, vertical: true)
                    Button("View details", action: onOpenActivity)
                        .buttonStyle(LinkPressStyle())
                        .font(.system(size: 11))
                }
            } else {
                Text("No sensitive operation")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var recentSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionHeading(title: "Recent")
            if store.recentActivity.isEmpty {
                Text("Nothing yet")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            } else {
                ForEach(Array(store.recentActivity.prefix(4).enumerated()), id: \.element.id) { index, event in
                    ActivityRow(event: event, compact: true)
                        .staggeredAppearance(index: index, isVisible: hasSettled)
                }
            }
        }
    }

    @ViewBuilder
    private var standingSection: some View {
        if !grants.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                SectionHeading(title: "Standing authorizations")
                ForEach(grants.prefix(3)) { grant in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(grant.credentialName)
                            .font(.system(size: 12, weight: .medium))
                        Text("\(grant.agentName) → \(OriginDisplay.host(grant.origin))")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                        Text("Expires \(RelativeTime.day(grant.expiresAt))")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(grant.credentialName), \(grant.agentName) to \(OriginDisplay.host(grant.origin)), expires \(RelativeTime.full(grant.expiresAt))")
                }
                if grants.count > 3 {
                    Button("Show all \(grants.count)") { onOpenActivity() }
                        .buttonStyle(.link)
                        .font(.system(size: 11))
                }
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 12) {
            Button("Activity") { onOpenActivity() }
                .buttonStyle(.link)
            Button("Settings") { onOpenSettings() }
                .buttonStyle(.link)
            Spacer()
            Button("Quit") { onQuit() }
                .buttonStyle(.link)
                .foregroundStyle(.secondary)
        }
        .font(.system(size: 11))
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }

    private func loadGrants() async {
        grants = (try? await store.grants()) ?? []
    }
}

/// The in-flight operation, as reported by the daemon.
///
/// Every protection line comes from `confirmedProtections`, which the executor
/// actually confirmed. The UI adds nothing to that list: claiming "screenshot
/// capture blocked" on the strength of an assumption would be worse than saying
/// nothing at all.
struct ActiveOperationSummary: View {
    let operation: ActiveOperation

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(operation.agentName)
                    .font(.system(size: 12, weight: .semibold))
                Text("\(operation.actionLabel) at \(OriginDisplay.host(operation.origin))")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }

            VerifiedField(label: "Credential", value: operation.credentialName)

            if !operation.steps.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Progress").font(.system(size: 11)).foregroundStyle(.secondary)
                    ForEach(operation.steps, id: \.label) { StepRow(step: $0) }
                }
                .animation(Motion.move(0.2), value: operation.steps)
            }

            VStack(alignment: .leading, spacing: 3) {
                Text("Browser protection").font(.system(size: 11)).foregroundStyle(.secondary)
                if operation.protectionVerified {
                    ForEach(Array(operation.confirmedProtections.enumerated()), id: \.element) { index, protection in
                        ConfirmationRow(text: protection)
                            .transition(Motion.contentSwap)
                            .zIndex(Double(-index))
                    }
                    if operation.confirmedProtections.isEmpty {
                        Text("Verified, no specific protections reported")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                } else {
                    ConfirmationRow(text: "Protection could not be verified", confirmed: false)
                        .transition(Motion.contentSwap)
                }
            }
            .animation(Motion.enter(), value: operation.confirmedProtections)
            .animation(Motion.enter(), value: operation.protectionVerified)

            ConfirmationRow(text: "Credential not exposed to the agent")
        }
    }
}

struct InterruptionNotice: View {
    let onDetails: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Protection interrupted", systemImage: "exclamationmark.shield.fill")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.red)
            Text("A sensitive browser operation was stopped. secretctl could no longer verify browser protection, so credential release was halted where possible.")
                .font(.system(size: 11))
                .fixedSize(horizontal: false, vertical: true)
            Button("View details", action: onDetails)
                .buttonStyle(.link)
                .font(.system(size: 11))
        }
    }
}

struct UncertainOutcomeNotice: View {
    let onDetails: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Outcome uncertain", systemImage: "questionmark.diamond.fill")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.orange)
            Text("The credential operation may have completed, but secretctl lost confirmation from the browser. No further credential operation will run until the session is re-established.")
                .font(.system(size: 11))
                .fixedSize(horizontal: false, vertical: true)
            Button("View details", action: onDetails)
                .buttonStyle(.link)
                .font(.system(size: 11))
        }
    }
}

/// The operation finished, but its audit record did not.
///
/// Distinct from Outcome uncertain: there, secretctl does not know whether the
/// credential was used. Here it knows that it was, and cannot prove it
/// afterwards — which matters for anyone who has to reconstruct what happened.
struct EvidenceLostNotice: View {
    let onDetails: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Completed — evidence lost", systemImage: "exclamationmark.triangle.fill")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.orange)
            Text("The credential operation finished, but secretctl could not record proof of it. The action did happen — do not retry it on the assumption that it did not.")
                .font(.system(size: 11))
                .fixedSize(horizontal: false, vertical: true)
            Button("View details", action: onDetails)
                .buttonStyle(LinkPressStyle())
                .font(.system(size: 11))
        }
    }
}

struct DisconnectedNotice: View {
    let failure: ErrorPresentation?
    let connecting: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(connecting ? "Connecting to secretctld" : "secretctld is not reachable",
                  systemImage: connecting ? "ellipsis.circle" : "shield.slash")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(connecting ? Color.secondary : Color.red)
            if let failure {
                Text(failure.headline)
                    .font(.system(size: 11))
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !connecting {
                Text("No credential operation can run while the daemon is unreachable.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// One activity row. `compact` is the popover's four-line form.
struct ActivityRow: View {
    let event: ActivityEvent
    var compact = false

    private var symbol: String {
        switch event.outcome {
        case .success: return "checkmark.circle.fill"
        case .denied: return "xmark.circle.fill"
        case .pending: return "clock.fill"
        case .interrupted: return "exclamationmark.triangle.fill"
        case .info: return "info.circle"
        }
    }

    private var tint: Color {
        switch event.outcome {
        case .success: return .green
        case .denied: return .red
        case .pending: return .secondary
        case .interrupted: return .orange
        case .info: return .secondary
        }
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: symbol)
                .font(.system(size: 10))
                .foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 1) {
                Text(event.summary)
                    .font(.system(size: compact ? 12 : 13))
                    .lineLimit(compact ? 1 : 2)
                if !compact {
                    HStack(spacing: 6) {
                        if let actor = event.actorName {
                            Text(actor).font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        if let origin = event.origin {
                            Text(OriginDisplay.host(origin)).font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Spacer(minLength: 4)
            Text(RelativeTime.short(event.createdAt))
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(spokenLabel)
    }

    private var spokenLabel: String {
        var parts = [event.summary]
        if let actor = event.actorName { parts.append("by \(actor)") }
        if let origin = event.origin { parts.append("at \(OriginDisplay.host(origin))") }
        parts.append(RelativeTime.spoken(event.createdAt))
        return parts.joined(separator: ", ")
    }
}
