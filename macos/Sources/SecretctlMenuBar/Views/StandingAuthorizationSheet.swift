import SwiftUI
import SecretctlKit

/// Creating a standing authorization.
///
/// Separate from "Authorize once" on purpose. The scope is shown in full and is
/// not editable here: it comes from the approval the daemon has just verified
/// against a live page, and `grant.create` takes the approval id rather than a
/// free-form tuple precisely so that the UI cannot widen it. Everything below
/// is a restatement of what the daemon will bind, plus the one dimension the
/// user genuinely chooses — how long it lasts.
struct StandingAuthorizationSheet: View {
    @EnvironmentObject private var store: BrokerStore
    @EnvironmentObject private var settings: AppSettings

    let request: AuthorizationRequest
    let onFinish: (Bool) -> Void

    @State private var ttlDays = 30
    @State private var isWorking = false
    @State private var failure: ErrorPresentation?
    @State private var presenceNotice: String?
    @State private var hasSettled = false

    private let ttlChoices = [1, 7, 30, 90]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Create standing authorization")
                .font(.system(size: 15, weight: .semibold))
                .padding(20)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    scope
                    expiry
                    conditions
                    if let failure { failureNotice(failure) }
                    if let presenceNotice {
                        Text(presenceNotice)
                            .font(.system(size: 11))
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
                    }
                }
                .padding(20)
            }

            Divider()

            HStack {
                Button("Cancel") { onFinish(false) }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if isWorking { ProgressView().controlSize(.small) }
                // This approves the pending request as well as minting the
                // grant, so it is an affirmative action and gets the same
                // treatment as the one on the prompt: no keyboard shortcut,
                // and inert until the sheet has settled.
                Button("Create authorization") { Task { await create() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(!hasSettled)
            }
            .disabled(isWorking)
            .padding(20)
        }
        .frame(width: 440)
        .frame(minHeight: 460)
        .task {
            try? await Task.sleep(for: ApprovalChrome.settleInterval)
            hasSettled = true
        }
    }

    private var scope: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeading(title: "Scope")
            VerifiedField(label: "Agent", value: request.agentName)
            VerifiedField(label: "Credential", value: request.credentialName)
            VerifiedField(label: "Destination", value: request.origin, monospaced: true)
            VerifiedField(label: "Action", value: request.actionLabel)
            if !request.flowSteps.isEmpty {
                VerifiedField(
                    label: "Authentication",
                    value: request.flowSteps.map(\.label).joined(separator: " + ")
                )
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("Risk ceiling").font(.system(size: 11)).foregroundStyle(.secondary)
                RiskBadge(risk: request.risk)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 8))
    }

    private var expiry: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionHeading(title: "Expires")
            Picker("Expires", selection: $ttlDays) {
                ForEach(ttlChoices, id: \.self) { days in
                    Text(Plural.counted(days, one: "day", other: "days")).tag(days)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityLabel("Authorization lifetime in days")

            Text("Ends \(RelativeTime.full(Date().addingTimeInterval(Double(ttlDays) * 86400))). You can revoke it sooner from Activity.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
    }

    private var conditions: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionHeading(title: "Conditions")
            ConfirmationRow(text: "Exact origin required — \(request.origin) only")
            ConfirmationRow(text: "Managed browser session required")
            ConfirmationRow(
                text: request.requiresPresence
                    ? "You will still confirm with \(Presence.presenceLabel) each time"
                    : "High-risk operations still require your presence"
            )
            ConfirmationRow(text: "Every use is recorded in the audit log")
        }
    }

    private func failureNotice(_ failure: ErrorPresentation) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(failure.headline)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
            if let detail = failure.detail {
                Text(detail).font(.system(size: 11)).fixedSize(horizontal: false, vertical: true)
            }
            if let technical = failure.technicalDetail {
                Text(technical)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
    }

    private func create() async {
        isWorking = true
        defer { isWorking = false }
        failure = nil
        presenceNotice = nil

        var presenceVerified = false
        if request.requiresPresence || (settings.requirePresenceForHighRisk && request.risk >= .high) {
            switch await Presence.verify(
                reason: "create a standing authorization for \(request.agentName) at \(OriginDisplay.host(request.origin))"
            ) {
            case .verified:
                presenceVerified = true
            case .cancelled:
                presenceNotice = "Verification was cancelled. No authorization was created."
                return
            case .unavailable(let detail):
                if request.requiresPresence {
                    presenceNotice = "This request requires user presence, but this Mac cannot verify it: \(detail)"
                    return
                }
            case .failed(let detail):
                presenceNotice = "Verification did not succeed: \(detail). No authorization was created."
                return
            }
        }

        do {
            let result = try await store.createStandingAuthorization(
                for: request, ttlDays: ttlDays, presenceVerified: presenceVerified
            )
            // `grant.create` approves the pending request in the same call, so
            // the same rule applies: a successful call can still carry a
            // refusal.
            guard result.decision.isApproved else {
                failure = ErrorPresentation.describe(refused: result.decision)
                return
            }
            onFinish(true)
        } catch {
            failure = ErrorPresentation.describe(error)
        }
    }
}
