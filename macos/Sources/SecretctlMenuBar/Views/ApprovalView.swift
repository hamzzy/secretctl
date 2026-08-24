import SwiftUI
import SecretctlKit

/// The trusted approval surface.
///
/// Everything above "Why" is broker-verified: measured from the live page,
/// resolved from the credential store, or decided by the policy evaluator. The
/// agent's own words appear once, below, clearly attributed. That separation is
/// the whole point of this window — an agent that could write text which reads
/// like system chrome could talk a person into an approval.
///
/// The window decides nothing. `Authorize once` calls `approval.decide`, and
/// the daemon independently re-validates the request, the echoed context digest
/// and the presence claim before anything is released.
struct ApprovalView: View {
    @EnvironmentObject private var store: BrokerStore
    @EnvironmentObject private var settings: AppSettings

    let request: AuthorizationRequest
    let onFinished: () -> Void

    @State private var isWorking = false
    @State private var failure: ErrorPresentation?
    @State private var showTechnicalDetail = false
    @State private var showStandingSheet = false
    @State private var presenceNotice: String?
    @State private var now = Date()

    private let clock = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headline
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if request.isFirstForAgent { firstTimeNotice }
                    verifiedSection
                    if let reason = request.reason, !reason.isEmpty { whySection(reason) }
                    securityNote
                    if let failure {
                        failureNotice(failure).transition(Motion.contentSwap)
                    }
                    if let presenceNotice {
                        noticeBox(presenceNotice).transition(Motion.contentSwap)
                    }
                }
                .padding(20)
                .animation(Motion.enter(), value: failure)
                .animation(Motion.enter(), value: presenceNotice)
            }
            Divider()
            actions
        }
        .frame(width: 460)
        .frame(minHeight: 480)
        .onReceive(clock) { now = $0 }
        .sheet(isPresented: $showStandingSheet) {
            StandingAuthorizationSheet(request: request) { granted in
                showStandingSheet = false
                if granted { onFinished() }
            }
            .environmentObject(store)
            .environmentObject(settings)
        }
    }

    // MARK: - Sections

    private var headline: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Authorization requested")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
                .kerning(0.5)
            Text("\(request.agentName) wants to \(request.actionLabel.lowercased()) at \(OriginDisplay.host(request.origin))")
                .font(.system(size: 17, weight: .semibold))
                .fixedSize(horizontal: false, vertical: true)
            Text(expiryText)
                .font(.system(size: 11))
                .foregroundStyle(isExpiringSoon ? Color.orange : Color.secondary)
                .monospacedDigit()
                .contentTransition(.numericText(countsDown: true))
                .animation(Motion.move(0.2), value: expiryText)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    private var firstTimeNotice: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "sparkles").font(.system(size: 12))
            Text("This is the first time \(request.agentName) has asked for this. Check the destination below before you authorize.")
                .font(.system(size: 12))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
    }

    private var verifiedSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 5) {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 10))
                    .foregroundStyle(Color.accentColor)
                SectionHeading(title: "Verified by secretctl")
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("The following facts were verified by secretctl")

            LazyVGrid(columns: [GridItem(.flexible(), alignment: .topLeading),
                                GridItem(.flexible(), alignment: .topLeading)], spacing: 12) {
                VerifiedField(label: "Agent", value: request.agentName)
                VerifiedField(label: "Credential", value: request.credentialName)
            }

            VerifiedField(label: "Destination", value: request.origin, monospaced: true)

            LazyVGrid(columns: [GridItem(.flexible(), alignment: .topLeading),
                                GridItem(.flexible(), alignment: .topLeading)], spacing: 12) {
                VerifiedField(label: "Action", value: request.actionLabel)
                VerifiedField(label: "Provider", value: request.provider)
            }

            if !request.flowSteps.isEmpty {
                VerifiedField(label: "Authentication", value: flowDescription)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text("Risk").font(.system(size: 11)).foregroundStyle(.secondary)
                RiskBadge(risk: request.risk)
            }

            if request.requiresPresence {
                ConfirmationRow(text: "You will be asked to confirm with \(Presence.presenceLabel)")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Color.accentColor.opacity(0.25), lineWidth: 1)
        )
    }

    private var flowDescription: String {
        request.flowSteps
            .map { $0.optional ? "\($0.label) (if asked)" : $0.label }
            .joined(separator: " + ")
    }

    private func whySection(_ reason: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeading(title: "Why")
            AgentProvidedText(agentName: request.agentName, text: reason)
        }
    }

    private var securityNote: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "lock.shield")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            Text("Credentials never enter the agent. secretctl releases them only to the managed browser, for this destination, once.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func failureNotice(_ failure: ErrorPresentation) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(failure.headline, systemImage: "exclamationmark.triangle.fill")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
            if let detail = failure.detail {
                Text(detail).font(.system(size: 11)).fixedSize(horizontal: false, vertical: true)
            }
            if let technical = failure.technicalDetail {
                DisclosureGroup("Technical details", isExpanded: $showTechnicalDetail) {
                    Text(technical)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.system(size: 11))
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
    }

    private func noticeBox(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11))
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
            .fixedSize(horizontal: false, vertical: true)
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Button("Deny") { Task { await deny() } }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if isWorking { ProgressView().controlSize(.small) }
                // Deliberately not "Always allow": a standing authorization is
                // a separate, explicitly scoped flow below.
                Button("Authorize once") { Task { await approve() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
            .disabled(isWorking)

            if request.grantable {
                Button("Create standing authorization…") { showStandingSheet = true }
                    .buttonStyle(LinkPressStyle())
                    .font(.system(size: 11))
                    .disabled(isWorking)
            } else {
                Text("This request is too sensitive for a standing authorization.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(20)
    }

    /// Under half a minute the countdown stops being background information.
    private var isExpiringSoon: Bool {
        let remaining = request.expiresAt.timeIntervalSince(now)
        return remaining > 0 && remaining <= 30
    }

    private var expiryText: String {
        let remaining = request.expiresAt.timeIntervalSince(now)
        if remaining <= 0 { return "This request has expired." }
        let minutes = Int(remaining) / 60
        let seconds = Int(remaining) % 60
        return String(format: "Expires in %d:%02d", minutes, seconds)
    }

    // MARK: - Decisions

    private func approve() async {
        isWorking = true
        defer { isWorking = false }
        failure = nil
        presenceNotice = nil

        guard let presenceVerified = await resolvePresence() else { return }

        do {
            let outcome = try await store.approve(request, presenceVerified: presenceVerified)
            // The call succeeding is not the decision succeeding: the broker
            // re-validates and can refuse. Closing the window here would tell
            // the user their credential was released when it was not.
            guard outcome.isApproved else {
                failure = ErrorPresentation.describe(refused: outcome)
                return
            }
            onFinished()
        } catch {
            failure = ErrorPresentation.describe(error)
        }
    }

    private func deny() async {
        isWorking = true
        defer { isWorking = false }
        do {
            try await store.deny(request)
            onFinished()
        } catch {
            failure = ErrorPresentation.describe(error)
        }
    }

    /// Returns the presence claim to send, or nil if the user backed out.
    ///
    /// `true` is only ever returned after an actual successful evaluation. The
    /// local "require presence for high-risk actions" setting can add a check
    /// the daemon did not demand, but can never remove one it did.
    private func resolvePresence() async -> Bool? {
        let localPolicyDemands = settings.requirePresenceForHighRisk && request.risk >= .high
        guard request.requiresPresence || localPolicyDemands else { return false }

        let outcome = await Presence.verify(
            reason: "authorize \(request.agentName) to \(request.actionLabel.lowercased()) at \(OriginDisplay.host(request.origin))"
        )
        switch outcome {
        case .verified:
            return true
        case .cancelled:
            presenceNotice = "Verification was cancelled. Nothing was authorized."
            return nil
        case .unavailable(let detail):
            if request.requiresPresence {
                presenceNotice = "This request requires user presence, but this Mac cannot verify it: \(detail)"
                return nil
            }
            // Only a local preference asked for this, and the daemon did not.
            // Proceed, but report presence honestly as unverified.
            return false
        case .failed(let detail):
            presenceNotice = "Verification did not succeed: \(detail). Nothing was authorized."
            return nil
        }
    }
}
