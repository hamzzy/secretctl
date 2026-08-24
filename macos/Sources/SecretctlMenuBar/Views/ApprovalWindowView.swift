import SwiftUI
import SecretctlKit

/// Wraps the approval prompt so it can be closed rather than refreshed.
///
/// §14.3.3: if any bound context element changes, the prompt is invalidated,
/// visibly closed with the reason shown, and the request fails. A prompt whose
/// contents silently mutate under the cursor is forbidden — someone reading a
/// request for `github-work` must never find that the same window is now
/// authorizing `aws-root`, least of all in the instant before they click.
///
/// So this view never re-binds to a different request. It watches for its own
/// approval leaving the daemon's pending set and, when that happens for any
/// reason other than the decision the user just made, replaces the prompt with
/// an explanation.
struct ApprovalWindowView: View {
    @EnvironmentObject private var store: BrokerStore
    @EnvironmentObject private var settings: AppSettings

    let request: AuthorizationRequest
    let onFinished: () -> Void

    /// Set the moment the user's decision is accepted, so the disappearance
    /// that follows is not mistaken for an invalidation.
    @State private var didDecide = false
    @State private var isInvalidated = false

    var body: some View {
        Group {
            if isInvalidated {
                InvalidatedNotice(request: request, onDismiss: onFinished)
            } else {
                ApprovalView(request: request) {
                    didDecide = true
                    onFinished()
                }
            }
        }
        .onChange(of: store.pending) { _, pending in
            guard !didDecide, !isInvalidated else { return }
            // Absence is the signal. The daemon removes an approval when it is
            // decided, expires, or its bound page context moves — and from
            // here those are indistinguishable, which is fine: all three mean
            // this window must stop offering to authorize anything.
            if store.hasConnectedOnce, !pending.contains(where: { $0.approvalID == request.approvalID }) {
                isInvalidated = true
            }
        }
    }
}

/// What replaces the prompt when its request stops being valid.
private struct InvalidatedNotice: View {
    let request: AuthorizationRequest
    let onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                Label("This request is no longer valid", systemImage: "xmark.shield.fill")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.orange)

                Text("secretctl closed it rather than changing what it was asking you to approve.")
                    .font(.system(size: 12))
                    .fixedSize(horizontal: false, vertical: true)

                Text("The page moved on, the request expired, or it was answered somewhere else. No credential was released. The agent will need to ask again.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Divider().padding(.vertical, 2)

                VStack(alignment: .leading, spacing: 8) {
                    SectionHeading(title: "What it had asked for")
                    VerifiedField(label: "Agent", value: request.agentName)
                    VerifiedField(label: "Credential", value: request.credentialName)
                    VerifiedField(label: "Destination", value: request.origin, monospaced: true)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            Divider()

            HStack {
                Spacer()
                Button("Dismiss", action: onDismiss)
                    .keyboardShortcut(.cancelAction)
            }
            .padding(20)
        }
        .frame(width: 460)
        .accessibilityElement(children: .contain)
    }
}
