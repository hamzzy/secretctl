import SwiftUI
import SecretctlKit

/// First run.
///
/// Three short steps that state the promise, then confirm the two things that
/// must actually be true for the promise to hold: a provider is connected, and
/// a managed browser is available. Both are read from the daemon rather than
/// asserted, so onboarding cannot end with a green tick that means nothing.
struct OnboardingView: View {
    @EnvironmentObject private var store: BrokerStore
    @EnvironmentObject private var settings: AppSettings

    let onFinish: () -> Void

    @State private var step = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            content
                .padding(28)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            Divider()

            HStack {
                if step > 0 {
                    Button("Back") { step -= 1 }
                }
                Spacer()
                Button(step == 2 ? "Done" : "Continue") {
                    if step == 2 { onFinish() } else { step += 1 }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            }
            .padding(20)
        }
        .frame(width: 520, height: 420)
    }

    @ViewBuilder
    private var content: some View {
        switch step {
        case 0: welcome
        case 1: providerStep
        default: browserStep
        }
    }

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 16) {
            BrandMark(size: 46)
            Text("Give agents access to accounts\nwithout giving them passwords.")
                .font(.system(size: 22, weight: .semibold))
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 8) {
                ConfirmationRow(text: "Credentials stay with the provider")
                ConfirmationRow(text: "Agents receive no secrets")
                ConfirmationRow(text: "Browser actions are isolated")
                ConfirmationRow(text: "Authorizations are audited")
            }
        }
    }

    private var providerStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Credential provider").font(.system(size: 20, weight: .semibold))
            if store.protection == .disconnected {
                statusCard(
                    ok: false,
                    title: "secretctld is not reachable",
                    detail: "Start the daemon, then come back. Run `secretctl init` first if you have not set up an installation."
                )
            } else if store.status.providers.isEmpty {
                statusCard(
                    ok: false,
                    title: "No provider enrolled yet",
                    detail: "Add a credential with the secretctl CLI. Its value stays in the provider — secretctl only stores a reference."
                )
            } else {
                statusCard(
                    ok: true,
                    title: store.status.providers.joined(separator: ", "),
                    detail: "Connected. secretctl reads credentials from here only when you authorize an operation."
                )
            }
        }
    }

    private var browserStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Browser").font(.system(size: 20, weight: .semibold))
            if store.status.browserSessionsConnected > 0 {
                statusCard(
                    ok: true,
                    title: "\(store.status.browserSessionsConnected) managed \(store.status.browserSessionsConnected == 1 ? "session" : "sessions") connected",
                    detail: "Credential operations will run inside a session the broker can verify."
                )
            } else {
                statusCard(
                    ok: false,
                    title: "No managed browser connected",
                    detail: "Launch a managed browser with the secretctl CLI and install the Chrome extension. secretctl will refuse credential operations until one is available."
                )
            }

            Text("secretctl stays in the menu bar. It will ask you whenever an agent needs permission.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func statusCard(ok: Bool, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                .font(.system(size: 16))
                .foregroundStyle(ok ? Color.green : Color.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 13, weight: .medium))
                Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
    }
}
