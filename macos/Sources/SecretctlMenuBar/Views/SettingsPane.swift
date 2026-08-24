import SwiftUI
import SecretctlKit

/// Settings, deliberately small.
///
/// Nothing here is a security control. The daemon owns policy; these are local
/// display and convenience choices, plus a diagnostics view for support. The
/// one switch that sounds like policy — requiring presence for high-risk
/// actions — can only *add* a check on top of what the daemon already demands.
struct SettingsPane: View {
    @EnvironmentObject private var settings: AppSettings
    @EnvironmentObject private var store: BrokerStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Settings").font(.system(size: 18, weight: .semibold))
                    Text("secretctl runs in the menu bar. Policy lives in the daemon, not here.")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }

                group("General") {
                    Toggle("Launch at login", isOn: $settings.launchAtLogin)
                    if let failure = settings.launchAtLoginFailure {
                        Text("macOS refused to register the login item: \(failure)")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                    Toggle("Show notifications", isOn: $settings.notificationsEnabled)
                }

                group("Privacy") {
                    Picker("Notification content", selection: $settings.notificationDetail) {
                        ForEach(NotificationDetail.allCases) { detail in
                            Text(detail.label).tag(detail)
                        }
                    }
                    .pickerStyle(.radioGroup)
                    Text(settings.notificationDetail.explanation)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    Toggle("Hide secretctl windows from screen sharing and screenshots",
                           isOn: $settings.hideFromScreenCapture)
                    Text("The approval window names both the account and the destination. With this on, a shared screen or a recording shows that a decision is happening, not what it is about. Takes effect for windows opened from now on.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                group("Security") {
                    Toggle("Ask for \(Presence.presenceLabel) on high-risk actions", isOn: $settings.requirePresenceForHighRisk)
                    Text("secretctld may require your presence regardless of this setting. Turning it off never removes a check the daemon asked for.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if !Presence.isAvailable {
                        Label("This Mac cannot verify user presence.", systemImage: "exclamationmark.triangle")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    } else if Presence.isBiometryEnrolled {
                        Label("\(Presence.biometryLabel) is enrolled. secretctl asks for it first and falls back to your login password.",
                              systemImage: "touchid")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        Label("No fingerprint is enrolled on this Mac, so secretctl will ask for your login password. Enrol one in System Settings › Touch ID & Password.",
                              systemImage: "touchid")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                group("Diagnostics") {
                    diagnosticRow("Daemon", store.protection == .disconnected ? "Not reachable" : "Connected")
                    diagnosticRow("Installation", InstallationPaths.default.directory.path)
                    diagnosticRow("Admin socket", InstallationPaths.default.adminSocket.path)
                    diagnosticRow("Policy fingerprint", store.status.policyFingerprint)
                    diagnosticRow("Audit chain", store.status.auditChainIntact ? "Verified" : "Not verified")
                    diagnosticRow("Providers", store.status.providers.isEmpty ? "None enrolled" : store.status.providers.joined(separator: ", "))
                    diagnosticRow("Managed browsers", "\(store.status.browserSessionsConnected) connected")
                    diagnosticRow("User presence", presenceDiagnostic)

                    if !store.status.auditChainIntact && store.protection != .disconnected {
                        Label("The audit chain did not verify on the last check. Investigate before trusting recent activity.",
                              systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 11))
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: 560, alignment: .leading)
        }
    }

    @ViewBuilder
    private func group<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeading(title: title)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var presenceDiagnostic: String {
        guard Presence.isAvailable else { return "Unavailable" }
        return Presence.isBiometryEnrolled
            ? "\(Presence.biometryLabel), password fallback"
            : "Login password only"
    }

    private func diagnosticRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(label).font(.system(size: 11)).foregroundStyle(.secondary).frame(width: 140, alignment: .leading)
            Text(value)
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }
}
