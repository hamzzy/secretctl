import SwiftUI
import SecretctlKit

enum ManageTab: String, CaseIterable, Identifiable {
    case activity, agents, grants, credentials, browsers, settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .activity: return "Activity"
        case .agents: return "Agents"
        case .grants: return "Authorizations"
        case .credentials: return "Credentials"
        case .browsers: return "Browsers"
        case .settings: return "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .activity: return "list.bullet.rectangle"
        case .agents: return "cpu"
        case .grants: return "key.horizontal"
        case .credentials: return "person.badge.key"
        case .browsers: return "macwindow"
        case .settings: return "gearshape"
        }
    }
}

/// The larger management window.
///
/// Everything here is read-mostly. The three things it can change — revoke an
/// authorization, disable an agent, adjust a local preference — are all either
/// a daemon call or a purely local display choice. No policy is expressed here.
struct ManageWindow: View {
    @EnvironmentObject private var store: BrokerStore
    @EnvironmentObject private var settings: AppSettings

    @State private var selection: ManageTab

    init(initialTab: ManageTab = .activity) {
        _selection = State(initialValue: initialTab)
    }

    var body: some View {
        NavigationSplitView {
            List(ManageTab.allCases, selection: $selection) { tab in
                Label(tab.title, systemImage: tab.symbol).tag(tab)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 180, max: 220)
        } detail: {
            Group {
                switch selection {
                case .activity: ActivityPane()
                case .agents: AgentsPane()
                case .grants: GrantsPane()
                case .credentials: CredentialsPane()
                case .browsers: BrowsersPane()
                case .settings: SettingsPane()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(minWidth: 780, minHeight: 520)
        .navigationTitle("secretctl")
    }
}

/// A pane that loads from the daemon, with a uniform loading/empty/error shape.
private struct LoadingPane<Item, Content: View>: View {
    let title: String
    let subtitle: String?
    let load: () async throws -> [Item]
    let emptyMessage: String
    @ViewBuilder let content: ([Item]) -> Content

    @State private var items: [Item] = []
    @State private var failure: ErrorPresentation?
    @State private var hasLoaded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 18, weight: .semibold))
                if let subtitle {
                    Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }
            .padding(20)

            Divider()

            if let failure {
                VStack(alignment: .leading, spacing: 6) {
                    Label(failure.headline, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    if let detail = failure.detail {
                        Text(detail).font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    Button("Try again") { Task { await reload() } }
                }
                .padding(20)
            } else if !hasLoaded {
                ProgressView().controlSize(.small).padding(20)
            } else if items.isEmpty {
                Text(emptyMessage)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .padding(20)
            } else {
                content(items)
            }
            Spacer(minLength: 0)
        }
        .task { await reload() }
    }

    private func reload() async {
        do {
            items = try await load()
            failure = nil
        } catch {
            failure = ErrorPresentation.describe(error)
        }
        hasLoaded = true
    }
}

// MARK: - Activity

struct ActivityPane: View {
    @EnvironmentObject private var store: BrokerStore
    @State private var showTechnical = false

    var body: some View {
        LoadingPane(
            title: "Activity",
            subtitle: "Every request, decision and credential operation, in the order the broker recorded them.",
            load: { try await store.activity(limit: 200) },
            emptyMessage: "No activity recorded yet."
        ) { events in
            VStack(alignment: .leading, spacing: 0) {
                Toggle("Show technical details", isOn: $showTechnical)
                    .font(.system(size: 11))
                    .padding(.horizontal, 20)
                    .padding(.vertical, 8)

                List(events) { event in
                    VStack(alignment: .leading, spacing: 2) {
                        ActivityRow(event: event)
                        if showTechnical {
                            HStack(spacing: 8) {
                                Text("#\(event.sequence)")
                                Text(event.eventType)
                                if let code = event.errorCode { Text(code) }
                            }
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                        }
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(.inset)
            }
        }
    }
}

// MARK: - Agents

struct AgentsPane: View {
    @EnvironmentObject private var store: BrokerStore
    @State private var confirmingDisable: Agent?

    var body: some View {
        LoadingPane(
            title: "Agents",
            subtitle: "Agents are security principals. Disabling one stops it enrolling new work immediately.",
            load: { try await store.agents() },
            emptyMessage: "No agents are enrolled yet."
        ) { agents in
            List(agents) { agent in
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(agent.displayName).font(.system(size: 13, weight: .medium))
                            Text(agent.state)
                                .font(.system(size: 10, weight: .medium))
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Color.secondary.opacity(0.15), in: Capsule())
                        }
                        Text("\(agent.activeGrants) standing \(agent.activeGrants == 1 ? "authorization" : "authorizations") · \(agent.recentEventCount) recent events")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                        Text(agent.lastActivityAt.map { "Last activity \(RelativeTime.spoken($0))" } ?? "No activity yet")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                        Text("Enrolled \(RelativeTime.full(agent.createdAt))")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 6) {
                        Button("Disable") { confirmingDisable = agent }
                            .disabled(agent.state.lowercased() == "disabled")
                        Button("Revoke all authorizations") {
                            Task { try? await store.revokeGrant(selector: "agent:\(agent.displayName)") }
                        }
                        .font(.system(size: 11))
                    }
                }
                .padding(.vertical, 4)
            }
            .listStyle(.inset)
            .confirmationDialog(
                "Disable \(confirmingDisable?.displayName ?? "this agent")?",
                isPresented: .init(get: { confirmingDisable != nil }, set: { if !$0 { confirmingDisable = nil } })
            ) {
                Button("Disable agent", role: .destructive) {
                    if let agent = confirmingDisable {
                        Task { try? await store.disableAgent(id: agent.agentID) }
                    }
                    confirmingDisable = nil
                }
                Button("Cancel", role: .cancel) { confirmingDisable = nil }
            } message: {
                Text("It will no longer be able to request credential operations.")
            }
        }
    }
}

// MARK: - Grants

struct GrantsPane: View {
    @EnvironmentObject private var store: BrokerStore
    @State private var includeRevoked = false
    @State private var confirmingRevoke: Grant?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            LoadingPane(
                title: "Standing authorizations",
                subtitle: "Each one is bound to an exact origin, a single action and an expiry. Revoking takes effect immediately.",
                load: { try await store.grants(includeRevoked: includeRevoked) },
                emptyMessage: "No standing authorizations."
            ) { grants in
                List(grants) { grant in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 6) {
                                Text(grant.credentialName).font(.system(size: 13, weight: .medium))
                                if !grant.active {
                                    Text(grant.revokedAt == nil ? "expired" : "revoked")
                                        .font(.system(size: 10, weight: .medium))
                                        .padding(.horizontal, 5).padding(.vertical, 1)
                                        .background(Color.secondary.opacity(0.15), in: Capsule())
                                }
                            }
                            Text("\(grant.agentName) → \(grant.origin)")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.secondary)
                            HStack(spacing: 10) {
                                Text(grant.actionLabel)
                                RiskBadge(risk: grant.riskCeiling)
                                if grant.requirePresence {
                                    Label("presence required", systemImage: "touchid").font(.system(size: 11))
                                }
                            }
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            Text("Expires \(RelativeTime.full(grant.expiresAt)) · used \(grant.useCount) \(grant.useCount == 1 ? "time" : "times")")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                            if let reason = grant.revokedReason {
                                Text("Revoked: \(reason)").font(.system(size: 11)).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        if grant.active {
                            Button("Revoke") { confirmingRevoke = grant }
                        }
                    }
                    .padding(.vertical, 4)
                }
                .listStyle(.inset)
                .confirmationDialog(
                    "Revoke this authorization?",
                    isPresented: .init(get: { confirmingRevoke != nil }, set: { if !$0 { confirmingRevoke = nil } })
                ) {
                    Button("Revoke", role: .destructive) {
                        if let grant = confirmingRevoke {
                            Task { try? await store.revokeGrant(selector: grant.grantID) }
                        }
                        confirmingRevoke = nil
                    }
                    Button("Cancel", role: .cancel) { confirmingRevoke = nil }
                } message: {
                    Text("The agent will have to ask you again next time.")
                }
            }
            .id(includeRevoked)

            Divider()
            Toggle("Include revoked and expired", isOn: $includeRevoked)
                .font(.system(size: 11))
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
        }
    }
}

// MARK: - Credentials

struct CredentialsPane: View {
    @EnvironmentObject private var store: BrokerStore

    var body: some View {
        LoadingPane(
            title: "Credentials",
            subtitle: "References only. secretctl never displays, copies or exports a secret — the value stays with the provider.",
            load: { try await store.credentials() },
            emptyMessage: "No credentials are enrolled yet."
        ) { credentials in
            List(credentials) { credential in
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(credential.name).font(.system(size: 13, weight: .medium))
                        Text(credential.kind)
                            .font(.system(size: 10))
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.secondary.opacity(0.15), in: Capsule())
                        if credential.disabled {
                            Text("disabled").font(.system(size: 10)).foregroundStyle(.red)
                        }
                    }
                    Text("Provider: \(credential.provider)").font(.system(size: 11)).foregroundStyle(.secondary)
                    if !credential.approvedOrigins.isEmpty {
                        Text("Approved destinations: \(credential.approvedOrigins.joined(separator: ", "))")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    Text(credential.usedBy.isEmpty ? "Not used by any agent yet" : "Used by \(credential.usedBy.joined(separator: ", "))")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                    if let lastUsed = credential.lastUsedAt {
                        Text("Last used \(RelativeTime.spoken(lastUsed))")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)
            }
            .listStyle(.inset)
        }
    }
}

// MARK: - Browser sessions

struct BrowsersPane: View {
    @EnvironmentObject private var store: BrokerStore

    var body: some View {
        LoadingPane(
            title: "Managed browsers",
            subtitle: "Credential operations only ever run inside a managed session that the broker can verify.",
            load: { try await store.browserSessions() },
            emptyMessage: "No managed browser session is connected."
        ) { sessions in
            VStack(alignment: .leading, spacing: 0) {
                if sessions.filter({ $0.state.lowercased() == "active" }).count > 1 {
                    // Choosing silently between sessions would let an operation
                    // land in a window the user did not have in mind.
                    Label(
                        "More than one managed session is connected. Agents must name the session they mean; secretctl will not choose one for them.",
                        systemImage: "info.circle"
                    )
                    .font(.system(size: 11))
                    .padding(.horizontal, 20)
                    .padding(.vertical, 8)
                }

                List(sessions) { session in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(session.profile).font(.system(size: 13, weight: .medium))
                            Text(session.state)
                                .font(.system(size: 10, weight: .medium))
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Color.secondary.opacity(0.15), in: Capsule())
                        }
                        Text("Assurance: \(session.assurance) · \(session.activeTabCount) \(session.activeTabCount == 1 ? "tab" : "tabs")")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                        if !session.currentOrigins.isEmpty {
                            Text(session.currentOrigins.joined(separator: ", "))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                        Text("Last heartbeat \(RelativeTime.spoken(session.lastHeartbeatAt))")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
                .listStyle(.inset)
            }
        }
    }
}
