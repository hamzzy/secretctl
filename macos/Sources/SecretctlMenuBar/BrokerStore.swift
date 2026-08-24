import Combine
import Foundation
import SecretctlKit

/// The single source of truth for everything the UI displays.
///
/// The daemon has no push channel, so this polls — quickly while an operation
/// is in flight, lazily when idle. Two rules hold everywhere below:
///
/// 1. State is never inferred locally. After the user approves something the
///    store does not mark anything successful; it re-reads and shows whatever
///    the daemon now reports. A local guess would be a security fiction.
/// 2. An unreachable daemon reports `.disconnected`, never the last good
///    status. A stale "Protected" during an outage is precisely the wrong
///    answer.
@MainActor
final class BrokerStore: ObservableObject {
    @Published private(set) var status: SystemStatus = .disconnected
    @Published private(set) var pending: [AuthorizationRequest] = []
    @Published private(set) var recentActivity: [ActivityEvent] = []
    @Published private(set) var lastFailure: ErrorPresentation?
    /// True once a first successful poll has happened, so the popover can
    /// distinguish "starting up" from "genuinely disconnected".
    @Published private(set) var hasConnectedOnce = false

    var protection: ProtectionState { status.protection }
    var activeOperation: ActiveOperation? { status.activeOperation }

    private let api = BrokerAPI()
    private var pollTask: Task<Void, Never>?

    /// Fast enough that the progress list tracks the executor closely.
    private static let activeInterval: Duration = .milliseconds(400)
    /// Slow enough to stay invisible in battery and CPU terms.
    private static let idleInterval: Duration = .milliseconds(1500)
    /// Recent activity is a SQLite query on the daemon side and almost nothing
    /// changes between ticks, so it is read on its own slower cadence rather
    /// than on every poll. A state change or an in-flight operation overrides
    /// this — those are exactly when the list does change.
    private static let activityInterval: TimeInterval = 6

    private var lastActivityFetch: Date = .distantPast

    /// Called with each newly seen pending request, and with each protection
    /// state transition, so the app can raise notifications without the
    /// notification layer needing its own polling loop.
    var onNewRequest: ((AuthorizationRequest) -> Void)?
    var onStateChange: ((ProtectionState, ProtectionState) -> Void)?

    func start() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            var announced = Set<String>()
            var previous: ProtectionState?
            while !Task.isCancelled {
                guard let self else { return }
                await self.refresh(announced: &announced, previous: &previous)
                try? await Task.sleep(for: self.status.activeOperation == nil
                    ? Self.idleInterval
                    : Self.activeInterval)
            }
        }
    }

    func stop() {
        pollTask?.cancel()
        pollTask = nil
        Task { await api.disconnect() }
    }

    private func refresh(announced: inout Set<String>, previous: inout ProtectionState?) async {
        do {
            let status = try await api.status()
            let pending = try await api.pending()

            let stateChanged = previous != nil && previous != status.protection
            if stateChanged
                || status.activeOperation != nil
                || Date().timeIntervalSince(lastActivityFetch) >= Self.activityInterval {
                self.recentActivity = try await api.activity(limit: 20)
                lastActivityFetch = Date()
            }

            self.status = status
            self.pending = pending
            self.lastFailure = nil
            if !hasConnectedOnce { Diagnostics.connected() }
            self.hasConnectedOnce = true

            if let previous, previous != status.protection {
                Diagnostics.protectionChanged(from: previous.rawValue, to: status.protection.rawValue)
                onStateChange?(previous, status.protection)
            }
            previous = status.protection

            for request in pending where !announced.contains(request.approvalID) {
                announced.insert(request.approvalID)
                onNewRequest?(request)
            }
            // Drop ids that are no longer pending, so a later request from the
            // same agent notifies again.
            let live = Set(pending.map(\.approvalID))
            announced.formIntersection(live)
        } catch {
            self.status = .disconnected
            self.pending = []
            self.lastFailure = ErrorPresentation.describe(error)
            if previous != .disconnected { Diagnostics.connectionFailed(error) }
            if let previous, previous != .disconnected {
                Diagnostics.protectionChanged(from: previous.rawValue, to: ProtectionState.disconnected.rawValue)
                onStateChange?(previous, .disconnected)
            }
            previous = .disconnected
        }
    }

    /// Force an immediate re-read, e.g. right after a decision.
    func refreshNow() async {
        var announced = Set(pending.map(\.approvalID))
        var previous: ProtectionState? = status.protection
        await refresh(announced: &announced, previous: &previous)
    }

    // MARK: - Actions
    //
    // Each of these is a thin pass-through to the daemon. None of them mutates
    // local state on success: the next poll reports what actually happened.

    /// Returns what the daemon actually decided. A call that succeeds is not
    /// the same as an approval that was accepted.
    @discardableResult
    func approve(_ request: AuthorizationRequest, presenceVerified: Bool) async throws -> DecisionOutcome {
        do {
            let outcome = try await api.approve(request, presenceVerified: presenceVerified)
            Diagnostics.decided(
                action: "approve", outcome: outcome.state, resultCode: outcome.resultCode,
                agent: request.agentName, origin: request.origin
            )
            await refreshNow()
            return outcome
        } catch {
            Diagnostics.decisionFailed(action: "approve", error: error)
            throw error
        }
    }

    @discardableResult
    func deny(_ request: AuthorizationRequest) async throws -> DecisionOutcome {
        do {
            let outcome = try await api.deny(request)
            Diagnostics.decided(
                action: "deny", outcome: outcome.state, resultCode: outcome.resultCode,
                agent: request.agentName, origin: request.origin
            )
            await refreshNow()
            return outcome
        } catch {
            Diagnostics.decisionFailed(action: "deny", error: error)
            throw error
        }
    }

    func createStandingAuthorization(
        for request: AuthorizationRequest,
        ttlDays: Int,
        presenceVerified: Bool
    ) async throws -> GrantCreateResult {
        do {
            let result = try await api.createStandingAuthorization(
                for: request, ttlDays: ttlDays, presenceVerified: presenceVerified
            )
            Diagnostics.decided(
                action: "grant.create", outcome: result.decision.state,
                resultCode: result.decision.resultCode,
                agent: request.agentName, origin: request.origin
            )
            await refreshNow()
            return result
        } catch {
            Diagnostics.decisionFailed(action: "grant.create", error: error)
            throw error
        }
    }

    func grants(includeRevoked: Bool = false) async throws -> [Grant] {
        try await api.grants(includeRevoked: includeRevoked)
    }

    func revokeGrant(selector: String) async throws {
        _ = try await api.revokeGrant(selector: selector)
        await refreshNow()
    }

    func agents() async throws -> [Agent] { try await api.agents() }

    func disableAgent(id: String) async throws {
        try await api.disableAgent(id: id)
        await refreshNow()
    }

    func credentials() async throws -> [CredentialReference] { try await api.credentials() }
    func browserSessions() async throws -> [BrowserSession] { try await api.browserSessions() }
    func activity(limit: Int) async throws -> [ActivityEvent] { try await api.activity(limit: limit) }
}
