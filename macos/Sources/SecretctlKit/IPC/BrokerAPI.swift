import Foundation

/// Typed façade over the admin RPC surface.
///
/// One method per existing daemon method — no new protocol, no client-side
/// composition of security decisions. In particular `approve` and
/// `createStandingAuthorization` echo the context digest the daemon handed out,
/// so the daemon can independently confirm the page has not navigated since the
/// human looked at it. The app cannot mark anything approved on its own.
public struct BrokerAPI: Sendable {
    private let client: AdminClient

    public init(client: AdminClient = AdminClient()) {
        self.client = client
    }

    public init(paths: InstallationPaths, keySource: SigningKeySource = .keychain) {
        self.client = AdminClient(paths: paths, keySource: keySource)
    }

    // MARK: - Status and pending work

    public func status() async throws -> SystemStatus {
        try await client.call("ui.status", as: SystemStatus.self)
    }

    public func pending() async throws -> [AuthorizationRequest] {
        try await client.call("ui.pending", as: [AuthorizationRequest].self)
    }

    public func pending(approvalID: String) async throws -> AuthorizationRequest {
        try await client.call(
            "ui.pending_one",
            .object(["approval_id": .string(approvalID)]),
            as: AuthorizationRequest.self
        )
    }

    public func ping() async -> Bool {
        await client.isReachable()
    }

    public func disconnect() async {
        await client.disconnect()
    }

    // MARK: - Decisions

    /// Authorize one request, once.
    ///
    /// `presenceVerified` reports whether the app actually completed a local
    /// presence check. It is an input to the daemon's own decision, not a
    /// substitute for it: the daemon still refuses if it required presence and
    /// this says false.
    @discardableResult
    public func approve(_ request: AuthorizationRequest, presenceVerified: Bool) async throws -> DecisionOutcome {
        try await decide(request, decision: "approve", presenceVerified: presenceVerified)
    }

    @discardableResult
    public func deny(_ request: AuthorizationRequest) async throws -> DecisionOutcome {
        try await decide(request, decision: "deny", presenceVerified: false)
    }

    @discardableResult
    private func decide(_ request: AuthorizationRequest, decision: String, presenceVerified: Bool) async throws -> DecisionOutcome {
        try await client.call("approval.decide", .object([
            "approval_id": .string(request.approvalID),
            "decision": .string(decision),
            "context_digest": .bytes(request.contextDigestBytes),
            "presence_verified": .bool(presenceVerified),
        ]), as: DecisionOutcome.self)
    }

    /// Create a standing authorization *from a pending request*, approving that
    /// request in the same call.
    ///
    /// Scoping comes from the approval the daemon already verified against a
    /// live page, not from anything assembled here, so the app cannot mint a
    /// grant for a tuple the broker has not just seen.
    public func createStandingAuthorization(
        for request: AuthorizationRequest,
        ttlDays: Int,
        presenceVerified: Bool
    ) async throws -> GrantCreateResult {
        try await client.call("grant.create", .object([
            "approval_id": .string(request.approvalID),
            "context_digest": .bytes(request.contextDigestBytes),
            "ttl_days": .integer(ttlDays),
            "presence_verified": .bool(presenceVerified),
        ]), as: GrantCreateResult.self)
    }

    // MARK: - Management

    public func grants(includeRevoked: Bool = false) async throws -> [Grant] {
        try await client.call(
            "grant.list",
            .object(["include_revoked": .bool(includeRevoked)]),
            as: [Grant].self
        )
    }

    @discardableResult
    public func revokeGrant(selector: String, reason: String = "revoked by user") async throws -> UInt32 {
        try await client.call("grant.revoke", .object([
            "selector": .string(selector),
            "reason": .string(reason),
        ]), as: RevokeResult.self).revoked
    }

    public func agents() async throws -> [Agent] {
        try await client.call("ui.agents", as: [Agent].self)
    }

    public func disableAgent(id: String) async throws {
        try await client.call("agent.disable", .object(["agent_id": .string(id)]))
    }

    public func credentials() async throws -> [CredentialReference] {
        try await client.call("ui.credentials", as: [CredentialReference].self)
    }

    public func browserSessions() async throws -> [BrowserSession] {
        try await client.call("ui.browser_sessions", as: [BrowserSession].self)
    }

    public func activity(limit: Int = 50) async throws -> [ActivityEvent] {
        try await client.call(
            "ui.activity",
            .object(["limit": .integer(limit)]),
            as: [ActivityEvent].self
        )
    }
}
