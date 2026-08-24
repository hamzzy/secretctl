import Foundation
import Testing
@testable import SecretctlKit

/// The decision path, against a real broker.
///
/// Unit tests cannot reach this. When the user authorizes a request, the
/// context digest the daemon issued travels back as base64url → bytes → a JSON
/// array of numbers → `serde`'s `Vec<u8>`, and the daemon compares it against
/// what it holds. A mistake anywhere on that chain does not throw: the daemon
/// simply reports the decision as invalidated and the credential is never
/// released. The only way to know it is right is to make a real broker accept
/// it.
///
/// Each test gets its own throwaway broker with its own installation directory,
/// store and identity. The user's own installation is never touched.
@Suite(.serialized, .enabled(if: LiveBroker.isAvailable,
                             "build the fixture first: just live-fixture"))
struct LiveDecisionTests {
    /// Presence is required by the fixture's policy, so this is what a
    /// completed Touch ID check reports.
    private static let presenceConfirmed = true

    private func connect(_ broker: LiveBroker) -> BrokerAPI {
        BrokerAPI(
            paths: InstallationPaths(directory: broker.directory),
            keySource: .fixed(broker.seed)
        )
    }

    @Test("The client reaches a real broker and sees its pending work")
    func seesPendingWork() async throws {
        let broker = try LiveBroker(approvals: 2)
        defer { broker.shutDown() }
        let api = connect(broker)

        let status = try await api.status()
        #expect(status.protection == .approvalRequired)
        #expect(status.pendingApprovals == 2)

        let pending = try await api.pending()
        #expect(pending.count == 2)

        let request = try #require(pending.first)
        // Broker-verified, not agent-claimed.
        #expect(request.agentName == broker.ready.agentName)
        #expect(request.credentialName == broker.ready.credential)
        #expect(request.origin == broker.ready.origin)
        #expect(request.actionLabel == "Sign in")
        #expect(request.requiresPresence)
        #expect(request.grantable)
        #expect(request.flowSteps.map(\.label) == ["Username", "Password"])
        // The agent's own words, tagged as such.
        #expect(request.reasonSource == .agentProvided)
        #expect(request.reason?.contains("Review open pull requests") == true)
        // 32 raw bytes behind the base64url the daemon handed out.
        #expect(request.contextDigestBytes.count == 32)
    }

    @Test("Authorizing once is accepted, and the approval is consumed")
    func approveIsAccepted() async throws {
        let broker = try LiveBroker(approvals: 2)
        defer { broker.shutDown() }
        let api = connect(broker)

        let request = try #require(try await api.pending().first)
        let outcome = try await api.approve(request, presenceVerified: Self.presenceConfirmed)

        // The real proof that the echoed digest round-tripped intact: a
        // mismatch would come back as `invalidated`, not as an error.
        #expect(outcome.isApproved, "broker refused with \(outcome.state)/\(outcome.resultCode ?? "-")")
        #expect(outcome.requestID == request.requestID)

        let remaining = try await api.pending()
        #expect(!remaining.contains { $0.approvalID == request.approvalID })

        let activity = try await api.activity(limit: 50)
        #expect(activity.contains { $0.eventType == "approval.approved" })
        #expect(activity.contains { $0.eventType == "capability.minted" })
    }

    @Test("The daemon refuses an approval that claims no presence")
    func approveWithoutPresenceIsRefused() async throws {
        let broker = try LiveBroker(approvals: 2)
        defer { broker.shutDown() }
        let api = connect(broker)

        let request = try #require(try await api.pending().first)
        #expect(request.requiresPresence)

        // The app is not the authority. Claiming an approval on a request that
        // demands presence, without having verified any, must not release the
        // credential — and the refusal arrives as a *successful* call, which is
        // exactly why the UI reads the outcome rather than the absence of an
        // error.
        let outcome = try await api.approve(request, presenceVerified: false)
        #expect(!outcome.isApproved)
        #expect(outcome.isDenied)

        let presentation = ErrorPresentation.describe(refused: outcome)
        #expect(presentation.headline.contains("did not accept"))

        let activity = try await api.activity(limit: 50)
        #expect(!activity.contains { $0.eventType == "capability.minted" },
                "no capability may be minted for a refused decision")
    }

    @Test("Denying is recorded and releases nothing")
    func denyIsRecorded() async throws {
        let broker = try LiveBroker(approvals: 2)
        defer { broker.shutDown() }
        let api = connect(broker)

        let request = try #require(try await api.pending().first)
        let outcome = try await api.deny(request)
        #expect(outcome.isDenied)

        let remaining = try await api.pending()
        #expect(!remaining.contains { $0.approvalID == request.approvalID })

        let activity = try await api.activity(limit: 50)
        #expect(activity.contains { $0.eventType == "approval.denied" })
        #expect(!activity.contains { $0.eventType == "capability.minted" })
    }

    @Test("A standing authorization is created from a verified approval")
    func standingAuthorizationIsCreated() async throws {
        let broker = try LiveBroker(approvals: 2)
        defer { broker.shutDown() }
        let api = connect(broker)

        let request = try #require(try await api.pending().first)
        #expect(request.grantable)

        let result = try await api.createStandingAuthorization(
            for: request, ttlDays: 30, presenceVerified: Self.presenceConfirmed
        )
        #expect(result.decision.isApproved, "broker refused with \(result.decision.state)")

        // Scope comes from the approval the broker itself verified, so it must
        // match the request exactly rather than anything the app assembled.
        let grant = result.grant
        #expect(grant.agentName == broker.ready.agentName)
        #expect(grant.credentialName == broker.ready.credential)
        #expect(grant.origin == broker.ready.origin)
        #expect(grant.action == request.action)
        #expect(grant.active)
        #expect(grant.riskCeiling <= .medium)

        let listed = try await api.grants()
        #expect(listed.contains { $0.grantID == grant.grantID })

        let activity = try await api.activity(limit: 50)
        #expect(activity.contains { $0.eventType == "grant.created" })
    }

    @Test("Revoking a standing authorization takes effect immediately")
    func revokeTakesEffect() async throws {
        let broker = try LiveBroker(approvals: 2)
        defer { broker.shutDown() }
        let api = connect(broker)

        let request = try #require(try await api.pending().first)
        let grant = try await api.createStandingAuthorization(
            for: request, ttlDays: 30, presenceVerified: Self.presenceConfirmed
        ).grant

        let revoked = try await api.revokeGrant(selector: grant.grantID, reason: "revoked by test")
        #expect(revoked == 1)

        let active = try await api.grants()
        #expect(!active.contains { $0.grantID == grant.grantID })

        let all = try await api.grants(includeRevoked: true)
        let stored = try #require(all.first { $0.grantID == grant.grantID })
        #expect(!stored.active)
        #expect(stored.revokedAt != nil)
        #expect(stored.revokedReason == "revoked by test")
    }

    @Test("An approval cannot be decided twice")
    func doubleDecideIsRejected() async throws {
        let broker = try LiveBroker(approvals: 2)
        defer { broker.shutDown() }
        let api = connect(broker)

        let request = try #require(try await api.pending().first)
        _ = try await api.deny(request)

        // The second attempt reaches a broker that no longer holds the
        // approval, so it must come back as an error rather than quietly
        // succeeding.
        await #expect(throws: BrokerError.self) {
            _ = try await api.approve(request, presenceVerified: Self.presenceConfirmed)
        }
    }

    @Test("Management surfaces read back from a real store")
    func managementSurfacesRead() async throws {
        let broker = try LiveBroker(approvals: 2)
        defer { broker.shutDown() }
        let api = connect(broker)

        let agents = try await api.agents()
        let agent = try #require(agents.first { $0.displayName == broker.ready.agentName })
        #expect(agent.state == "enrolled")

        let sessions = try await api.browserSessions()
        let session = try #require(sessions.first { $0.profile == "Development" })
        #expect(session.assurance == "managed")

        // A credential's approved destinations are derived from its live
        // standing authorizations, not from policy, so one has to exist before
        // the credentials screen can show anything.
        let credentials = try await api.credentials()
        let before = try #require(credentials.first { $0.name == broker.ready.credential })
        #expect(before.approvedOrigins.isEmpty)
        // The projection must never carry where the secret actually lives.
        #expect(before.provider == "memory")

        let request = try #require(try await api.pending().first)
        _ = try await api.createStandingAuthorization(
            for: request, ttlDays: 30, presenceVerified: Self.presenceConfirmed
        )

        let after = try #require(try await api.credentials().first { $0.name == broker.ready.credential })
        #expect(after.approvedOrigins == [broker.ready.origin])
        #expect(after.usedBy == [broker.ready.agentName])
        #expect(after.lastUsedAt == nil, "a grant is not a use")
    }
}
