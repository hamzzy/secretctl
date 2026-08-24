import Foundation
import Testing
@testable import SecretctlKit

/// The Swift models are hand-written mirrors of the Rust UI DTOs, so a renamed
/// field on either side would otherwise fail silently — the popover would just
/// render empty with no build error anywhere. These decode payloads that
/// `serde` actually produced.
struct ModelDecodingTests {
    static func payload(_ name: String) throws -> Data {
        let group = CrossLanguageCryptoTests.group("dtos")
        return try JSONSerialization.data(withJSONObject: group[name]!)
    }

    static func decode<T: Decodable>(_ name: String, as type: T.Type) throws -> T {
        try AdminClient.decoder.decode(T.self, from: try payload(name))
    }

    @Test("An authorization request decodes every field the approval window shows")
    func authorizationRequestDecodes() throws {
        let request = try Self.decode("authorization_request", as: AuthorizationRequest.self)
        #expect(request.approvalID == "apr_01")
        #expect(request.agentName == "Claude")
        #expect(request.credentialName == "github-work")
        #expect(request.provider == "macOS Keychain")
        #expect(request.origin == "https://github.com:443")
        #expect(request.action == .authenticatePassword)
        #expect(request.actionLabel == "Sign in")
        #expect(request.risk == .medium)
        #expect(request.reason == "Review open pull requests")
        #expect(request.reasonSource == .agentProvided)
        #expect(request.requiresPresence)
        #expect(request.isFirstForAgent)
        #expect(request.grantable)
        #expect(request.flowSteps.count == 2)
        #expect(request.flowSteps[0].label == "Password")
        #expect(request.flowSteps[1].optional)
    }

    @Test("The context digest round-trips to the bytes approval.decide expects")
    func contextDigestDecodesToBytes() throws {
        let request = try Self.decode("authorization_request", as: AuthorizationRequest.self)
        // The daemon hands out base64url and takes back a byte array; getting
        // this wrong would make every approval fail as a digest mismatch.
        #expect(request.contextDigestBytes == Data((0..<32).map(UInt8.init)))
    }

    @Test("Raw bytes serialise as a JSON array, the way serde reads Vec<u8>")
    func byteArrayEncoding() throws {
        let json = try JSONEncoder().encode(JSONValue.bytes(Data([0, 1, 255])))
        #expect(String(decoding: json, as: UTF8.self) == "[0,1,255]")
    }

    @Test("Integer params stay integers so serde can read them as u32")
    func integerEncoding() throws {
        let json = try JSONEncoder().encode(JSONValue.object(["limit": .integer(50)]))
        // `50.0` would be rejected by serde as a u32.
        #expect(String(decoding: json, as: UTF8.self) == "{\"limit\":50}")
    }

    @Test("Status decodes, including the in-flight operation")
    func statusDecodes() throws {
        let status = try Self.decode("status", as: SystemStatus.self)
        #expect(status.protection == .sensitiveOperation)
        #expect(status.pendingApprovals == 1)
        #expect(status.activeGrants == 3)
        #expect(status.providers == ["macOS Keychain"])
        #expect(status.policyFingerprint == "sha256:abcd1234")
        #expect(status.auditChainIntact)

        let operation = try #require(status.activeOperation)
        #expect(operation.agentName == "Claude")
        #expect(operation.protectionVerified)
        #expect(operation.steps.map(\.state) == [.done, .done, .active])
        #expect(operation.confirmedProtections.count == 2)
    }

    @Test("Grant, agent, credential, session and event all decode")
    func remainingModelsDecode() throws {
        let grant = try Self.decode("grant", as: Grant.self)
        #expect(grant.grantID == "gnt_01")
        #expect(grant.action == .authenticateTotp)
        #expect(grant.riskCeiling == .medium)
        #expect(grant.requirePresence)
        #expect(grant.useCount == 4)
        #expect(grant.active)
        #expect(grant.revokedAt == nil)

        let agent = try Self.decode("agent", as: Agent.self)
        #expect(agent.displayName == "Claude")
        #expect(agent.activeGrants == 3)
        #expect(agent.recentEventCount == 12)

        let credential = try Self.decode("credential", as: CredentialReference.self)
        #expect(credential.name == "github-work")
        #expect(credential.allowedActions == [.authenticatePassword, .authenticateTotp])
        #expect(credential.approvedOrigins == ["https://github.com:443"])
        #expect(!credential.disabled)

        let session = try Self.decode("browser_session", as: BrowserSession.self)
        #expect(session.profile == "Development")
        #expect(session.activeTabCount == 2)

        let event = try Self.decode("activity_event", as: ActivityEvent.self)
        #expect(event.sequence == 42)
        #expect(event.outcome == .success)
        #expect(event.summary == "GitHub authentication")
        #expect(event.errorCode == nil)
    }

    @Test("An unknown protection state degrades to disconnected, not to a crash")
    func unknownEnumsDegradeSafely() throws {
        // A newer daemon must never be able to make an older app render a
        // reassuring state it does not understand.
        let json = Data(#"{"protection":"invented_state","pending_approvals":0,"active_operation":null,"browser_sessions_connected":0,"agents_enrolled":0,"agents_active":0,"active_grants":0,"providers":[],"policy_fingerprint":"x","audit_chain_intact":false}"#.utf8)
        let status = try AdminClient.decoder.decode(SystemStatus.self, from: json)
        #expect(status.protection == .disconnected)
    }
}
