import Foundation

/// Swift mirrors of the `secretctl_protocol::admin` UI DTOs.
///
/// These are projections, not domain objects. The daemon already strips
/// provider locators, capability tokens and enrolment keys before anything
/// reaches this socket; these types keep that shape rather than widening it.
/// Nothing here should ever grow a field that could carry credential material.

public enum ActionKind: String, Codable, Sendable {
    case authenticatePassword = "authenticate.password"
    case authenticateTotp = "authenticate.totp"
    case formSensitiveFill = "form.sensitive_fill"
    case oauthAuthorize = "oauth.authorize"

    /// Falls back rather than throwing: a daemon that learns a new action kind
    /// must not break the whole activity list in an older app.
    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = ActionKind(rawValue: raw) ?? .formSensitiveFill
    }

    public var label: String {
        switch self {
        case .authenticatePassword: return String(localized: "Sign in")
        case .authenticateTotp: return String(localized: "Complete TOTP")
        case .formSensitiveFill: return String(localized: "Fill sensitive form")
        case .oauthAuthorize: return String(localized: "Authorize OAuth access")
        }
    }
}

public enum RiskLevel: String, Codable, Sendable, Comparable {
    case low, medium, high, critical

    /// `rawValue.capitalized` would have been untranslatable — the severity
    /// words have to be real strings to be a translator's problem.
    public var label: String {
        switch self {
        case .low: return String(localized: "Low")
        case .medium: return String(localized: "Medium")
        case .high: return String(localized: "High")
        case .critical: return String(localized: "Critical")
        }
    }

    private var order: Int {
        switch self {
        case .low: return 0
        case .medium: return 1
        case .high: return 2
        case .critical: return 3
        }
    }

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool { lhs.order < rhs.order }
}

public enum ProtectionState: String, Codable, Sendable {
    case protected
    case approvalRequired = "approval_required"
    case sensitiveOperation = "sensitive_operation"
    case completed
    case blocked
    case protectionInterrupted = "protection_interrupted"
    case outcomeUncertain = "outcome_uncertain"
    case completedEvidenceLost = "completed_evidence_lost"
    case disconnected

    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = ProtectionState(rawValue: raw) ?? .disconnected
    }

    /// Short line under the product name in the popover header.
    public var headline: String {
        switch self {
        case .protected: return String(localized: "Protected")
        case .approvalRequired: return String(localized: "Approval required")
        case .sensitiveOperation: return String(localized: "Sensitive operation")
        case .completed: return String(localized: "Completed")
        case .blocked: return String(localized: "Blocked")
        case .protectionInterrupted: return String(localized: "Protection interrupted")
        case .outcomeUncertain: return String(localized: "Outcome uncertain")
        case .completedEvidenceLost: return String(localized: "Completed — evidence lost")
        case .disconnected: return String(localized: "Disconnected")
        }
    }

    /// Spoken description for the menu-bar item. State is never conveyed by
    /// colour alone, so this is the authoritative label for assistive tech.
    public var accessibilityDescription: String {
        switch self {
        case .protected: return String(localized: "secretctl: protected. No sensitive operation.")
        case .approvalRequired: return String(localized: "secretctl: an authorization request is waiting for you.")
        case .sensitiveOperation: return String(localized: "secretctl: a sensitive credential operation is in progress.")
        case .completed: return String(localized: "secretctl: the last operation completed.")
        case .blocked: return String(localized: "secretctl: an operation was blocked. The credential was not released.")
        case .protectionInterrupted: return String(localized: "secretctl: browser protection was interrupted. Credential release halted.")
        case .outcomeUncertain: return String(localized: "secretctl: the outcome of the last operation could not be verified.")
        case .completedEvidenceLost: return String(localized: "secretctl: the operation completed, but its audit evidence was lost. Do not retry.")
        case .disconnected: return String(localized: "secretctl: the daemon is not reachable. Sensitive operations are disabled.")
        }
    }

    /// Whether this state should hold the user's attention until acknowledged.
    public var isAlarming: Bool {
        switch self {
        case .blocked, .protectionInterrupted, .outcomeUncertain, .completedEvidenceLost, .disconnected: return true
        default: return false
        }
    }
}

public enum ReasonSource: String, Codable, Sendable {
    case agentProvided = "agent_provided"
}

public struct FlowStep: Codable, Sendable, Hashable {
    public let role: String
    public let label: String
    public let optional: Bool
}

public struct AuthorizationRequest: Codable, Sendable, Identifiable, Equatable {
    public let approvalID: String
    public let requestID: String
    public let agentName: String
    public let agentID: String
    public let credentialName: String
    public let provider: String
    public let origin: String
    public let action: ActionKind
    public let actionLabel: String
    public let flowSteps: [FlowStep]
    public let risk: RiskLevel
    /// The agent's own words. Always rendered as an attributed quotation, never
    /// as system chrome — see `reasonSource`.
    public let reason: String?
    public let reasonSource: ReasonSource
    /// Base64url of the digest being approved, echoed back on decide so the
    /// daemon can confirm the page has not navigated since.
    public let contextDigest: String
    public let expiresAt: Date
    public let requiresPresence: Bool
    public let isFirstForAgent: Bool
    public let grantable: Bool

    public var id: String { approvalID }

    /// The digest as the bytes `approval.decide` expects.
    public var contextDigestBytes: Data { Base64URL.decode(contextDigest) ?? Data() }

    enum CodingKeys: String, CodingKey {
        case approvalID = "approval_id"
        case requestID = "request_id"
        case agentName = "agent_name"
        case agentID = "agent_id"
        case credentialName = "credential_name"
        case provider, origin, action, risk, reason, grantable
        case actionLabel = "action_label"
        case flowSteps = "flow_steps"
        case reasonSource = "reason_source"
        case contextDigest = "context_digest"
        case expiresAt = "expires_at"
        case requiresPresence = "requires_presence"
        case isFirstForAgent = "is_first_for_agent"
    }
}

public enum StepState: String, Codable, Sendable {
    case pending, active, done, failed
}

public struct OperationStep: Codable, Sendable, Hashable {
    public let label: String
    public let state: StepState
}

public struct ActiveOperation: Codable, Sendable {
    public let requestID: String
    public let agentName: String
    public let credentialName: String
    public let origin: String
    public let actionLabel: String
    public let steps: [OperationStep]
    /// Protections the executor has actually confirmed. Displayed verbatim and
    /// never supplemented with anything the UI merely assumes to be true.
    public let confirmedProtections: [String]
    public let protectionVerified: Bool

    enum CodingKeys: String, CodingKey {
        case requestID = "request_id"
        case agentName = "agent_name"
        case credentialName = "credential_name"
        case origin
        case actionLabel = "action_label"
        case steps
        case confirmedProtections = "confirmed_protections"
        case protectionVerified = "protection_verified"
    }
}

public struct SystemStatus: Codable, Sendable {
    public let protection: ProtectionState
    public let pendingApprovals: UInt32
    public let activeOperation: ActiveOperation?
    public let browserSessionsConnected: UInt32
    public let agentsEnrolled: UInt32
    public let agentsActive: UInt32
    public let activeGrants: UInt32
    public let providers: [String]
    public let policyFingerprint: String
    public let auditChainIntact: Bool

    enum CodingKeys: String, CodingKey {
        case protection, providers
        case pendingApprovals = "pending_approvals"
        case activeOperation = "active_operation"
        case browserSessionsConnected = "browser_sessions_connected"
        case agentsEnrolled = "agents_enrolled"
        case agentsActive = "agents_active"
        case activeGrants = "active_grants"
        case policyFingerprint = "policy_fingerprint"
        case auditChainIntact = "audit_chain_intact"
    }

    /// What the UI shows when the daemon cannot be reached. A stale
    /// "Protected" during an outage is precisely the wrong answer.
    public static let disconnected = SystemStatus(
        protection: .disconnected,
        pendingApprovals: 0,
        activeOperation: nil,
        browserSessionsConnected: 0,
        agentsEnrolled: 0,
        agentsActive: 0,
        activeGrants: 0,
        providers: [],
        policyFingerprint: "unavailable",
        auditChainIntact: false
    )
}

public struct Grant: Codable, Sendable, Identifiable {
    public let grantID: String
    public let agentName: String
    public let credentialName: String
    public let origin: String
    public let action: ActionKind
    public let actionLabel: String
    public let riskCeiling: RiskLevel
    public let requirePresence: Bool
    public let createdAt: Date
    public let expiresAt: Date
    public let revokedAt: Date?
    public let revokedReason: String?
    public let lastUsedAt: Date?
    public let useCount: UInt64
    public let active: Bool

    public var id: String { grantID }

    enum CodingKeys: String, CodingKey {
        case grantID = "grant_id"
        case agentName = "agent_name"
        case credentialName = "credential_name"
        case origin, action, active
        case actionLabel = "action_label"
        case riskCeiling = "risk_ceiling"
        case requirePresence = "require_presence"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
        case revokedAt = "revoked_at"
        case revokedReason = "revoked_reason"
        case lastUsedAt = "last_used_at"
        case useCount = "use_count"
    }
}

public struct Agent: Codable, Sendable, Identifiable {
    public let agentID: String
    public let displayName: String
    public let role: String
    public let state: String
    public let createdAt: Date
    public let activeGrants: UInt32
    public let recentEventCount: UInt32
    public let lastActivityAt: Date?

    public var id: String { agentID }

    enum CodingKeys: String, CodingKey {
        case agentID = "agent_id"
        case displayName = "display_name"
        case role, state
        case createdAt = "created_at"
        case activeGrants = "active_grants"
        case recentEventCount = "recent_event_count"
        case lastActivityAt = "last_activity_at"
    }
}

/// A credential *reference*. Carries no secret and no provider locator, which
/// is what keeps the credentials screen from becoming a password manager.
public struct CredentialReference: Codable, Sendable, Identifiable {
    public let name: String
    public let kind: String
    public let provider: String
    public let allowedActions: [ActionKind]
    public let approvedOrigins: [String]
    public let usedBy: [String]
    public let lastUsedAt: Date?
    public let disabled: Bool

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, kind, provider, disabled
        case allowedActions = "allowed_actions"
        case approvedOrigins = "approved_origins"
        case usedBy = "used_by"
        case lastUsedAt = "last_used_at"
    }
}

public struct BrowserSession: Codable, Sendable, Identifiable {
    public let sessionID: String
    public let profile: String
    public let state: String
    public let assurance: String
    public let lastHeartbeatAt: Date
    public let activeTabCount: UInt32
    public let currentOrigins: [String]

    public var id: String { sessionID }

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case profile, state, assurance
        case lastHeartbeatAt = "last_heartbeat_at"
        case activeTabCount = "active_tab_count"
        case currentOrigins = "current_origins"
    }
}

public enum EventOutcome: String, Codable, Sendable {
    case success, denied, pending, interrupted, info

    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = EventOutcome(rawValue: raw) ?? .info
    }
}

public struct ActivityEvent: Codable, Sendable, Identifiable {
    public let sequence: UInt64
    public let eventID: String
    public let eventType: String
    public let summary: String
    public let outcome: EventOutcome
    public let actorType: String
    public let actorName: String?
    public let origin: String?
    public let action: ActionKind?
    public let risk: RiskLevel?
    /// Shown only behind "technical details".
    public let errorCode: String?
    public let createdAt: Date

    public var id: String { eventID }

    enum CodingKeys: String, CodingKey {
        case sequence, summary, outcome, origin, action, risk
        case eventID = "event_id"
        case eventType = "event_type"
        case actorType = "actor_type"
        case actorName = "actor_name"
        case errorCode = "error_code"
        case createdAt = "created_at"
    }
}

/// What the daemon actually did with a decision.
///
/// `approval.decide` succeeds at the RPC level even when the broker refuses the
/// decision — a stale context digest, a page that navigated, or an approval
/// claiming presence it does not have all come back as a *successful* call
/// reporting `denied`. Treating "no error" as "approved" would close the window
/// on the user as though their credential had been released when it had not.
public struct DecisionOutcome: Decodable, Sendable, Equatable {
    public let requestID: String
    public let state: String
    public let resultCode: String?
    public let evidenceRef: String?

    /// The broker only mints a capability on an approval it accepted, so any
    /// state short of that means the credential was not released.
    public var isApproved: Bool {
        ["approved", "capability_issued", "executing", "completed"].contains(state)
    }

    public var isDenied: Bool { state == "denied" }
    public var isExpired: Bool { state == "expired" }

    enum CodingKeys: String, CodingKey {
        case requestID = "request_id"
        case state
        case resultCode = "result_code"
        case evidenceRef = "evidence_ref"
    }
}

public struct GrantCreateResult: Decodable, Sendable {
    public let grant: Grant
    public let decision: DecisionOutcome
}

public struct RevokeResult: Decodable, Sendable {
    public let revoked: UInt32
}
