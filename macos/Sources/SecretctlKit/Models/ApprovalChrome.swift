import Foundation

/// Wording and timing the broker owns, not the agent.
///
/// These are constants rather than view-local strings because §14.3.1 makes
/// them a security property: button language is fixed, and no screen may
/// substitute agent-supplied or page-supplied wording. Keeping them here means
/// a test can assert the affirmative button says the same thing no matter what
/// text arrived with the request.
public enum ApprovalChrome {
    /// The affirmative action. Never "Always allow", never anything an agent
    /// influenced, and never shortened to imply less than it does.
    public static let affirmativeLabel = "Authorize this exact action once"
    public static let negativeLabel = "Deny"

    /// The label over agent-supplied text. Fixed, and always shown.
    public static let untrustedSectionLabel = "Untrusted agent-supplied text"

    /// How long the affirmative button stays inert after the prompt becomes
    /// visible.
    ///
    /// This defeats click-through: a prompt that appears under a cursor already
    /// travelling toward a click would otherwise accept that click as an
    /// authorization. The negative button has no such delay — denying early is
    /// always safe.
    public static let settleInterval: Duration = .milliseconds(400)

    /// Prompt rate limits, per agent × credential.
    ///
    /// Not a security control on its own. It exists so that a prompt storm
    /// cannot be used to fatigue someone into a wrong click.
    public enum RateLimit {
        public static let minimumInterval: TimeInterval = 10
        public static let maximumPerMinute = 5
    }
}

/// Tracks how often each (agent, credential) pair has raised a prompt.
///
/// A request that exceeds the limits is not dropped — the daemon still holds it
/// and the popover still lists it. What is suppressed is the *interruption*:
/// the notification and the window coming forward. Suppressing the request
/// itself would be a security decision, and this process does not make those.
public struct PromptRateLimiter: Sendable {
    private var history: [String: [Date]] = [:]

    public init() {}

    public enum Verdict: Equatable {
        case allow
        /// Too soon after the last prompt for this pair.
        case toosoon
        /// More than the per-minute allowance.
        case tooMany
    }

    public mutating func admit(agent: String, credential: String, now: Date = Date()) -> Verdict {
        let key = "\(agent)\u{0}\(credential)"
        var recent = (history[key] ?? []).filter { now.timeIntervalSince($0) < 60 }

        if let last = recent.last,
           now.timeIntervalSince(last) < ApprovalChrome.RateLimit.minimumInterval {
            history[key] = recent
            return .toosoon
        }
        if recent.count >= ApprovalChrome.RateLimit.maximumPerMinute {
            history[key] = recent
            return .tooMany
        }

        recent.append(now)
        history[key] = recent
        return .allow
    }
}
