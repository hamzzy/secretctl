import Foundation
import os

/// Structured logging for the menu-bar app.
///
/// A menu-bar accessory has nowhere to print, so without this a support
/// question about why an authorization failed has no evidence behind it. The
/// log goes to the unified system log, readable with:
///
///     log stream --predicate 'subsystem == "com.secretctl.menubar"'
///
/// **What may be logged.** Machine facts: protection states, error codes,
/// method names, durations. Nothing that identifies an account or a
/// destination is logged publicly — credential names, origins, agent names and
/// the agent's own `reason` text are either omitted or marked `.private`, so
/// they are redacted in anyone else's copy of the log. Credential material
/// never reaches this process at all, so there is nothing stronger to protect
/// against here; the concern is the ordinary privacy of what the human is
/// doing, on a machine whose logs are readable by other software.
public enum Diagnostics {
    private static let subsystem = "com.secretctl.menubar"

    public static let connection = Logger(subsystem: subsystem, category: "connection")
    public static let decisions = Logger(subsystem: subsystem, category: "decisions")
    public static let state = Logger(subsystem: subsystem, category: "state")

    public static func connectionFailed(_ error: Error) {
        let presentation = ErrorPresentation.describe(error)
        connection.error("""
            admin session failed: \(presentation.symbol ?? "UNKNOWN", privacy: .public) \
            \(presentation.code.map(String.init) ?? "-", privacy: .public)
            """)
    }

    public static func connected() {
        connection.info("admin session established")
    }

    public static func protectionChanged(from previous: String, to current: String) {
        state.info("protection \(previous, privacy: .public) -> \(current, privacy: .public)")
    }

    /// The outcome of a decision the human made.
    ///
    /// `agent` and `origin` are `.private`: which account someone is signing
    /// into is theirs, not the log's.
    public static func decided(
        action: String,
        outcome: String,
        resultCode: String?,
        agent: String,
        origin: String
    ) {
        decisions.notice("""
            \(action, privacy: .public) -> \(outcome, privacy: .public) \
            [\(resultCode ?? "-", privacy: .public)] \
            agent=\(agent, privacy: .private) origin=\(origin, privacy: .private)
            """)
    }

    public static func decisionFailed(action: String, error: Error) {
        let presentation = ErrorPresentation.describe(error)
        decisions.error("""
            \(action, privacy: .public) failed: \
            \(presentation.symbol ?? "UNKNOWN", privacy: .public) \
            \(presentation.code.map(String.init) ?? "-", privacy: .public)
            """)
    }
}

extension Diagnostics {
    /// A prompt was suppressed to avoid fatigue. The request itself is
    /// untouched — only the interruption was withheld.
    public static func promptRateLimited(reason: String) {
        decisions.notice("prompt suppressed: \(reason, privacy: .public)")
    }
}
