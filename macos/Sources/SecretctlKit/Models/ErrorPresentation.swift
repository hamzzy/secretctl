import Foundation

/// Plain-language rendering of broker error codes.
///
/// The primary surface never shows a code. `EPOCH_INVALIDATED` means nothing to
/// the person deciding whether to trust an agent; "the browser page changed
/// before the credential could be released" does. The symbol and number stay
/// available for the advanced details disclosure, and for support.
public struct ErrorPresentation: Sendable, Equatable {
    /// Short sentence for the primary surface.
    public let headline: String
    /// Optional second line: what this means for the user's task.
    public let detail: String?
    /// Machine symbol, e.g. `EPOCH_INVALIDATED`. Advanced details only.
    public let symbol: String?
    /// Numeric code. Advanced details only.
    public let code: Int?

    public init(headline: String, detail: String? = nil, symbol: String? = nil, code: Int? = nil) {
        self.headline = headline
        self.detail = detail
        self.symbol = symbol
        self.code = code
    }

    /// The line shown under "Technical details", or nil when there is nothing
    /// machine-specific to disclose.
    public var technicalDetail: String? {
        switch (symbol, code) {
        case (let symbol?, let code?): return "\(symbol) (\(code))"
        case (let symbol?, nil): return symbol
        case (nil, let code?): return "Error \(code)"
        default: return nil
        }
    }

    /// A decision the broker accepted the call for but refused on the merits.
    ///
    /// `result_code` is what distinguishes the reasons the daemon collapses
    /// into one `denied` state, so the user gets the actual cause rather than
    /// a shrug.
    public static func describe(refused outcome: DecisionOutcome) -> ErrorPresentation {
        switch outcome.resultCode?.uppercased() {
        case "INVALIDATED":
            return ErrorPresentation(
                headline: "The browser page changed before the credential could be released.",
                detail: "secretctl stopped rather than acting on a page you did not approve. The agent will need to ask again.",
                symbol: "APPROVAL_INVALIDATED"
            )
        case "EXPIRED":
            return ErrorPresentation(
                headline: "This request expired before it was answered.",
                detail: "The credential was not released. The agent will need to ask again.",
                symbol: "APPROVAL_EXPIRED"
            )
        default:
            return ErrorPresentation(
                headline: "secretctl did not accept the authorization.",
                detail: "The credential was not released. This happens when the request could no longer be verified — most often because user presence was not confirmed, or the page moved on.",
                symbol: "APPROVAL_DENIED"
            )
        }
    }

    public static func describe(_ error: Error) -> ErrorPresentation {
        if let broker = error as? BrokerError { return describe(broker) }
        if let client = error as? AdminClient.Failure {
            return ErrorPresentation(
                headline: client.errorDescription ?? "secretctl could not reach the daemon.",
                detail: nil,
                symbol: "DAEMON_UNAVAILABLE",
                code: nil
            )
        }
        if let keychain = error as? InstallationSigningKey.Failure {
            return ErrorPresentation(
                headline: keychain.errorDescription ?? "secretctl could not read its installation key.",
                symbol: "INSTALLATION_KEY_UNAVAILABLE"
            )
        }
        if error is UnixSocketConnection.Failure {
            return ErrorPresentation(
                headline: "secretctl lost its connection to the daemon.",
                detail: "No credential operation can run until it reconnects.",
                symbol: "TRANSPORT_FAILED"
            )
        }
        return ErrorPresentation(headline: "Something went wrong.", detail: error.localizedDescription)
    }

    public static func describe(_ error: BrokerError) -> ErrorPresentation {
        let symbol = Self.symbol(for: error.code)
        switch error.code {
        case -32001:
            return ErrorPresentation(
                headline: "Policy does not allow this action.",
                detail: "The credential was not released.",
                symbol: symbol, code: error.code
            )
        case -32002:
            return ErrorPresentation(
                headline: "This request was already denied.",
                detail: "Nothing further happened. The agent has been told it was refused.",
                symbol: symbol, code: error.code
            )
        case -32003:
            return ErrorPresentation(
                headline: "The request expired before it was answered.",
                detail: "The agent will need to ask again.",
                symbol: symbol, code: error.code
            )
        case -32004:
            return ErrorPresentation(
                headline: "The authorization expired before it could be used.",
                detail: "The credential was not released.",
                symbol: symbol, code: error.code
            )
        case -32005:
            return ErrorPresentation(
                headline: "This authorization was already used.",
                detail: "Each authorization can be used once. The agent will need to ask again.",
                symbol: symbol, code: error.code
            )
        case -32006:
            return ErrorPresentation(
                headline: "The browser page changed before the credential could be released.",
                detail: "secretctl stopped rather than typing into a page you did not approve.",
                symbol: symbol, code: error.code
            )
        case -32007:
            return ErrorPresentation(
                headline: "The destination does not match what was authorized.",
                detail: "The credential was not released.",
                symbol: symbol, code: error.code
            )
        case -32008:
            return ErrorPresentation(
                headline: "The page tried to use the credential somewhere it was not allowed.",
                detail: "The credential was not released.",
                symbol: symbol, code: error.code
            )
        case -32009:
            return ErrorPresentation(
                headline: "The browser session ended.",
                detail: "Reconnect the managed browser before running another operation.",
                symbol: symbol, code: error.code
            )
        case -32010:
            return ErrorPresentation(
                headline: "The browser could not complete the operation.",
                detail: "secretctl could not confirm what happened, so no further credential operation will run on this session.",
                symbol: symbol, code: error.code
            )
        case -32011:
            return ErrorPresentation(
                headline: "secretctl does not know how to sign in to this site yet.",
                detail: "No site recipe matched this destination.",
                symbol: symbol, code: error.code
            )
        case -32012:
            return ErrorPresentation(
                headline: "secretctl could not confirm that you were present.",
                detail: "This action requires Touch ID or your login password, and neither could be used. The credential was not released.",
                symbol: symbol, code: error.code
            )
        case -32099:
            return ErrorPresentation(
                headline: "secretctl stopped a request that failed a security check.",
                detail: "The credential was not released.",
                symbol: symbol, code: error.code
            )
        case -32602:
            return ErrorPresentation(
                headline: "That request is no longer valid.",
                detail: "It may have already been answered or expired.",
                symbol: symbol, code: error.code
            )
        default:
            return ErrorPresentation(
                headline: "secretctl could not complete that.",
                detail: error.message,
                symbol: symbol, code: error.code
            )
        }
    }

    static func symbol(for code: Int) -> String {
        switch code {
        case -32700: return "PARSE_ERROR"
        case -32600: return "INVALID_REQUEST"
        case -32601: return "METHOD_NOT_FOUND"
        case -32602: return "INVALID_PARAMS"
        case -32603: return "INTERNAL_ERROR"
        case -32001: return "AUTH_POLICY_DENIED"
        case -32002: return "APPROVAL_REJECTED"
        case -32003: return "APPROVAL_TIMEOUT"
        case -32004: return "CAPABILITY_EXPIRED"
        case -32005: return "CAPABILITY_CONSUMED"
        case -32006: return "EPOCH_INVALIDATED"
        case -32007: return "ORIGIN_MISMATCH"
        case -32008: return "FRAME_VIOLATION"
        case -32009: return "SESSION_TERMINATED"
        case -32010: return "EXECUTOR_FAILED"
        case -32011: return "RECIPE_NOT_FOUND"
        case -32012: return "USER_PRESENCE_UNAVAILABLE"
        case -32099: return "SECURITY_VIOLATION"
        default: return "BROKER_ERROR"
        }
    }
}
