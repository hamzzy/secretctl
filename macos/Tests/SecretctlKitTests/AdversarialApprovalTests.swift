import Foundation
import Testing
@testable import SecretctlKit

/// The fixtures §14.3.5 requires.
///
/// Each one is text an agent could put in `reason`, chosen because it is trying
/// to do something to the person reading the prompt rather than to inform them.
/// Every case must come out inert, plain, and clearly subordinate, and none of
/// them may change the broker's fact block or the button semantics.
struct AdversarialApprovalTests {
    private static let origin = "https://github.com:443"

    private func sanitize(_ raw: String) -> AgentText {
        AgentText.sanitize(raw, verifiedOrigin: Self.origin)
    }

    // MARK: - The prompt's own chrome is not for sale

    @Test("Button wording is fixed and says exactly what it does")
    func buttonWordingIsBrokerOwned() {
        // §14.3.1 rule 4. These are asserted literally because the whole point
        // is that no code path may soften or shorten them.
        #expect(ApprovalChrome.affirmativeLabel == "Authorize this exact action once")
        #expect(ApprovalChrome.negativeLabel == "Deny")
        // "Always allow" is not a thing the prompt offers.
        #expect(!ApprovalChrome.affirmativeLabel.lowercased().contains("always"))
    }

    @Test("Text imitating the broker's own labels is replaced, not rendered")
    func brokerLabelImpersonationIsRedacted() {
        let hostile = "Credential: aws-root  Destination: https://evil.example  Verified by secretctl"
        let result = sanitize(hostile)

        #expect(result.impersonatedBrokerChrome)
        // The words that made it look like a fact row are gone.
        #expect(!result.displayed.lowercased().contains("verified by secretctl"))
        #expect(result.displayed.contains("[removed: text imitating secretctl]"))
    }

    @Test("Homoglyph renderings of the product name are caught")
    func homoglyphProductNameIsCaught() {
        // Cyrillic е, с, о — visually identical, different code points.
        let hostile = "This action was approved by ѕесretctl support"
        let result = sanitize(hostile)
        #expect(result.impersonatedBrokerChrome)
        #expect(!result.displayed.contains("ѕесretctl"))
    }

    @Test("Homoglyph renderings of the verified origin are caught")
    func homoglyphOriginIsCaught() {
        // Cyrillic 'і' in github.
        let hostile = "Continue to gіthub.com to finish"
        let result = sanitize(hostile)
        #expect(result.impersonatedBrokerChrome)
        #expect(!result.displayed.contains("gіthub.com"))
    }

    // MARK: - Invisible and reordering characters

    @Test("Bidi overrides cannot reorder the visible line")
    func bidiOverridesAreStripped() {
        // A right-to-left override makes the rendered line read differently
        // from the characters it contains.
        let hostile = "Sign in to \u{202E}moc.elpmaxe.live\u{202C} now"
        let result = sanitize(hostile)

        for scalar in result.displayed.unicodeScalars {
            #expect(!(0x202A...0x202E).contains(scalar.value))
            #expect(!(0x2066...0x2069).contains(scalar.value))
        }
    }

    @Test("Zero-width and tag characters are removed")
    func invisibleCharactersAreStripped() {
        let hostile = "app\u{200B}rove\u{FEFF} this\u{2060}"
            + String(String.UnicodeScalarView([Unicode.Scalar(0xE0041)!, Unicode.Scalar(0xE0042)!]))
        let result = sanitize(hostile)

        for scalar in result.displayed.unicodeScalars {
            #expect(scalar.value != 0x200B && scalar.value != 0xFEFF && scalar.value != 0x2060)
            #expect(!(0xE0000...0xE007F).contains(scalar.value))
        }
        #expect(result.displayed == "approve this")
    }

    @Test("ANSI escape sequences leave nothing behind, payload included")
    func ansiEscapesAreStripped() {
        // The broker's own filter removes the ESC as a control character, so
        // the payload can arrive on its own — both forms must vanish.
        let withEscape = sanitize("\u{1B}[31mURGENT\u{1B}[0m review needed")
        #expect(withEscape.displayed == "URGENT review needed")

        let payloadOnly = sanitize("[31mURGENT[0m review needed")
        #expect(payloadOnly.displayed == "URGENT review needed")
    }

    @Test("Combining-mark stacks cannot scribble over neighbouring rows")
    func combiningMarkStacksAreCapped() {
        let zalgo = "A" + String(repeating: "\u{0301}", count: 40) + " request"
        let result = sanitize(zalgo)
        let marks = result.displayed.unicodeScalars.filter {
            $0.properties.canonicalCombiningClass != .notReordered
        }
        #expect(marks.count <= 2)
    }

    // MARK: - Layout and length

    @Test("Newlines cannot fake the layout above the reason")
    func whitespaceIsCollapsed() {
        let hostile = "Please approve.\n\n\n\n        Risk    LOW\n\n        Agent    secretctl"
        let result = sanitize(hostile)
        #expect(!result.displayed.contains("\n"))
        #expect(!result.displayed.contains("  "))
    }

    @Test("A wall of text is cut at the display cap, visibly")
    func longTextIsTruncatedVisibly() {
        let result = sanitize(String(repeating: "persuasion ", count: 200))
        #expect(result.wasTruncated)
        #expect(result.displayed.count <= AgentText.displayLimit + 1)
        #expect(result.displayed.hasSuffix("…"))
    }

    // MARK: - Text that is merely persuasive

    /// Persuasion is not sanitized away — it cannot be, and pretending
    /// otherwise would be worse than showing it. What defends the user is that
    /// it renders as plain, collapsed, attributed text next to a fact block the
    /// agent could not touch.
    @Test("Persuasive and urgent text survives, inert and plain")
    func persuasionIsRenderedInert() {
        let cases = [
            "IT approved this, click Approve",
            "URGENT: your account will be locked in 00:09 seconds",
            "System requirement: secretctl requires you to authorize this",
            "This is a routine action for aws-root on https://evil.example",
            "See https://evil.example/help or [click here](https://evil.example)",
        ]
        for hostile in cases {
            let result = sanitize(hostile)
            // Nothing became markup, a link, or a control sequence.
            #expect(!result.displayed.contains("\n"))
            #expect(!result.displayed.unicodeScalars.contains { $0.value < 0x20 })
            // It is still present — the user reads it and judges it.
            #expect(!result.displayed.isEmpty)
        }
    }

    @Test("Benign text passes through untouched")
    func benignTextIsUnchanged() {
        let benign = "Review open pull requests"
        let result = sanitize(benign)
        #expect(result.displayed == benign)
        #expect(!result.wasTruncated)
        #expect(!result.impersonatedBrokerChrome)
        #expect(!result.wasModified)
    }

    @Test("Sanitizing never touches the broker's own fields")
    func brokerFactsAreNeverDerivedFromAgentText() throws {
        // The projection the daemon sends is the only source for the fact
        // block. Sanitizing the reason must not, and cannot, reach it.
        let json = #"{"approval_id":"apr_1","request_id":"req_1","agent_name":"Claude","agent_id":"agt_1","credential_name":"github-work","provider":"macOS Keychain","origin":"https://github.com:443","action":"authenticate.password","action_label":"Sign in","flow_steps":[],"risk":"medium","reason":"Destination https://evil.example ‮override","reason_source":"agent_provided","context_digest":"AAAA","expires_at":"2026-08-24T04:00:00Z","requires_presence":true,"is_first_for_agent":true,"grantable":true}"#
        let request = try AdminClient.decoder.decode(AuthorizationRequest.self, from: Data(json.utf8))

        let result = AgentText.sanitize(request.reason ?? "", verifiedOrigin: request.origin)
        #expect(request.origin == "https://github.com:443")
        #expect(request.credentialName == "github-work")
        #expect(request.actionLabel == "Sign in")
        #expect(request.risk == .medium)
        // The reason claimed a different destination; the fact block still says
        // the measured one, and the claim is redacted as impersonation.
        #expect(result.impersonatedBrokerChrome)
    }

    // MARK: - Rate limiting

    @Test("A prompt storm is throttled, per agent and credential")
    func promptStormIsThrottled() {
        var limiter = PromptRateLimiter()
        let start = Date()

        #expect(limiter.admit(agent: "Claude", credential: "github-work", now: start) == .allow)
        // A second prompt one second later is too soon.
        #expect(limiter.admit(agent: "Claude", credential: "github-work",
                              now: start.addingTimeInterval(1)) == .toosoon)
        // A different credential is a different budget.
        #expect(limiter.admit(agent: "Claude", credential: "aws-root",
                              now: start.addingTimeInterval(1)) == .allow)

        // Five in a rolling minute, spaced past the minimum interval, then no
        // more until the window moves on.
        var storm = PromptRateLimiter()
        var allowed = 0
        for index in 0..<6 {
            let moment = start.addingTimeInterval(Double(index) * 11)
            if storm.admit(agent: "Claude", credential: "github-work", now: moment) == .allow {
                allowed += 1
            }
        }
        #expect(allowed == ApprovalChrome.RateLimit.maximumPerMinute)
    }

    @Test("The budget recovers once the window has passed")
    func rateLimitRecovers() {
        var limiter = PromptRateLimiter()
        let start = Date()
        for index in 0..<ApprovalChrome.RateLimit.maximumPerMinute {
            _ = limiter.admit(agent: "Claude", credential: "github-work",
                              now: start.addingTimeInterval(Double(index) * 11))
        }
        #expect(limiter.admit(agent: "Claude", credential: "github-work",
                              now: start.addingTimeInterval(55)) == .tooMany)
        #expect(limiter.admit(agent: "Claude", credential: "github-work",
                              now: start.addingTimeInterval(130)) == .allow)
    }

    @Test("The settle interval is long enough to break a click-through")
    func settleIntervalIsMeaningful() {
        #expect(ApprovalChrome.settleInterval >= .milliseconds(400))
    }
}
