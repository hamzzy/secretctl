import Foundation
import Testing
@testable import SecretctlKit

/// §30: the primary surface speaks plain language; codes live behind
/// "technical details". These tests hold that line — both that every code the
/// daemon can return is translated, and that no translation leaks the raw
/// symbol into the sentence the user reads first.
struct ErrorPresentationTests {
    /// Every code in `RpcErrorCode`.
    static let allCodes = [
        -32700, -32600, -32601, -32602, -32603,
        -32001, -32002, -32003, -32004, -32005, -32006,
        -32007, -32008, -32009, -32010, -32011, -32012, -32099,
    ]

    @Test("Every broker error code gets a plain-language headline")
    func everyCodeIsTranslated() {
        for code in Self.allCodes {
            let presentation = ErrorPresentation.describe(BrokerError(code: code, message: "raw daemon text"))
            #expect(!presentation.headline.isEmpty)
            #expect(presentation.headline.last == "." || presentation.headline.last == "?")
        }
    }

    @Test("A headline never contains a machine symbol or a raw code")
    func headlinesStayHumanReadable() {
        for code in Self.allCodes {
            let presentation = ErrorPresentation.describe(BrokerError(code: code, message: "x"))
            let symbol = ErrorPresentation.symbol(for: code)
            #expect(!presentation.headline.contains(symbol))
            #expect(!presentation.headline.contains("\(code)"))
            #expect(!presentation.headline.contains("_"))
        }
    }

    @Test("EPOCH_INVALIDATED reads as a page change, with the code kept for details")
    func epochInvalidatedReadsAsAPageChange() {
        let presentation = ErrorPresentation.describe(BrokerError(code: -32006, message: "epoch invalidated"))
        #expect(presentation.headline == "The browser page changed before the credential could be released.")
        #expect(presentation.technicalDetail == "EPOCH_INVALIDATED (-32006)")
    }

    @Test("Refusals say the credential was not released")
    func refusalsSayNothingWasReleased() {
        // The single most important thing a person needs from a failure
        // message here is whether their secret went anywhere.
        for code in [-32001, -32007, -32008, -32012, -32099, -32004] {
            let presentation = ErrorPresentation.describe(BrokerError(code: code, message: "x"))
            let text = [presentation.headline, presentation.detail ?? ""].joined(separator: " ")
            #expect(text.lowercased().contains("not released"))
        }
    }

    @Test("An unknown code still produces something usable")
    func unknownCodeDegrades() {
        let presentation = ErrorPresentation.describe(BrokerError(code: -40000, message: "something new"))
        #expect(presentation.headline == "secretctl could not complete that.")
        #expect(presentation.detail == "something new")
        #expect(presentation.technicalDetail == "BROKER_ERROR (-40000)")
    }

    @Test("Transport and setup failures are described without a broker code")
    func clientFailuresAreDescribed() {
        let unavailable = ErrorPresentation.describe(AdminClient.Failure.daemonUnavailable("socket closed"))
        #expect(unavailable.headline.contains("not reachable"))
        #expect(unavailable.code == nil)

        let pin = ErrorPresentation.describe(AdminClient.Failure.keyPinMismatch)
        #expect(pin.headline.contains("does not match"))

        let missing = ErrorPresentation.describe(InstallationSigningKey.Failure.notFound)
        #expect(missing.headline.contains("secretctl init"))
    }
}
