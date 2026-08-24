import Foundation

/// Sanitized agent-supplied text, ready to render.
///
/// The approval prompt is a security boundary that displays attacker-controlled
/// text. The attacker's goal is not to break the crypto — it is to make a tired
/// human click Authorize on a different action than the one they think they are
/// approving. Everything here exists to make that harder.
///
/// The broker already strips bidi controls and C0/C1 characters on the way out,
/// and caps the string. This is the second layer, and it is not redundant: it
/// adds NFC normalization, zero-width removal, combining-mark limiting,
/// whitespace collapsing, confusable detection against the broker's own labels
/// and the verified origin, and the short display cap. A renderer that trusts
/// its input to have been cleaned upstream is one upstream bug away from
/// rendering an attack.
public struct AgentText: Sendable, Equatable {
    /// Safe to render. Plain text, never markup, never a link.
    public let displayed: String
    /// True when the original ran past the display cap, so the UI can show that
    /// something was cut rather than silently ending mid-sentence.
    public let wasTruncated: Bool
    /// True when the text tried to imitate the broker's own chrome — a field
    /// label, a button, the product name, or the verified origin — including
    /// via homoglyphs. The offending run is replaced, and the UI says so.
    public let impersonatedBrokerChrome: Bool
    /// True when anything at all was removed or rewritten. Not shown on its
    /// own; it exists so the app can log that hostile text arrived.
    public let wasModified: Bool

    /// Characters displayed. The broker accepts and stores up to 500; a prompt
    /// shows far less, because a wall of attacker text is itself the attack.
    public static let displayLimit = 200

    /// At most this many combining marks may sit on one base character.
    /// Zalgo-style stacks otherwise scribble over neighbouring rows.
    private static let combiningMarkLimit = 2

    /// The broker's own words. Agent text that reproduces any of these — in any
    /// script — is trying to look like system chrome.
    private static let protectedChrome = [
        "secretctl",
        "verified by",
        "authorize this exact action",
        "authorize once",
        "browser protection",
        "standing authorization",
        "credential",
        "destination",
        "provider",
        "authentication",
    ]

    public static func sanitize(_ raw: String, verifiedOrigin: String? = nil) -> AgentText {
        var text = raw

        // 1. Terminal escape sequences, before control characters are removed —
        //    stripping the lone ESC first would leave "[31m" behind as text.
        text = stripEscapeSequences(text)

        // 2. Bidi overrides, zero-width and other invisible formatting, and all
        //    control characters. A right-to-left override can reverse a visible
        //    line so it reads as a different origin than it contains.
        var kept = String.UnicodeScalarView()
        for scalar in text.unicodeScalars
        where !isBidiControl(scalar) && !isInvisibleFormat(scalar) && !isControl(scalar) {
            kept.append(scalar)
        }
        text = String(kept)

        // 3. Normalize, so a decomposed lookalike cannot dodge the comparisons
        //    below.
        text = text.precomposedStringWithCanonicalMapping

        // 4. Cap combining marks per base character.
        text = limitCombiningMarks(text)

        // 5. Collapse whitespace and newlines. A reason cannot use blank space
        //    to push its own content into the shape of the layout above it.
        text = text
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")

        // 6. Confusables against the broker's chrome and the real origin.
        let (redacted, impersonated) = redactImpersonation(text, verifiedOrigin: verifiedOrigin)
        text = redacted

        // 7. Display cap, with the cut made visible.
        let truncated = text.count > displayLimit
        if truncated {
            text = String(text.prefix(displayLimit)).trimmingCharacters(in: .whitespaces) + "…"
        }

        return AgentText(
            displayed: text,
            wasTruncated: truncated,
            impersonatedBrokerChrome: impersonated,
            wasModified: text != raw
        )
    }

    // MARK: - Steps

    private static func stripEscapeSequences(_ text: String) -> String {
        // CSI (ESC [ … final), OSC (ESC ] … BEL or ST), and two-character
        // escapes. The bracket forms are also matched without their ESC,
        // because the broker's own filter removes control characters and would
        // otherwise leave the payload behind as visible text.
        let patterns = [
            "\u{1B}\\][^\u{07}\u{1B}]*(?:\u{07}|\u{1B}\\\\)",
            "\u{1B}\\[[0-9;?]*[ -/]*[@-~]",
            "\u{1B}[@-Z\\\\-_]",
            "\\[[0-9;?]{1,8}[a-zA-Z]",
        ]
        var result = text
        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { continue }
            result = regex.stringByReplacingMatches(
                in: result,
                range: NSRange(result.startIndex..., in: result),
                withTemplate: ""
            )
        }
        return result
    }

    private static func isBidiControl(_ scalar: Unicode.Scalar) -> Bool {
        (0x202A...0x202E).contains(scalar.value)
            || (0x2066...0x2069).contains(scalar.value)
            || scalar.value == 0x200E || scalar.value == 0x200F
            || scalar.value == 0x061C
    }

    private static func isInvisibleFormat(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x200B...0x200D, 0x2060...0x2064, 0xFEFF, 0x00AD, 0x180E:
            return true
        // Variation selectors and tag characters: invisible, and tags have been
        // used to smuggle whole hidden sentences past a reader.
        case 0xFE00...0xFE0F, 0xE0000...0xE007F:
            return true
        default:
            return false
        }
    }

    private static func isControl(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value < 0x20 || (0x7F...0x9F).contains(scalar.value)
    }

    private static func limitCombiningMarks(_ text: String) -> String {
        var result = String.UnicodeScalarView()
        var run = 0
        for scalar in text.unicodeScalars {
            if scalar.properties.canonicalCombiningClass != .notReordered {
                run += 1
                if run > combiningMarkLimit { continue }
            } else {
                run = 0
            }
            result.append(scalar)
        }
        return String(result)
    }

    // MARK: - Confusables

    /// Fold a string down to the shape a reader actually perceives, so that
    /// Cyrillic "ѕесretctl" and Latin "secretctl" compare equal.
    static func skeleton(_ text: String) -> String {
        let folded = text.folding(
            options: [.diacriticInsensitive, .caseInsensitive, .widthInsensitive],
            locale: Locale(identifier: "en_US_POSIX")
        )
        var result = ""
        for character in folded {
            if let replacement = confusables[character] {
                result.append(replacement)
            } else if character.isLetter || character.isNumber {
                result.append(character)
            }
            // Punctuation and spacing are dropped: they are the cheapest way to
            // break a naive substring match while leaving the text readable.
        }
        return result
    }

    /// Latin lookalikes from other scripts. Not exhaustive — no such table is —
    /// but it covers the characters an attacker actually reaches for.
    private static let confusables: [Character: Character] = [
        // Cyrillic
        "а": "a", "в": "b", "с": "c", "е": "e", "ѕ": "s", "і": "i", "ј": "j",
        "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "т": "t", "у": "y",
        "х": "x", "ԁ": "d", "ո": "n", "ѵ": "v", "ԛ": "q",
        // Greek
        "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k",
        "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y",
        // Armenian
        "օ": "o", "ս": "u", "գ": "q",
        // Digit / letter confusions
        "0": "o", "1": "l", "3": "e", "5": "s",
    ]

    private static func redactImpersonation(
        _ text: String,
        verifiedOrigin: String?
    ) -> (String, Bool) {
        var targets = protectedChrome.map(skeleton).filter { !$0.isEmpty }
        if let verifiedOrigin {
            // Both the full origin and its bare host: an attacker quoting
            // "github.com" is imitating the destination row just as much as one
            // quoting the whole canonical origin.
            targets.append(skeleton(verifiedOrigin))
            if let host = URL(string: verifiedOrigin)?.host() {
                targets.append(skeleton(host))
            }
        }
        targets = targets.filter { $0.count >= 5 }

        // Work word by word: a phrase is replaced wholesale rather than having
        // characters surgically removed, which would leave a readable remnant.
        let words = text.split(separator: " ", omittingEmptySubsequences: false)
        var output: [String] = []
        var found = false
        var index = 0

        while index < words.count {
            var matchedLength = 0
            // Longest run of up to four words that folds onto a protected term.
            for length in stride(from: min(4, words.count - index), through: 1, by: -1) {
                let phrase = words[index..<(index + length)].joined(separator: " ")
                let folded = skeleton(phrase)
                guard !folded.isEmpty else { continue }
                if targets.contains(where: { folded == $0 || folded.contains($0) }) {
                    matchedLength = length
                    break
                }
            }
            if matchedLength > 0 {
                found = true
                output.append("[removed: text imitating secretctl]")
                index += matchedLength
            } else {
                output.append(String(words[index]))
                index += 1
            }
        }

        return (output.joined(separator: " "), found)
    }
}
