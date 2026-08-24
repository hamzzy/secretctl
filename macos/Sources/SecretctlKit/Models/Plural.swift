import Foundation

/// Counted nouns that a translator can actually reach.
///
/// An inline ternary inside a `Text` literal — `count == 1 ? "tab" : "tabs"` —
/// is invisible to string extraction and untranslatable: it bakes English's
/// two-form plural rule into the layout, and languages with three or six forms
/// have nowhere to put them. Routing every count through here gives each form a
/// real key, and a language that needs more forms can override the same key in
/// a `.stringsdict` without any code changing.
public enum Plural {
    /// A count and its noun, e.g. "1 tab" / "4 tabs".
    public static func counted(
        _ count: Int,
        one: String.LocalizationValue,
        other: String.LocalizationValue
    ) -> String {
        let noun = count == 1 ? String(localized: one) : String(localized: other)
        return String(localized: "\(count) \(noun)")
    }

    /// Just the noun, for when the count is displayed separately.
    public static func noun(
        _ count: Int,
        one: String.LocalizationValue,
        other: String.LocalizationValue
    ) -> String {
        count == 1 ? String(localized: one) : String(localized: other)
    }
}
