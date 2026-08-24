import AppKit
import SecretctlKit

/// Menu-bar iconography.
///
/// Each state gets a distinct silhouette rather than a distinct colour, so the
/// icon stays readable for colour-blind users, in high-contrast mode, and as a
/// template image in both light and dark menu bars. Colour, where it appears at
/// all, is confirmation of a shape that already carries the meaning.
enum StatusGlyph {
    static func symbolName(for state: ProtectionState) -> String {
        switch state {
        case .protected: return "lock.shield.fill"
        case .approvalRequired: return "person.fill.questionmark"
        case .sensitiveOperation: return "bolt.shield.fill"
        case .completed: return "checkmark.shield.fill"
        case .blocked: return "xmark.shield.fill"
        case .protectionInterrupted: return "exclamationmark.shield.fill"
        case .outcomeUncertain: return "questionmark.diamond.fill"
        case .disconnected: return "shield.slash"
        }
    }

    static func image(for state: ProtectionState) -> NSImage? {
        let image = NSImage(
            systemSymbolName: symbolName(for: state),
            accessibilityDescription: state.accessibilityDescription
        )
        // Template rendering lets the menu bar tint the glyph itself, which is
        // what keeps it correct in dark mode, in Reduce Transparency, and when
        // the menu bar is tinted by the desktop picture.
        image?.isTemplate = true
        return image
    }
}
