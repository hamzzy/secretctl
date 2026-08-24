import AppKit
import SwiftUI

/// Motion tokens.
///
/// Three rules decide everything here.
///
/// **Frequency decides whether a thing animates at all.** The menu-bar glyph
/// changes constantly and is watched passively — it swaps with no animation.
/// The popover opens dozens of times a day, so its content moves a little and
/// briefly. The approval window is rare and consequential, so it can afford a
/// real entrance.
///
/// **Exits are faster than entrances.** The user is deciding on the way in and
/// the system is responding on the way out; matching the two makes dismissal
/// feel like it lagged.
///
/// **The built-in curves are too weak.** `easeOut` reads as mush at these
/// durations; the custom curve starts fast enough to feel like a direct
/// consequence of the click. Nothing here uses `easeIn` — delaying the first
/// few frames is exactly the wrong thing at the moment the eye is on the
/// element.
enum Motion {
    /// System-wide Reduce Motion. Read from AppKit so non-View code (the status
    /// item, the notification layer) can honour it too.
    static var reduceMotion: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
    }

    /// cubic-bezier(0.23, 1, 0.32, 1) — strong ease-out for anything arriving.
    static func enter(_ duration: TimeInterval = 0.18) -> Animation {
        reduceMotion
            ? .linear(duration: 0.12)
            : .timingCurve(0.23, 1, 0.32, 1, duration: duration)
    }

    /// Deliberately quicker than `enter`.
    static func exit(_ duration: TimeInterval = 0.12) -> Animation {
        reduceMotion
            ? .linear(duration: 0.09)
            : .timingCurve(0.23, 1, 0.32, 1, duration: duration)
    }

    /// cubic-bezier(0.77, 0, 0.175, 1) — for something moving or morphing
    /// in place rather than arriving or leaving.
    static func move(_ duration: TimeInterval = 0.24) -> Animation {
        reduceMotion
            ? .linear(duration: 0.12)
            : .timingCurve(0.77, 0, 0.175, 1, duration: duration)
    }

    /// Press feedback. Short enough to read as instantaneous acknowledgement.
    static let press = Animation.timingCurve(0.23, 1, 0.32, 1, duration: 0.16)

    /// Stagger step for a list arriving together. Long enough to read as a
    /// cascade, short enough that the last row is not perceptibly late.
    static let stagger: TimeInterval = 0.04

    /// The entrance used for content that replaces other content in place.
    ///
    /// Nothing scales from zero — an element that is 4px low and transparent
    /// still has a shape, so it reads as arriving rather than materialising.
    static var contentSwap: AnyTransition {
        if reduceMotion { return .opacity }
        return .asymmetric(
            insertion: .opacity.combined(with: .offset(y: 4)),
            removal: .opacity
        )
    }
}

/// Press feedback for anything clickable that isn't a stock AppKit control.
///
/// Stock buttons already acknowledge a press; plain and custom ones do not,
/// and without it the surface feels like it did not hear the click. The scale
/// is deliberately small — enough to register, not enough to notice.
struct PressableStyle: ButtonStyle {
    var scale: CGFloat = 0.97
    var opacity: Double = 1

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(Motion.reduceMotion ? 1 : (configuration.isPressed ? scale : 1))
            .opacity(configuration.isPressed ? opacity : 1)
            .animation(Motion.press, value: configuration.isPressed)
    }
}

/// A row that lifts slightly under the pointer and depresses on click.
struct HoverHighlight: ViewModifier {
    var cornerRadius: CGFloat = 6
    var restingOpacity: Double = 0
    var hoverOpacity: Double = 0.05

    @State private var isHovering = false

    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius)
                    .fill(Color.primary.opacity(isHovering ? hoverOpacity : restingOpacity))
            )
            .onHover { hovering in
                // Hover is a colour change, so it takes `ease`-like timing
                // rather than the sharper entrance curve.
                withAnimation(.easeOut(duration: 0.12)) { isHovering = hovering }
            }
    }
}

extension View {
    func hoverHighlight(cornerRadius: CGFloat = 6, hoverOpacity: Double = 0.05) -> some View {
        modifier(HoverHighlight(cornerRadius: cornerRadius, hoverOpacity: hoverOpacity))
    }

    /// Fade-and-rise entrance for a row at `index` in a list that arrives
    /// together. Decorative only — it never gates interaction.
    func staggeredAppearance(index: Int, isVisible: Bool) -> some View {
        modifier(StaggeredAppearance(index: index, isVisible: isVisible))
    }
}

private struct StaggeredAppearance: ViewModifier {
    let index: Int
    let isVisible: Bool

    func body(content: Content) -> some View {
        content
            .opacity(isVisible ? 1 : 0)
            .offset(y: isVisible || Motion.reduceMotion ? 0 : 5)
            .animation(
                Motion.enter(0.22).delay(Motion.reduceMotion ? 0 : Double(index) * Motion.stagger),
                value: isVisible
            )
    }
}

/// A text link that acknowledges the press.
///
/// `.link` gives no press feedback at all, which on a surface where the click
/// opens another window reads as the click having missed.
struct LinkPressStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(isEnabled ? Color.accentColor : Color.secondary)
            .opacity(configuration.isPressed ? 0.6 : 1)
            .animation(Motion.press, value: configuration.isPressed)
            .contentShape(Rectangle())
    }
}
