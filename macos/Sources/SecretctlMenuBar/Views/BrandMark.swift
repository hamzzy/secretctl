import AppKit
import SwiftUI

/// The secretctl mark.
///
/// Loaded from the bundle when one exists, with a drawn fallback so the view
/// still renders when the app is run as a bare SwiftPM binary (no bundle, no
/// resources) — which is how it runs under `swift run` during development.
struct BrandMark: View {
    var size: CGFloat = 46

    private var bundled: NSImage? {
        guard let url = Bundle.main.url(forResource: "mark", withExtension: "png") else { return nil }
        return NSImage(contentsOf: url)
    }

    var body: some View {
        Group {
            if let bundled {
                Image(nsImage: bundled)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
            } else {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: size * 0.78))
                    .foregroundStyle(Color.accentColor)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
