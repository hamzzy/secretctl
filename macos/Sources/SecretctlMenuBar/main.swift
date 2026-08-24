import AppKit

// A menu-bar utility, started by hand rather than by SwiftUI's App lifecycle so
// that activation policy and the status item are set before anything can draw a
// window. secretctl should never present a window on launch.
MainActor.assumeIsolated {
    let application = NSApplication.shared
    let delegate = AppDelegate()
    application.delegate = delegate
    // Held for the process lifetime; NSApplication keeps only a weak delegate.
    objc_setAssociatedObject(application, "secretctl.delegate", delegate, .OBJC_ASSOCIATION_RETAIN)
    application.run()
}
