import AppKit
import SwiftUI
import SecretctlKit

/// Menu-bar lifecycle and window plumbing.
///
/// The app is an accessory: no Dock icon, no window at launch, nothing in the
/// way. It surfaces on its own only to ask for an authorization decision, and
/// only into a real window — never into the popover, and never into a
/// notification, both of which are too easy to click through.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private let store = BrokerStore()
    private let settings = AppSettings()
    private lazy var notifications = NotificationPresenter(settings: settings)

    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var approvalWindows: [String: NSWindow] = [:]
    private var manageWindow: NSWindow?
    private var onboardingWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        installStatusItem()
        installPopover()

        notifications.onReview = { [weak self] approvalID in self?.presentApproval(approvalID: approvalID) }
        notifications.onOpenPopover = { [weak self] in self?.showPopover() }
        notifications.prepare()

        store.onNewRequest = { [weak self] request in
            self?.notifications.announce(request)
        }
        store.onStateChange = { [weak self] _, new in
            self?.applyGlyph(new)
            self?.notifications.announce(stateChange: new)
        }
        store.start()
        applyGlyph(store.protection)

        if !settings.hasCompletedOnboarding {
            showOnboarding()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        store.stop()
    }

    // MARK: - Status item

    private func installStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.image = StatusGlyph.image(for: .disconnected)
        item.button?.imagePosition = .imageLeading
        item.button?.target = self
        item.button?.action = #selector(togglePopover)
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        item.button?.setAccessibilityLabel(ProtectionState.disconnected.accessibilityDescription)
        statusItem = item
    }

    private func applyGlyph(_ state: ProtectionState) {
        guard let button = statusItem?.button else { return }
        button.image = StatusGlyph.image(for: state)
        // The count is redundant with the glyph, but it is the difference
        // between "something is waiting" and "three things are waiting".
        let pending = store.status.pendingApprovals
        button.title = state == .approvalRequired && pending > 1 ? " \(pending)" : ""
        button.setAccessibilityLabel(
            pending > 1
                ? "\(state.accessibilityDescription) \(pending) requests waiting."
                : state.accessibilityDescription
        )
    }

    // MARK: - Popover

    private func installPopover() {
        let popover = NSPopover()
        popover.behavior = .transient
        popover.delegate = self
        popover.contentViewController = NSHostingController(
            rootView: PopoverView(
                onReview: { [weak self] request in self?.presentApproval(request) },
                onOpenActivity: { [weak self] in self?.showManageWindow(tab: .activity) },
                onOpenSettings: { [weak self] in self?.showManageWindow(tab: .settings) },
                onQuit: { NSApp.terminate(nil) }
            )
            .environmentObject(store)
            .environmentObject(settings)
        )
        self.popover = popover
    }

    @objc private func togglePopover() {
        guard let popover else { return }
        if popover.isShown { popover.performClose(nil) } else { showPopover() }
    }

    private func showPopover() {
        guard let popover, let button = statusItem?.button else { return }
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        if let window = popover.contentViewController?.view.window {
            // The popover lists recent destinations and standing
            // authorizations, so it gets the same treatment.
            window.sharingType = settings.hideFromScreenCapture ? .none : .readOnly
            window.makeKey()
        }
    }

    // MARK: - Approval windows

    private func presentApproval(approvalID: String) {
        if let request = store.pending.first(where: { $0.approvalID == approvalID }) {
            presentApproval(request)
            return
        }
        // The notification may have outlived the request — it could have been
        // answered elsewhere, or expired. Ask the daemon rather than guessing.
        Task { [weak self] in
            guard let self else { return }
            await self.store.refreshNow()
            if let request = self.store.pending.first(where: { $0.approvalID == approvalID }) {
                self.presentApproval(request)
            } else {
                self.showPopover()
            }
        }
    }

    private func presentApproval(_ request: AuthorizationRequest) {
        popover?.performClose(nil)
        notifications.withdraw(approvalID: request.approvalID)

        if let existing = approvalWindows[request.approvalID] {
            existing.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 460, height: 520),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Authorization requested"
        window.titlebarAppearsTransparent = true
        window.isReleasedWhenClosed = false
        window.level = .floating
        // The one surface that names the account and the destination together.
        // Excluding it from capture means a shared screen or a screen recording
        // shows that a decision is being made, not what it is about.
        window.sharingType = settings.hideFromScreenCapture ? .none : .readOnly
        window.collectionBehavior.insert(.moveToActiveSpace)
        window.center()
        window.contentView = NSHostingView(
            rootView: ApprovalView(request: request) { [weak self] in
                self?.closeApproval(request.approvalID)
            }
            .environmentObject(store)
            .environmentObject(settings)
        )
        approvalWindows[request.approvalID] = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func closeApproval(_ approvalID: String) {
        approvalWindows.removeValue(forKey: approvalID)?.close()
    }

    // MARK: - Management and onboarding

    private func showManageWindow(tab: ManageTab) {
        popover?.performClose(nil)
        if let manageWindow {
            manageWindow.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 860, height: 560),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "secretctl"
        window.isReleasedWhenClosed = false
        window.sharingType = settings.hideFromScreenCapture ? .none : .readOnly
        window.center()
        window.contentView = NSHostingView(
            rootView: ManageWindow(initialTab: tab)
                .environmentObject(store)
                .environmentObject(settings)
        )
        manageWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func showOnboarding() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 420),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Welcome to secretctl"
        window.titlebarAppearsTransparent = true
        window.isReleasedWhenClosed = false
        window.center()
        window.contentView = NSHostingView(
            rootView: OnboardingView { [weak self] in
                self?.settings.hasCompletedOnboarding = true
                self?.onboardingWindow?.close()
                self?.onboardingWindow = nil
            }
            .environmentObject(store)
            .environmentObject(settings)
        )
        onboardingWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}
