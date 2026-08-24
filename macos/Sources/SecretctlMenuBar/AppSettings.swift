import Foundation
import ServiceManagement

/// How much a notification may say before the user has opened the request.
enum NotificationDetail: String, CaseIterable, Identifiable {
    /// "An agent needs permission to perform a sensitive action." Nothing else.
    case privacyPreserving
    /// Names the agent and the destination.
    case descriptive

    var id: String { rawValue }

    var label: String {
        switch self {
        case .privacyPreserving: return "Hide details until opened"
        case .descriptive: return "Show agent and destination"
        }
    }

    var explanation: String {
        switch self {
        case .privacyPreserving:
            return "Notifications say only that a request is waiting. Nothing about which account or site appears on the lock screen or during screen sharing."
        case .descriptive:
            return "Notifications name the agent and the destination. Convenient, but visible to anyone who can see your screen."
        }
    }
}

/// Small, local, non-security settings.
///
/// Nothing here can loosen a daemon decision. `requirePresenceForHighRisk` only
/// ever adds a local check on top of what the daemon already demands — the
/// daemon's own presence requirement is not affected by this switch.
@MainActor
final class AppSettings: ObservableObject {
    @Published var notificationDetail: NotificationDetail {
        didSet { defaults.set(notificationDetail.rawValue, forKey: Keys.notificationDetail) }
    }
    @Published var notificationsEnabled: Bool {
        didSet { defaults.set(notificationsEnabled, forKey: Keys.notificationsEnabled) }
    }
    @Published var requirePresenceForHighRisk: Bool {
        didSet { defaults.set(requirePresenceForHighRisk, forKey: Keys.requirePresence) }
    }
    /// Keep authorization surfaces out of screen recordings, screen sharing and
    /// screenshots. On by default: the approval window names an account and a
    /// destination, which is exactly what should not be visible to whoever is
    /// watching a shared screen.
    @Published var hideFromScreenCapture: Bool {
        didSet { defaults.set(hideFromScreenCapture, forKey: Keys.hideFromCapture) }
    }
    @Published var hasCompletedOnboarding: Bool {
        didSet { defaults.set(hasCompletedOnboarding, forKey: Keys.onboarded) }
    }
    @Published private(set) var launchAtLoginFailure: String?

    @Published var launchAtLogin: Bool {
        didSet { applyLaunchAtLogin() }
    }

    private enum Keys {
        static let notificationDetail = "notificationDetail"
        static let notificationsEnabled = "notificationsEnabled"
        static let requirePresence = "requirePresenceForHighRisk"
        static let hideFromCapture = "hideFromScreenCapture"
        static let onboarded = "hasCompletedOnboarding"
    }

    private let defaults = UserDefaults.standard

    init() {
        defaults.register(defaults: [
            Keys.notificationsEnabled: true,
            Keys.requirePresence: true,
            Keys.hideFromCapture: true,
        ])
        notificationDetail = NotificationDetail(
            rawValue: defaults.string(forKey: Keys.notificationDetail) ?? ""
        ) ?? .privacyPreserving
        notificationsEnabled = defaults.bool(forKey: Keys.notificationsEnabled)
        requirePresenceForHighRisk = defaults.bool(forKey: Keys.requirePresence)
        hideFromScreenCapture = defaults.bool(forKey: Keys.hideFromCapture)
        hasCompletedOnboarding = defaults.bool(forKey: Keys.onboarded)
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    private func applyLaunchAtLogin() {
        do {
            if launchAtLogin {
                if SMAppService.mainApp.status != .enabled { try SMAppService.mainApp.register() }
            } else {
                if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() }
            }
            launchAtLoginFailure = nil
        } catch {
            // Unsigned local builds cannot register a login item. Report it
            // rather than leaving the toggle silently lying.
            launchAtLoginFailure = error.localizedDescription
            launchAtLogin = SMAppService.mainApp.status == .enabled
        }
    }
}
