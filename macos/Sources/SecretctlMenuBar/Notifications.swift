import AppKit
import Foundation
import SecretctlKit
import UserNotifications

/// Notifications are an attention mechanism, not the authorization boundary.
///
/// Nothing can be approved from a notification. The only action is "Review",
/// which brings up the trusted approval window; the decision is always made
/// against broker-verified detail the user has actually looked at.
///
/// Default content is privacy-preserving: the lock screen, a shared screen, or
/// a glance over the shoulder should not reveal which account an agent is
/// reaching for.
@MainActor
final class NotificationPresenter: NSObject, UNUserNotificationCenterDelegate {
    static let approvalCategory = "secretctl.approval"
    static let reviewAction = "secretctl.review"

    private let settings: AppSettings
    /// Invoked with the approval id the user chose to review.
    var onReview: ((String) -> Void)?
    /// Invoked when an alarming state notification is opened.
    var onOpenPopover: (() -> Void)?

    /// Notification APIs need a bundle identity. A bare SwiftPM binary has
    /// none, so the app degrades to menu-bar-only signalling rather than
    /// trapping at launch.
    private let isAvailable: Bool = Bundle.main.bundleIdentifier != nil

    init(settings: AppSettings) {
        self.settings = settings
        super.init()
    }

    func prepare() {
        guard isAvailable else { return }
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let review = UNNotificationAction(
            identifier: Self.reviewAction,
            title: "Review",
            options: [.foreground]
        )
        center.setNotificationCategories([
            UNNotificationCategory(
                identifier: Self.approvalCategory,
                actions: [review],
                intentIdentifiers: [],
                options: []
            )
        ])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func announce(_ request: AuthorizationRequest) {
        guard isAvailable, settings.notificationsEnabled else { return }
        let content = UNMutableNotificationContent()
        content.title = "secretctl"
        switch settings.notificationDetail {
        case .privacyPreserving:
            content.body = "Authorization request waiting.\nAn agent needs permission to perform a sensitive action."
        case .descriptive:
            content.body = "\(request.agentName) is requesting access to \(Self.displayHost(request.origin))."
        }
        content.categoryIdentifier = Self.approvalCategory
        content.userInfo = ["approval_id": request.approvalID]
        content.interruptionLevel = request.risk >= .high ? .timeSensitive : .active
        submit(content, id: "approval-\(request.approvalID)")
    }

    /// Announce a state the user must not miss. Success is deliberately quiet:
    /// the menu-bar glyph is enough, and a notification per completed sign-in
    /// would train people to dismiss secretctl without reading.
    func announce(stateChange state: ProtectionState) {
        guard isAvailable, settings.notificationsEnabled, state.isAlarming else { return }
        let content = UNMutableNotificationContent()
        content.title = "secretctl"
        switch state {
        case .protectionInterrupted:
            content.body = "Protection interrupted. A sensitive browser operation was stopped and credential release halted."
        case .blocked:
            content.body = "An operation was blocked. The credential was not released."
        case .outcomeUncertain:
            content.body = "The result of a credential operation could not be verified."
        case .disconnected:
            content.body = "secretctl lost contact with its daemon. Sensitive operations are disabled."
        default:
            return
        }
        content.interruptionLevel = .timeSensitive
        submit(content, id: "state-\(state.rawValue)")
    }

    private func submit(_ content: UNMutableNotificationContent, id: String) {
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: id, content: content, trigger: nil)
        )
    }

    func withdraw(approvalID: String) {
        guard isAvailable else { return }
        UNUserNotificationCenter.current()
            .removeDeliveredNotifications(withIdentifiers: ["approval-\(approvalID)"])
    }

    static func displayHost(_ origin: String) -> String {
        guard let url = URL(string: origin), let host = url.host() else { return origin }
        return host
    }

    // MARK: - UNUserNotificationCenterDelegate

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        let approvalID = response.notification.request.content.userInfo["approval_id"] as? String
        await MainActor.run {
            NSApp.activate(ignoringOtherApps: true)
            if let approvalID {
                self.onReview?(approvalID)
            } else {
                self.onOpenPopover?()
            }
        }
    }
}
