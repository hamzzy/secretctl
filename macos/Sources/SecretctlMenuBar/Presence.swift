import Foundation
import LocalAuthentication
import SecretctlKit

/// Local user-presence check: Touch ID first, the login password as fallback.
///
/// This proves a human is at the machine right now. It is *not* the
/// authorization: the daemon re-decides every request on its own terms and will
/// still refuse if it demanded presence and the app reports none. Reporting
/// `true` here without a completed evaluation would be lying to the security
/// authority, so the only path that returns `.verified` is a successful
/// `evaluatePolicy`.
///
/// Two policies are used rather than one. `deviceOwnerAuthenticationWithBiometrics`
/// is tried first when a finger is actually enrolled, because it puts the Touch
/// ID sheet up immediately instead of a password field the user then has to
/// dismiss to reach the sensor. `deviceOwnerAuthentication` — biometrics *or*
/// password — is the fallback, and the only policy used on a Mac with no
/// sensor, with no finger enrolled, or after too many failed attempts have
/// locked biometrics out. A Mac without Touch ID must still be able to satisfy
/// a presence requirement.
enum Presence {
    enum Outcome: Equatable {
        case verified(Method)
        case cancelled
        case unavailable(String)
        case failed(String)

        var isVerified: Bool {
            if case .verified = self { return true }
            return false
        }
    }

    /// How presence was actually established. Reported so the UI can say so
    /// truthfully rather than assuming a fingerprint.
    enum Method: Equatable {
        case biometric(String)
        case password

        var label: String {
            switch self {
            case .biometric(let name): return name
            case .password: return "your login password"
            }
        }
    }

    /// A fresh context per check. Reusing one lets a previous successful
    /// evaluation satisfy a later call without the user doing anything.
    private static func context() -> LAContext {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        context.localizedFallbackTitle = "Use Password…"
        // Never let an earlier unlock stand in for this decision.
        context.touchIDAuthenticationAllowableReuseDuration = 0
        return context
    }

    /// Whether this Mac can verify presence at all, by either route.
    static var isAvailable: Bool {
        context().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    }

    /// Whether a biometric sensor is present *and* enrolled right now.
    static var isBiometryEnrolled: Bool {
        let context = context()
        var error: NSError?
        let can = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        return can && context.biometryType != .none
    }

    /// Name of this Mac's biometry, or the password fallback when there is
    /// none. Used in UI copy, so it must never promise a sensor that is absent.
    static var biometryLabel: String {
        let context = context()
        // `biometryType` is only populated after a policy evaluation check.
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .touchID: return "Touch ID"
        case .faceID: return "Face ID"
        case .opticID: return "Optic ID"
        default: return "your login password"
        }
    }

    /// A label safe to use in a sentence like "Ask for … on high-risk actions".
    static var presenceLabel: String {
        isBiometryEnrolled ? biometryLabel : "your login password"
    }

    static func verify(reason: String) async -> Outcome {
        guard isAvailable else {
            return .unavailable("This Mac has neither Touch ID nor a login password set for verification.")
        }

        if isBiometryEnrolled {
            let name = biometryLabel
            switch await evaluate(.deviceOwnerAuthenticationWithBiometrics, reason: reason) {
            case .success:
                return .verified(.biometric(name))
            case .cancelled:
                return .cancelled
            case .fallbackToPassword:
                // The user chose "Use Password…", or the sensor is locked out
                // or temporarily unusable. Fall through to the combined policy,
                // which presents the password field.
                break
            case .failure(let message):
                return .failed(message)
            }
        }

        switch await evaluate(.deviceOwnerAuthentication, reason: reason) {
        case .success:
            // The combined policy may itself have been satisfied by the sensor,
            // so report the honest thing: presence, by whichever route.
            return .verified(isBiometryEnrolled ? .biometric(biometryLabel) : .password)
        case .cancelled:
            return .cancelled
        case .fallbackToPassword:
            return .cancelled
        case .failure(let message):
            return .failed(message)
        }
    }

    // MARK: - Evaluation

    private enum Step {
        case success
        case cancelled
        case fallbackToPassword
        case failure(String)
    }

    private static func evaluate(_ policy: LAPolicy, reason: String) async -> Step {
        let context = context()
        var error: NSError?
        guard context.canEvaluatePolicy(policy, error: &error) else {
            return classify(error as? LAError)
        }
        do {
            let success = try await context.evaluatePolicy(policy, localizedReason: reason)
            return success ? .success : .failure("Verification did not succeed.")
        } catch let laError as LAError {
            return classify(laError)
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    private static func classify(_ error: LAError?) -> Step {
        guard let error else { return .failure("Verification did not succeed.") }
        switch error.code {
        case .userCancel, .appCancel, .systemCancel:
            return .cancelled
        case .userFallback, .biometryNotEnrolled, .biometryNotAvailable, .biometryLockout:
            return .fallbackToPassword
        case .authenticationFailed:
            return .failure("The fingerprint or password was not recognised.")
        case .passcodeNotSet:
            return .failure("This Mac has no login password set, so presence cannot be verified.")
        default:
            return .failure(error.localizedDescription)
        }
    }
}
