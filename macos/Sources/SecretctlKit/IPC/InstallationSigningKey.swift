import CryptoKit
import Foundation
import Security

/// The installation signing key, read from the login Keychain.
///
/// This is the app's own credential for authenticating to the admin socket —
/// not a user credential, and explicitly not in scope for the rule that the UI
/// never receives secret material. That rule is about *managed* credentials:
/// passwords, TOTP seeds, API keys. This key proves "the human's own tooling is
/// talking", which is exactly what an admin session must establish, and it is
/// the same key `secretctl` the CLI and the Tauri build use.
///
/// It is held only for the duration of a handshake and zeroed afterwards.
public enum InstallationSigningKey {
    public static let service = "secretctl"
    public static let account = "installation-signing-key"

    public enum Failure: Error, LocalizedError {
        case notFound
        case accessDenied
        case malformed
        case keychain(OSStatus)

        public var errorDescription: String? {
            switch self {
            case .notFound:
                return "secretctl is not set up on this Mac yet. Run `secretctl init` to create an installation."
            case .accessDenied:
                return "macOS did not allow secretctl to read its installation key from the Keychain."
            case .malformed:
                return "The installation key in the Keychain is not a valid signing key."
            case .keychain(let status):
                return "The Keychain returned an unexpected error (\(status))."
            }
        }
    }

    /// Load the seed. The caller is responsible for keeping it short-lived.
    public static func loadSeed() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else { throw Failure.malformed }
            return data
        case errSecItemNotFound:
            throw Failure.notFound
        case errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled:
            throw Failure.accessDenied
        default:
            throw Failure.keychain(status)
        }
    }

    /// Run `body` with the Ed25519 key, wiping the seed on the way out.
    public static func withSigningKey<T>(_ body: (Curve25519.Signing.PrivateKey) throws -> T) throws -> T {
        var seed = try loadSeed()
        defer { seed.resetBytes(in: 0..<seed.count) }
        let key: Curve25519.Signing.PrivateKey
        do {
            key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        } catch {
            throw Failure.malformed
        }
        return try body(key)
    }
}
