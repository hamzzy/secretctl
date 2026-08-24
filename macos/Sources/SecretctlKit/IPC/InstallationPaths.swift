import Foundation

/// Where an installation of secretctl lives.
///
/// The default is resolved with the same rules the CLI and daemon use, so the
/// menu-bar app always addresses the installation the user already configured
/// rather than creating a second one. It is a value rather than a namespace of
/// statics so a test — or a second installation — can be addressed without
/// mutating process-wide environment.
public struct InstallationPaths: Sendable, Equatable {
    public let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    public static let `default` = InstallationPaths(directory: resolveDefaultDirectory())

    public var adminSocket: URL {
        directory.appendingPathComponent("run/admin.sock")
    }

    /// The pinned broker identity, written at `secretctl init`.
    public var brokerPublicKey: URL {
        directory.appendingPathComponent("broker_key.pub")
    }

    public var isInitialised: Bool {
        FileManager.default.fileExists(atPath: brokerPublicKey.path)
    }

    static func resolveDefaultDirectory() -> URL {
        let base: URL
        if let configHome = ProcessInfo.processInfo.environment["XDG_CONFIG_HOME"], !configHome.isEmpty {
            base = URL(fileURLWithPath: configHome, isDirectory: true)
        } else if let home = ProcessInfo.processInfo.environment["HOME"], !home.isEmpty {
            base = URL(fileURLWithPath: home, isDirectory: true).appendingPathComponent(".config")
        } else {
            base = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true).appendingPathComponent(".config")
        }
        return base.appendingPathComponent("secretctl", isDirectory: true)
    }
}

/// Where the client's own authentication key comes from.
///
/// Production always uses `.keychain`. The indirection exists so an end-to-end
/// test can drive a throwaway broker without a Keychain dialog — it is a
/// constructor parameter, not an environment switch, so nothing outside this
/// process can redirect where a running app looks for its key.
public struct SigningKeySource: Sendable {
    public let loadSeed: @Sendable () throws -> Data

    public init(loadSeed: @escaping @Sendable () throws -> Data) {
        self.loadSeed = loadSeed
    }

    public static let keychain = SigningKeySource { try InstallationSigningKey.loadSeed() }

    /// A caller-supplied seed. Test and fixture use only.
    public static func fixed(_ seed: Data) -> SigningKeySource {
        SigningKeySource { seed }
    }
}
