import CryptoKit
import Foundation

/// Length-prefixed SHA-256 transcript hash.
///
/// Mirrors `secretctl_crypto::compute_context_digest`: each component is
/// preceded by its length as a big-endian `u64`, so no two different component
/// lists can collide by concatenation. The handshake signature is computed over
/// this, which means an error here surfaces as a rejected handshake rather than
/// as a subtle security weakness.
public enum ContextDigest {
    public static func compute(_ components: [Data]) -> Data {
        var hasher = SHA256()
        for component in components {
            var length = UInt64(component.count).bigEndian
            withUnsafeBytes(of: &length) { hasher.update(bufferPointer: $0) }
            hasher.update(data: component)
        }
        return Data(hasher.finalize())
    }

    public static func compute(_ components: [any DataConvertible]) -> Data {
        compute(components.map(\.asData))
    }
}

public protocol DataConvertible {
    var asData: Data { get }
}

extension Data: DataConvertible {
    public var asData: Data { self }
}

extension String: DataConvertible {
    public var asData: Data { Data(utf8) }
}

extension [UInt8]: DataConvertible {
    public var asData: Data { Data(self) }
}
