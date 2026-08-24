import CryptoKit
import Foundation

/// Client half of the broker's authenticated channel.
///
/// Byte-compatible with `secretctl_crypto::SecureChannel`:
///
/// - HKDF-SHA256 over the raw X25519 shared secret, salted with the server
///   nonce, expanded to 64 bytes. The first 32 are the client's transmit key,
///   the second 32 its receive key; the daemon swaps them.
/// - ChaCha20-Poly1305 with a deterministic 12-byte nonce: four zero bytes
///   followed by a big-endian counter that advances independently in each
///   direction.
/// - The frame is `ciphertext || tag`. CryptoKit's `combined` representation
///   prepends the nonce, which the daemon does not expect, so the parts are
///   assembled explicitly here.
///
/// Nonce reuse would be catastrophic, so the counters only ever move forward
/// and a decrypt failure leaves the receive counter untouched — the caller is
/// expected to discard the whole session rather than resynchronise.
public final class SecureChannel {
    private let transmitKey: SymmetricKey
    private let receiveKey: SymmetricKey
    private var transmitCounter: UInt64 = 0
    private var receiveCounter: UInt64 = 0

    public enum Failure: Error {
        case counterExhausted
        case decryptionFailed
        case frameTooShort
    }

    /// - Parameters:
    ///   - sharedSecret: raw 32-byte X25519 output.
    ///   - salt: the server nonce, as UTF-8 bytes.
    ///   - info: channel label, e.g. `secretctl-admin-session-v1`.
    public init(sharedSecret: Data, salt: Data, info: Data) {
        let material = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: salt,
            info: info,
            outputByteCount: 64
        )
        let bytes = material.withUnsafeBytes { Data($0) }
        transmitKey = SymmetricKey(data: bytes.prefix(32))
        receiveKey = SymmetricKey(data: bytes.suffix(32))
    }

    private static func nonce(for counter: UInt64) throws -> ChaChaPoly.Nonce {
        var raw = Data(repeating: 0, count: 4)
        withUnsafeBytes(of: counter.bigEndian) { raw.append(contentsOf: $0) }
        return try ChaChaPoly.Nonce(data: raw)
    }

    public func encrypt(_ plaintext: Data) throws -> Data {
        let box = try ChaChaPoly.seal(
            plaintext,
            using: transmitKey,
            nonce: try Self.nonce(for: transmitCounter)
        )
        let (next, overflow) = transmitCounter.addingReportingOverflow(1)
        guard !overflow else { throw Failure.counterExhausted }
        transmitCounter = next
        return box.ciphertext + box.tag
    }

    public func decrypt(_ frame: Data) throws -> Data {
        guard frame.count >= 16 else { throw Failure.frameTooShort }
        let box = try ChaChaPoly.SealedBox(
            nonce: try Self.nonce(for: receiveCounter),
            ciphertext: frame.prefix(frame.count - 16),
            tag: frame.suffix(16)
        )
        let plaintext: Data
        do {
            plaintext = try ChaChaPoly.open(box, using: receiveKey)
        } catch {
            throw Failure.decryptionFailed
        }
        let (next, overflow) = receiveCounter.addingReportingOverflow(1)
        guard !overflow else { throw Failure.counterExhausted }
        receiveCounter = next
        return plaintext
    }
}
