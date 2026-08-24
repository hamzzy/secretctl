import Foundation

/// A length-prefixed frame transport over a Unix domain socket.
///
/// Mirrors `LengthPrefixedCodec`: a big-endian `u32` length followed by that
/// many bytes, capped at the daemon's 1 MiB agent-channel limit. The cap is
/// enforced on receive as well as send so a malformed length cannot make the
/// app allocate unboundedly.
///
/// The POSIX calls block, so every operation is hopped onto a private serial
/// queue and bridged back with a continuation. A receive timeout is set on the
/// socket: an unresponsive daemon must surface as `Disconnected` in the UI, not
/// as a spinner that never resolves.
/// `@unchecked Sendable` is justified by construction: every access to the
/// descriptor happens on `queue`, and nothing else is mutable.
public final class UnixSocketConnection: @unchecked Sendable {
    public static let maxFrameBytes = 1024 * 1024

    public enum Failure: Error {
        case connectFailed(String)
        case pathTooLong
        case closed
        case timedOut
        case frameTooLarge(Int)
        case io(String)
    }

    private var descriptor: Int32 = -1
    private let queue = DispatchQueue(label: "com.secretctl.menubar.socket")

    public init() {}

    deinit { if descriptor >= 0 { Darwin.close(descriptor) } }

    public func connect(path: String, timeout: TimeInterval = 5) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            queue.async {
                do {
                    try self.connectSync(path: path, timeout: timeout)
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func connectSync(path: String, timeout: TimeInterval) throws {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count < capacity else { throw Failure.pathTooLong }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.baseAddress!.copyMemory(from: pathBytes, byteCount: pathBytes.count)
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.connectFailed(String(cString: strerror(errno))) }

        var timeval = timeval(
            tv_sec: Int(timeout),
            tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000)
        )
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeval, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeval, socklen_t(MemoryLayout<timeval>.size))

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                Darwin.connect(fd, rebound, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let message = String(cString: strerror(errno))
            Darwin.close(fd)
            throw Failure.connectFailed(message)
        }
        descriptor = fd
    }

    public func send(frame: Data) async throws {
        guard frame.count <= Self.maxFrameBytes else { throw Failure.frameTooLarge(frame.count) }
        var payload = Data()
        withUnsafeBytes(of: UInt32(frame.count).bigEndian) { payload.append(contentsOf: $0) }
        payload.append(frame)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            queue.async {
                do {
                    try self.writeAll(payload)
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func receiveFrame() async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            queue.async {
                do {
                    let header = try self.readExactly(4)
                    let length = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
                    guard Int(length) <= Self.maxFrameBytes else {
                        throw Failure.frameTooLarge(Int(length))
                    }
                    continuation.resume(returning: try self.readExactly(Int(length)))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func close() {
        queue.sync {
            if descriptor >= 0 {
                Darwin.close(descriptor)
                descriptor = -1
            }
        }
    }

    // MARK: - Blocking primitives, always on `queue`

    private func writeAll(_ data: Data) throws {
        guard descriptor >= 0 else { throw Failure.closed }
        var offset = 0
        try data.withUnsafeBytes { buffer in
            while offset < data.count {
                let written = Darwin.write(descriptor, buffer.baseAddress!.advanced(by: offset), data.count - offset)
                if written > 0 {
                    offset += written
                    continue
                }
                if written < 0 && errno == EINTR { continue }
                if written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { throw Failure.timedOut }
                throw Failure.io(String(cString: strerror(errno)))
            }
        }
    }

    private func readExactly(_ count: Int) throws -> Data {
        guard descriptor >= 0 else { throw Failure.closed }
        guard count > 0 else { return Data() }
        var buffer = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let read = buffer.withUnsafeMutableBytes { pointer in
                Darwin.read(descriptor, pointer.baseAddress!.advanced(by: offset), count - offset)
            }
            if read > 0 {
                offset += read
                continue
            }
            if read == 0 { throw Failure.closed }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK { throw Failure.timedOut }
            throw Failure.io(String(cString: strerror(errno)))
        }
        return Data(buffer)
    }
}
