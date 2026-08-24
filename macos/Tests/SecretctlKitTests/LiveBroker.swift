import Foundation

/// A throwaway `secretctld` for the duration of one test.
///
/// Spawns `Tools/live-broker`, which stands up a real `BrokerServer` on a real
/// admin socket in a temp directory with real pending approvals on it. Nothing
/// here touches the user's own installation: the directory, the store and the
/// broker identity are all per-test.
final class LiveBroker {
    struct Ready: Decodable {
        let socket: String
        let agentName: String
        let credential: String
        let origin: String
        let approvals: [String]

        enum CodingKeys: String, CodingKey {
            case socket, credential, origin, approvals
            case agentName = "agent_name"
        }
    }

    let directory: URL
    let seed: Data
    let ready: Ready
    private let process: Process
    private var hasShutDown = false

    /// The fixture binary, built by `just live-fixture`. Absent when only the
    /// Swift side has been built, in which case the live tests skip rather than
    /// fail — cargo is not a prerequisite for `swift test`.
    static var binary: URL {
        packageRoot
            .appendingPathComponent("Tools/live-broker/target/debug/live-broker")
    }

    static var isAvailable: Bool {
        FileManager.default.isExecutableFile(atPath: binary.path)
    }

    static var packageRoot: URL {
        // .../Tests/SecretctlKitTests/LiveBroker.swift → package root
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    init(approvals: Int = 4) throws {
        // Deliberately short and shallow. A Unix socket path cannot exceed
        // ~104 bytes, and `NSTemporaryDirectory()` on macOS is already most of
        // that before the socket name is appended.
        let handle = UUID().uuidString.prefix(8).lowercased()
        directory = URL(fileURLWithPath: "/tmp/sctl-\(handle)")
        var seedBytes = Data(count: 32)
        seedBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        seed = seedBytes

        process = Process()
        process.executableURL = Self.binary
        process.arguments = [directory.path, seedBytes.map { String(format: "%02x", $0) }.joined(), String(approvals)]
        let output = Pipe()
        let errors = Pipe()
        process.standardOutput = output
        process.standardError = errors
        try process.run()

        // The fixture prints one JSON line once the socket is accepting.
        // Waiting for it rather than sleeping keeps the tests quick and makes a
        // failed start a clear error instead of a mystery timeout.
        var buffer = Data()
        let deadline = Date().addingTimeInterval(20)
        var parsed: Ready?
        while Date() < deadline {
            let chunk = output.fileHandleForReading.availableData
            if chunk.isEmpty && !process.isRunning { break }
            buffer.append(chunk)
            if let newline = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<newline]
                parsed = try? JSONDecoder().decode(Ready.self, from: Data(line))
                break
            }
        }
        guard let parsed else {
            // Without the fixture's own diagnostics a failure here is
            // unreadable: the interesting message is always on stderr.
            let diagnostics = String(decoding: errors.fileHandleForReading.availableData, as: UTF8.self)
            let stdout = String(decoding: buffer, as: UTF8.self)
            Self.stop(process)
            throw Failure.didNotStart("exit \(process.terminationStatus); stdout: \(stdout); stderr: \(diagnostics)")
        }
        ready = parsed

        // Keep both pipes drained for the rest of the fixture's life. A child
        // that fills a 64 KiB pipe buffer blocks on write and then never exits,
        // which turns `waitUntilExit()` below into a permanent hang.
        output.fileHandleForReading.readabilityHandler = { _ = $0.availableData }
        errors.fileHandleForReading.readabilityHandler = { _ = $0.availableData }
    }

    enum Failure: Error {
        case didNotStart(String)
    }

    func shutDown() {
        guard !hasShutDown else { return }
        hasShutDown = true
        (process.standardOutput as? Pipe)?.fileHandleForReading.readabilityHandler = nil
        (process.standardError as? Pipe)?.fileHandleForReading.readabilityHandler = nil
        Self.stop(process)
        try? FileManager.default.removeItem(at: directory)
    }

    /// Stop the fixture within a bounded time.
    ///
    /// `waitUntilExit()` waits forever, so a child that ignores SIGTERM hangs
    /// the whole test run rather than failing it. This escalates instead.
    private static func stop(_ process: Process) {
        guard process.isRunning else { return }
        process.terminate()
        let deadline = Date().addingTimeInterval(3)
        while process.isRunning && Date() < deadline {
            usleep(20_000)
        }
        if process.isRunning {
            kill(process.processIdentifier, SIGKILL)
            let hardDeadline = Date().addingTimeInterval(3)
            while process.isRunning && Date() < hardDeadline {
                usleep(20_000)
            }
        }
    }

    deinit {
        // `shutDown()` is the supported path; this only catches a test that
        // threw before reaching its `defer`.
        if !hasShutDown { Self.stop(process) }
    }
}
