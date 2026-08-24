import CryptoKit
import Foundation

/// Authenticated client for the `secretctld` admin socket.
///
/// This is the only path by which the menu-bar app reaches the broker, and it
/// performs the same handshake as the CLI: pin the broker's public key from
/// disk, require it to match the installation key held in the Keychain,
/// complete an X25519 exchange, then speak JSON-RPC inside a `SecureChannel`.
/// The daemon independently checks the peer UID against the socket owner before
/// any of this runs.
///
/// Nothing here decides anything. Every call is re-authorized by the daemon on
/// its own terms, so a reconnect mid-session is an ordinary operational event
/// rather than a security-relevant one.
public actor AdminClient {
    /// The daemon terminates an admin session at 600s. Renew well before that
    /// so expiry never surfaces as a failed user action.
    private static let sessionMaxAge: TimeInterval = 480
    private static let cryptoSuite = "X25519-HKDF-SHA256-CHACHA20POLY1305"
    private static let channelInfo = Data("secretctl-admin-session-v1".utf8)

    private struct Session {
        let connection: UnixSocketConnection
        let channel: SecureChannel
        let establishedAt: Date
        var nextID: UInt64

        var isExpiring: Bool { Date().timeIntervalSince(establishedAt) >= AdminClient.sessionMaxAge }
    }

    public enum Failure: Error, LocalizedError {
        case notInitialised
        case keyPinMismatch
        case handshakeRejected(String)
        case daemonUnavailable(String)
        case malformedResponse

        public var errorDescription: String? {
            switch self {
            case .notInitialised:
                return "secretctl is not set up on this Mac yet. Run `secretctl init` to create an installation."
            case .keyPinMismatch:
                return "The daemon's identity does not match the key this Mac has pinned. secretctl will not connect."
            case .handshakeRejected(let detail):
                return "secretctld refused the connection: \(detail)"
            case .daemonUnavailable(let detail):
                return "secretctld is not reachable: \(detail)"
            case .malformedResponse:
                return "secretctld sent a response secretctl could not read."
            }
        }
    }

    private var session: Session?
    private let paths: InstallationPaths
    private let keySource: SigningKeySource

    public init(paths: InstallationPaths = .default, keySource: SigningKeySource = .keychain) {
        self.paths = paths
        self.keySource = keySource
    }

    // MARK: - Calls

    /// Issue an admin RPC, connecting or reconnecting as needed.
    ///
    /// A transport failure rebuilds the session once and retries; a refusal
    /// from the broker is returned untouched, because the channel is healthy
    /// and the answer is "no".
    @discardableResult
    public func call(_ method: String, _ params: JSONValue = .object([:])) async throws -> Data {
        if session?.isExpiring == true { await teardown() }
        if session == nil { session = try await connect() }

        do {
            return try await perform(method, params)
        } catch let error as BrokerError {
            throw error
        } catch {
            await teardown()
            session = try await connect()
            return try await perform(method, params)
        }
    }

    public func call<T: Decodable>(_ method: String, _ params: JSONValue = .object([:]), as type: T.Type) async throws -> T {
        let payload = try await call(method, params)
        do {
            return try Self.decoder.decode(T.self, from: payload)
        } catch {
            throw Failure.malformedResponse
        }
    }

    /// Whether the daemon is answering right now. Drives the Disconnected
    /// state; never used to gate anything security-relevant.
    public func isReachable() async -> Bool {
        (try? await call("admin.ping")) != nil
    }

    public func disconnect() async { await teardown() }

    private func teardown() async {
        session?.connection.close()
        session = nil
    }

    private func perform(_ method: String, _ params: JSONValue) async throws -> Data {
        guard var live = session else { throw Failure.daemonUnavailable("no session") }
        let request = RpcRequest(id: String(live.nextID), method: method, params: params)
        live.nextID += 1
        session = live

        let body = try JSONEncoder().encode(request)
        try await live.connection.send(frame: try live.channel.encrypt(body))
        let wire = try await live.connection.receiveFrame()
        let plaintext = try live.channel.decrypt(wire)
        return try Self.unwrap(plaintext)
    }

    /// Split a JSON-RPC envelope into either a `BrokerError` or the raw bytes
    /// of `result`.
    ///
    /// `JSONSerialization` is used rather than a `Codable` round trip so that
    /// integers stay integers: re-encoding through `Double` would turn a `u64`
    /// sequence number into `7.0` and break decoding downstream.
    static func unwrap(_ data: Data) throws -> Data {
        guard let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Failure.malformedResponse
        }
        if let error = envelope["error"] as? [String: Any] {
            throw BrokerError(
                code: error["code"] as? Int ?? -32603,
                message: error["message"] as? String ?? "Unknown broker error"
            )
        }
        guard let result = envelope["result"] else { throw Failure.malformedResponse }
        return try JSONSerialization.data(withJSONObject: result, options: [.fragmentsAllowed])
    }

    // MARK: - Handshake

    private func connect() async throws -> Session {
        guard paths.isInitialised,
              let pinned = try? Data(contentsOf: paths.brokerPublicKey),
              pinned.count == 32
        else { throw Failure.notInitialised }

        let signingSeed = try keySource.loadSeed()
        var seed = signingSeed
        defer { seed.resetBytes(in: 0..<seed.count) }
        guard let signingKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else {
            throw InstallationSigningKey.Failure.malformed
        }
        // A daemon that cannot prove this identity is not talked to at all.
        guard signingKey.publicKey.rawRepresentation == pinned else { throw Failure.keyPinMismatch }

        let connection = UnixSocketConnection()
        do {
            try await connection.connect(path: paths.adminSocket.path)
        } catch {
            throw Failure.daemonUnavailable("the admin socket is not accepting connections")
        }

        var clientNonceBytes = Data(count: 24)
        clientNonceBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 24, $0.baseAddress!) }
        let clientNonce = Base64URL.encode(clientNonceBytes)

        let hello: JSONValue = .object([
            "protocol_version": .string("1.0"),
            "role": .string("admin"),
            "principal_id": .string("local-admin"),
            "client_nonce": .string(clientNonce),
            "supported_suites": .array([.string(Self.cryptoSuite)]),
        ])
        try await connection.send(frame: try JSONEncoder().encode(
            RpcRequest(id: "hello", method: "session.hello", params: hello)
        ))

        let helloWire = try await connection.receiveFrame()
        let helloResult: HelloResult
        do {
            helloResult = try Self.decoder.decode(HelloResult.self, from: try Self.unwrap(helloWire))
        } catch let error as BrokerError {
            connection.close()
            throw Failure.handshakeRejected(error.message)
        } catch {
            connection.close()
            throw Failure.handshakeRejected("the daemon rejected the admin hello")
        }

        guard let serverPublic = Base64URL.decode(helloResult.ephemeralPublicKey), serverPublic.count == 32,
              let serverSignature = Base64URL.decode(helloResult.signature)
        else {
            connection.close()
            throw Failure.handshakeRejected("the daemon sent a malformed ephemeral key")
        }

        let helloTranscript = ContextDigest.compute([
            Data("secretctl-session-hello-v1".utf8),
            Data(clientNonce.utf8),
            Data(helloResult.serverNonce.utf8),
            Data("local-admin".utf8),
            serverPublic,
        ])
        let pinnedKey = try Curve25519.Signing.PublicKey(rawRepresentation: pinned)
        guard pinnedKey.isValidSignature(serverSignature, for: helloTranscript) else {
            connection.close()
            throw Failure.keyPinMismatch
        }

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let clientPublic = ephemeral.publicKey.rawRepresentation
        let authTranscript = ContextDigest.compute([
            Data("secretctl-session-auth-v1".utf8),
            Data("1.0".utf8),
            Data("admin".utf8),
            Data("local-admin".utf8),
            Data(clientNonce.utf8),
            Data(helloResult.serverNonce.utf8),
            serverPublic,
            clientPublic,
        ])
        let signature = try signingKey.signature(for: authTranscript)

        try await connection.send(frame: try JSONEncoder().encode(RpcRequest(
            id: "auth",
            method: "session.authenticate",
            params: .object([
                "client_ephemeral_public_key": .string(Base64URL.encode(clientPublic)),
                "signature": .string(Base64URL.encode(signature)),
            ])
        )))

        let authWire = try await connection.receiveFrame()
        do {
            _ = try Self.unwrap(authWire)
        } catch let error as BrokerError {
            connection.close()
            throw Failure.handshakeRejected(error.message)
        }

        let peerKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublic)
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: peerKey)
        let channel = SecureChannel(
            sharedSecret: shared.withUnsafeBytes { Data($0) },
            salt: Data(helloResult.serverNonce.utf8),
            info: Self.channelInfo
        )
        return Session(connection: connection, channel: channel, establishedAt: Date(), nextID: 1)
    }

    private struct HelloResult: Decodable {
        let protocolVersion: String
        let serverNonce: String
        let ephemeralPublicKey: String
        let serverKeyID: String
        let signature: String

        enum CodingKeys: String, CodingKey {
            case protocolVersion = "protocol_version"
            case serverNonce = "server_nonce"
            case ephemeralPublicKey = "ephemeral_public_key"
            case serverKeyID = "server_key_id"
            case signature
        }
    }

    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let text = try decoder.singleValueContainer().decode(String.self)
            if let date = ISO8601DateFormatter.secretctlWithFractional.date(from: text) { return date }
            if let date = ISO8601DateFormatter.secretctlPlain.date(from: text) { return date }
            throw DecodingError.dataCorruptedError(
                in: try decoder.singleValueContainer(),
                debugDescription: "Unrecognised timestamp \(text)"
            )
        }
        return decoder
    }()
}

extension ISO8601DateFormatter {
    /// `chrono` serialises UTC timestamps with fractional seconds; older rows
    /// and checkpoints may not have them.
    static let secretctlWithFractional: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    static let secretctlPlain: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}
