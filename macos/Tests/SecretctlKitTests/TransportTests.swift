import Foundation
import Testing
@testable import SecretctlKit

/// Envelope handling and the framing cap.
struct TransportTests {
    @Test("A JSON-RPC error becomes a BrokerError carrying its code")
    func errorEnvelopeBecomesBrokerError() {
        let payload = Data(#"{"jsonrpc":"2.0","id":"1","error":{"code":-32007,"message":"origin mismatch"}}"#.utf8)
        #expect(throws: BrokerError(code: -32007, message: "origin mismatch")) {
            try AdminClient.unwrap(payload)
        }
    }

    @Test("A success envelope yields the result bytes with integers intact")
    func successEnvelopeKeepsIntegers() throws {
        let payload = Data(#"{"jsonrpc":"2.0","id":"1","result":{"sequence":9007199254740993,"limit":50}}"#.utf8)
        let result = try AdminClient.unwrap(payload)
        let text = String(decoding: result, as: UTF8.self)
        // Round-tripping through Double would corrupt this; JSONSerialization
        // preserves it.
        #expect(text.contains("9007199254740993"))
        #expect(!text.contains("50.0"))
    }

    @Test("An envelope with neither result nor error is rejected")
    func emptyEnvelopeIsRejected() {
        #expect(throws: AdminClient.Failure.self) {
            try AdminClient.unwrap(Data(#"{"jsonrpc":"2.0","id":"1"}"#.utf8))
        }
    }

    @Test("Oversized frames are refused before they are written")
    func oversizedFramesRefused() async {
        let connection = UnixSocketConnection()
        let payload = Data(repeating: 0, count: UnixSocketConnection.maxFrameBytes + 1)
        await #expect(throws: UnixSocketConnection.Failure.self) {
            try await connection.send(frame: payload)
        }
    }

    @Test("The installation directory follows the CLI's resolution rules")
    func installationPathsMatchTheCLI() {
        let directory = InstallationPaths.default.directory.path
        #expect(directory.hasSuffix("/secretctl"))
        #expect(InstallationPaths.default.adminSocket.path == directory + "/run/admin.sock")
        #expect(InstallationPaths.default.brokerPublicKey.path == directory + "/broker_key.pub")
    }
}
