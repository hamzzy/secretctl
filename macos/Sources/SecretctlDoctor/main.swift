import Foundation
import SecretctlKit

/// `secretctl-doctor` — verify the menu-bar app's path to the daemon.
///
/// The menu-bar app is an accessory with no console, so when it cannot reach
/// secretctld there is nowhere for it to explain why. This runs exactly the
/// same client against the same socket and prints each step, which makes the
/// difference between "not initialised", "daemon down", "key pin mismatch" and
/// "Keychain refused" visible instead of collapsing them all into a grey icon.
///
/// It reads only UI-safe projections — the same ones the app sees.

func step(_ label: String, _ detail: String? = nil, ok: Bool = true) {
    let mark = ok ? "✔" : "✘"
    print("\(mark) \(label)")
    if let detail { print("    \(detail)") }
    // Flushed so a step that then blocks — the Keychain prompt below is the
    // usual culprit — still shows where it got to.
    fflush(stdout)
}

/// Announce a step *before* running it, for anything that can block on a
/// system dialog the console gives no hint about.
func pending(_ label: String, _ detail: String? = nil) {
    print("… \(label)")
    if let detail { print("    \(detail)") }
    fflush(stdout)
}

func fail(_ label: String, _ error: Error) -> Never {
    let presentation = ErrorPresentation.describe(error)
    step(label, presentation.headline, ok: false)
    if let detail = presentation.detail { print("    \(detail)") }
    if let technical = presentation.technicalDetail { print("    \(technical)") }
    exit(1)
}

print("secretctl-doctor")
print("")

step("Installation directory", InstallationPaths.default.directory.path)

guard InstallationPaths.default.isInitialised else {
    step("Broker key pin", "Not found. Run `secretctl init` first.", ok: false)
    exit(1)
}
step("Broker key pin", InstallationPaths.default.brokerPublicKey.path)

guard FileManager.default.fileExists(atPath: InstallationPaths.default.adminSocket.path) else {
    step("Admin socket", "Not present. Is secretctld running?", ok: false)
    exit(1)
}
step("Admin socket", InstallationPaths.default.adminSocket.path)

// Reading the installation key can put up a Keychain authorisation dialog,
// and it does so every time the app's code signature changes — which, with the
// ad-hoc signature used for local builds, is every rebuild. Say so first, so a
// stall here is legible rather than a hang.
pending("Reading the installation key from the Keychain",
        "If macOS asks, choose Always Allow. An ad-hoc signed build re-prompts after every rebuild.")

do {
    var seed = try InstallationSigningKey.loadSeed()
    seed.resetBytes(in: 0..<seed.count)
    step("Installation key", "found in the login Keychain")
} catch {
    fail("Installation key", error)
}

let api = BrokerAPI()

do {
    let reachable = await api.ping()
    guard reachable else {
        step("Handshake", "admin.ping did not succeed.", ok: false)
        exit(1)
    }
    step("Handshake", "X25519 + Ed25519 pin verified, channel established")
}

do {
    let status = try await api.status()
    step("ui.status", "protection=\(status.protection.rawValue), pending=\(status.pendingApprovals), grants=\(status.activeGrants)")
    step("Providers", status.providers.isEmpty ? "none enrolled" : status.providers.joined(separator: ", "))
    step("Audit chain", status.auditChainIntact ? "verified" : "NOT verified", ok: status.auditChainIntact)
    step("Managed browsers", "\(status.browserSessionsConnected) connected")
} catch {
    fail("ui.status", error)
}

for (label, probe) in [
    ("ui.pending", { try await api.pending().count }),
    ("ui.agents", { try await api.agents().count }),
    ("ui.credentials", { try await api.credentials().count }),
    ("ui.browser_sessions", { try await api.browserSessions().count }),
    ("grant.list", { try await api.grants().count }),
    ("ui.activity", { try await api.activity(limit: 5).count }),
] as [(String, () async throws -> Int)] {
    do {
        step(label, "\(try await probe()) \(label == "ui.activity" ? "events" : "records")")
    } catch {
        fail(label, error)
    }
}

await api.disconnect()
print("")
print("All checks passed. The menu-bar app can reach secretctld.")
