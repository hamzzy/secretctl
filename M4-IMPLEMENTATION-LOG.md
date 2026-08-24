# M4 implementation log

## Implemented

- Broker-owned OAuth Authorization Code + PKCE state, S256 challenge, exact
  callback binding, replay protection, scope validation, and zeroizing
  verifier/code/token buffers.
- Managed-Chrome executor integration. The extension navigates the capability-
  bound tab, observes only top-frame commits, rejects navigation outside the
  configured issuer, and forwards the exact callback through the authenticated
  native executor channel. Authorization codes never enter an agent response.
- HTTPS-only token exchange through rustls with redirects disabled, bounded
  timeout, response-status enforcement, and refusal of returned scope
  expansion.
- Provider-backed token grants. Token bytes are stored in the platform secret
  provider; SQLite and agent responses contain only the opaque grant ID,
  provider locator, scopes, and safe timestamps. Revocation deletes both the
  provider item and its metadata.
- macOS Keychain, Windows Credential Manager, and Linux Secret Service provider
  selection in the daemon, CLI, and native host. Windows and Linux providers
  fail closed when compiled on another platform.
- Windows WiX/MSI source plus Linux systemd, Debian, and RPM package metadata.
  Linux is explicitly limited to low/medium-risk actions. High/critical risk
  returns `user_presence_unavailable` and records
  `security.presence_unavailable` rather than silently downgrading.
- Browser automation covers the installed Chrome private DevTools pipe,
  pinned extension, native-host bridge, and OAuth navigation/callback logic.

## Verification on 2026-08-24

- `cargo test --workspace --all-targets`: passed on macOS.
- `cargo check --workspace`: passed on macOS.
- `cargo check -p secretctl-provider-windows --target
  x86_64-pc-windows-msvc`: passed.
- `cargo check -p secretctl-provider-linux --target
  x86_64-unknown-linux-gnu`: passed.
- The full Windows/Linux workspace cross-check reaches native C dependencies
  but cannot link from this macOS host because the Windows SDK and Linux GNU
  cross compiler are not installed. Native target CI remains required.
- The opt-in installed-Chrome private-pipe test passed against Google Chrome.
- TypeScript SDK, Python SDK, MCP adapter, and extension syntax checks passed.

## Acceptance status

Implementation coverage is not the same as a release acceptance pass. See
`M4-ACCEPTANCE-EVIDENCE.md` for the commands, evidence, and environmental
blockers. AT-12, AT-21, and the native-Linux portion of AT-33 still require
external environments; they are not marked passed here. M4 also cannot formally
exit until the PRD-required external security review has no open high or
critical findings.
