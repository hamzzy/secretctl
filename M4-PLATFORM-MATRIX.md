# M4 platform and browser matrix

| Surface | Implemented state | Remaining release evidence |
|---|---|---|
| macOS Keychain | Platform provider wired into daemon, CLI, native host, OAuth grant storage/revocation | Signed/notarized clean-machine package and non-interactive daemon ACL validation |
| Windows Credential Manager | Dedicated provider crate, platform selection, and per-user WiX/MSI source; Windows target crate check passes | Native Windows package build, signing, install, `doctor`, and quickstart |
| Linux Secret Service | Dedicated provider crate, platform selection, systemd user unit, Debian control, and RPM spec; Linux target crate check passes | Native Ubuntu/Fedora package builds and live D-Bus Secret Service exercise |
| Linux presence | Low/medium risk may use explicit `confirm`; high/critical fails with `user_presence_unavailable` | Native Linux AT-33 run and audit inspection |
| Managed Chrome | Private CDP pipe, pinned extension, authenticated native host, bound OAuth redirect observer | Full OAuth run with a disposable HTTPS IdP/client |
| Chromium/Edge | Protocol path is Chromium-compatible | Native compatibility jobs and signed extension/package fixtures |
| OAuth exchange | Authorization Code + S256, exact callback, HTTPS-only rustls client, redirect refusal, scope containment | Live disposable IdP success/attack runs |

No unavailable provider or presence mechanism falls back to a plaintext file or
weaker confirmation.
