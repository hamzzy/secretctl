# M4 acceptance evidence — 2026-08-24

| Gate | Result | Evidence and next required environment |
|---|---|---|
| AT-12 | **Not yet a live pass** | Broker/extension/token/provider path is implemented and its secret-containment tests pass. A complete pass still needs a disposable OAuth client on a real HTTPS IdP in managed Chrome, followed by canary scans of process output, SQLite, audit output, traces, and agent objects. |
| AT-13 | **Implementation tests pass; live IdP run pending** | Tests reject wrong redirect, wrong state, duplicate callback, token-endpoint redirect status, insecure HTTP endpoint, and returned scope expansion. The live disposable-IdP attack matrix is still required for the release gate. |
| AT-21 | **Blocked in this host; not passed** | An isolated configuration and provider namespace completed `secretctl init`. The unsigned development daemon then blocked before creating its sockets when accessing its macOS Keychain items, so `secretctl doctor` and the five-minute packaged quickstart could not complete. Run from a signed/notarized package on a clean VM. |
| AT-33 | **Policy tests pass; native Linux run pending** | The platform rule rejects Linux high/critical risk with `user_presence_unavailable` and never selects weaker confirmation. A native Linux package run must confirm the RPC result and `security.presence_unavailable` audit event. |

Additional evidence:

- The installed-Chrome private DevTools pipe automation passed with the pinned
  extension and native host.
- Full macOS Rust workspace tests pass.
- Windows and Linux provider crates compile for their native Rust targets.
- Full foreign-target workspace builds are infrastructure-blocked on this Mac:
  no Windows SDK headers and no `x86_64-linux-gnu-gcc` are installed.

These statuses deliberately separate implementation/unit evidence from the
PRD's clean-machine and real-provider acceptance requirements.
