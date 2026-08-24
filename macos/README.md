# secretctl for macOS

A native menu-bar control surface for `secretctld`.

This is **not** the security authority and **not** a password manager. The Rust
broker decides everything; this app is where a human sees what is happening and
answers the questions the broker asks.

> Agents can use your credentials without possessing them.

---

## What this is

```text
 AI Agent ──agent.sock──▶ secretctld ──executor.sock──▶ Chrome executor ──▶ website
                              ▲
                              │ authenticated local IPC (admin.sock)
                              │
 Human ──────────────▶ secretctl.app (this)
```

The app is an accessory process: no Dock icon, no window at launch. It lives in
the menu bar, changes its glyph as the broker's protection state changes, and
raises a real window when an authorization decision is needed.

It is separate from, and does not replace, the Tauri build in `desktop/`. Both
speak the same admin RPC; nothing in this directory changes the daemon.

---

## The security boundary

The app never receives a password, TOTP seed, API key, private key, provider
locator, or capability token. It reads only the UI-safe projections the daemon
already produces in `secretctl_protocol::admin` — `UiAuthorizationRequest`,
`UiStatus`, `UiGrant` and friends — which the daemon's own tests assert are free
of secret-bearing fields.

Three rules hold throughout the code:

1. **The app decides nothing.** `Authorize once` calls `approval.decide` and the
   daemon independently re-validates the request, the echoed context digest and
   the presence claim. Nothing is marked approved locally.
2. **State is never inferred.** After any action the store re-reads from the
   daemon and displays what it now reports. An unreachable daemon shows
   `Disconnected`, never the last good status.
3. **Verified and agent-supplied text are drawn differently.** An agent controls
   its own `reason` string, so it is rendered as an attributed quotation with an
   explicit "not verified by secretctl" caption and can never impersonate system
   chrome.

The one secret the app *does* read is its own client credential: the
installation signing key in the login Keychain, used to authenticate to the
admin socket. That is the same key the CLI and the Tauri build use. It is held
only for the duration of a handshake and zeroed afterwards.

---

## The IPC client

`SecretctlKit` reimplements the broker handshake with CryptoKit rather than
linking the Rust crates, so the app has no Rust dependency at runtime:

| Step | Rust | Swift |
|---|---|---|
| Transcript hash | `compute_context_digest` | `ContextDigest` (SHA-256, `u64` BE length prefixes) |
| Broker identity | `ed25519-dalek` | `Curve25519.Signing` |
| Key exchange | `x25519-dalek` | `Curve25519.KeyAgreement` |
| Key schedule | `hkdf` + `Sha256` | `HKDF<SHA256>`, 64 bytes split tx/rx |
| Record layer | `chacha20poly1305` | `ChaChaPoly`, counter nonce, `ciphertext‖tag` |
| Framing | `LengthPrefixedCodec` | `UnixSocketConnection` (`u32` BE, 1 MiB cap) |

Two reimplementations of one protocol can drift silently, so they are pinned
against each other. `Tools/handshake-vectors` is a standalone Rust binary that
emits vectors from the **real** `secretctl-crypto` code — transcript digests,
an Ed25519 identity and signature, and actual `SecureChannel` frames — plus
serialized samples of every UI DTO. `SecretctlKitTests` asserts the Swift side
reproduces all of it byte for byte, including that the daemon's own frames
decrypt in order and that a replay is refused.

Regenerate them after any change to the crypto crate or the admin DTOs:

```bash
just vectors && just test
```

### The decision path, against a real broker

Vectors prove the transport; they cannot prove a decision. When the user
authorizes a request, the context digest the daemon issued travels back as
base64url → bytes → a JSON array of numbers → `serde`'s `Vec<u8>`, and the
daemon compares it with what it holds. A mistake anywhere on that chain does not
throw — the daemon simply reports the decision as invalidated and the credential
is never released.

`Tools/live-broker` therefore stands up a real `BrokerServer`, on a real admin
socket, in a throwaway installation directory, with real pending approvals
produced by the real policy path. `LiveDecisionTests` drives it through the
ordinary client: approve, deny, create a standing authorization, revoke it,
and confirm the broker refuses an approval that claims presence it does not
have. Nothing touches the user's own installation — directory, store and broker
identity are all per-test, and the broker identity comes from a seed the test
supplies rather than the Keychain, so the suite runs without a dialog.

```bash
just test-all    # builds the fixture, then runs everything
```

The live tests skip (rather than fail) when the fixture has not been built, so
cargo is not a prerequisite for `just test`.

---

## Building and running

Requires macOS 14+ and Xcode 16+ (Swift 6).

```bash
just test      # unit + cross-language vector tests
just app       # assemble build/secretctl.app (ad-hoc signed)
just run       # build and launch
just doctor    # verify the path to secretctld, step by step
```

The app is wrapped in a real bundle rather than run as a bare SwiftPM binary
because macOS ties several things to bundle identity: notifications refuse to
work without it, `SMAppService` cannot register a login item, and `LSUIElement`
is what keeps the app out of the Dock. Ad-hoc signing is enough for local use;
replace `--sign -` in `build-app.sh` with a Developer ID for distribution.

`secretctl-doctor` exists because a menu-bar accessory has nowhere to print. It
runs the identical client against the identical socket and reports each step, so
"not initialised", "daemon down", "key pin mismatch" and "Keychain refused" are
distinguishable instead of collapsing into one grey icon.

### The Keychain prompt on every rebuild

A code signature is part of a Keychain item's access control, and an ad-hoc
signature (`--sign -`) is different on every build. So macOS puts up an
authorisation dialog the first time each freshly built binary reads the
installation key, and **Always Allow** only holds until the next rebuild.

That is a local-development artefact, not a bug: sign with a stable Developer ID
and the ACL matches across builds, and the prompt happens once. Until then,
expect a dialog after `just app` — the app sits in `Connecting…` while it waits,
and `just doctor` announces the step before it blocks so a stall there is
legible rather than looking like a hang.

---

## Testing the decision path for real

The riskiest thing in this client is not the crypto — the vectors pin that. It
is the decision round-trip. When a person authorizes a request, the context
digest the daemon issued travels back as base64url → bytes → a JSON array of
numbers → `serde`'s `Vec<u8>`, and the daemon compares it against what it holds.
A mistake anywhere on that chain does not throw. The daemon simply records the
decision as invalidated and never releases the credential.

So `LiveDecisionTests` drives a real one. `Tools/live-broker` stands up an
actual `BrokerServer` on an actual admin socket, in a temp directory, with real
pending approvals produced by the real policy path, and the Swift client makes
real decisions against it:

- an approval is accepted, and the broker mints a capability
- an approval **claiming no presence on a request that demands it is refused**
- a denial is recorded and mints nothing
- a standing authorization is created from a verified approval, then revoked
- an approval cannot be decided twice
- the credentials screen shows a destination only once a grant exists

Nothing touches the user's installation: the directory, the SQLite store and the
broker identity are all per-test, and the client's key comes from
`SigningKeySource.fixed` rather than the Keychain, so the suite runs without a
dialog. `just test` builds the fixture first; `just test-swift` skips these if
you have no Rust toolchain.

### What this caught

`approval.decide` succeeds at the RPC level even when the broker *refuses* the
decision — a stale digest, a page that navigated, or a presence claim the daemon
does not accept all come back as a successful call reporting `denied`. The
approval window was treating "no error" as "authorized" and closing itself, so a
refused authorization would have looked to the user exactly like a granted one.
`BrokerAPI.approve` now returns the outcome and the window keeps itself open
with the real reason.

---

## Motion

How often a surface is seen decides whether it animates at all. The tokens live
in `Views/Motion.swift`; the reasoning is on the canvas's Motion page.

| Surface | Kind | Duration | Why |
|---|---|---|---|
| Menu-bar glyph | none | — | Watched passively and changes all day |
| Popover state swap | enter / exit | 180ms / 120ms | Exits are faster: the user decides on the way in, the system responds on the way out |
| Recent list | stagger | 220ms, 40ms apart | Decorative; rows are hit-testable from the first frame |
| Operation steps | move | 200ms | Morphs in place, so it takes the in-out curve |
| Press feedback | scale(0.97) | 160ms | Without it a custom control reads as not having heard the click |
| Expiry countdown | numeric | 200ms | Digits roll, and turn amber under 30s |
| Approval window | none | — | A reading surface for a security decision |

Entrances use `cubic-bezier(0.23, 1, 0.32, 1)`; things moving in place use
`cubic-bezier(0.77, 0, 0.175, 1)`. Nothing uses `ease-in` — withholding the
first frames is exactly wrong at the moment the eye is on the element. Nothing
enters from `scale(0)`. Reduce Motion keeps the opacity changes that aid
comprehension and drops every position change.

---

## User presence

`Presence` asks for Touch ID first when a finger is enrolled, so the sensor
sheet comes up immediately rather than a password field the user must dismiss
to reach it. It falls back to the login password when biometrics are absent,
unenrolled, locked out, or when the user picks "Use Password…". A Mac with no
sensor can still satisfy a presence requirement.

Presence is never the authorization. The daemon re-decides every request and
still refuses if it demanded presence and the app reports none, so the only
path that reports `true` is a completed `evaluatePolicy`. The context is fresh
per check with `touchIDAuthenticationAllowableReuseDuration = 0`, so an earlier
unlock can never stand in for this decision.

---

## Menu-bar states

Each state has a distinct silhouette, not just a distinct colour, and each
exposes a spoken description to VoiceOver.

| State | Glyph | Meaning |
|---|---|---|
| `protected` | `lock.shield.fill` | Daemon healthy, nothing in flight |
| `approval_required` | `person.fill.questionmark` | A request is waiting on you |
| `sensitive_operation` | `bolt.shield.fill` | A capability is being consumed now |
| `completed` | `checkmark.shield.fill` | Last operation succeeded |
| `blocked` | `xmark.shield.fill` | Denied, or a check failed closed |
| `protection_interrupted` | `exclamationmark.shield.fill` | Browser protection unverifiable; release halted |
| `outcome_uncertain` | `questionmark.diamond.fill` | Result could not be confirmed either way |
| `disconnected` | `shield.slash` | Daemon unreachable; operations disabled |

`completed` and `outcome_uncertain` are deliberately distinct. secretctl never
shows a success it cannot confirm.

---

## Notifications and privacy

Notifications are an attention mechanism, not the authorization boundary.
Nothing can be approved from one — the only action is **Review**, which opens
the trusted window.

Default content is privacy-preserving: *"Authorization request waiting. An agent
needs permission to perform a sensitive action."* No credential name, no
destination, no agent reason on the lock screen or during screen sharing.
Settings → Privacy can opt into naming the agent and destination.

---

## Layout

```text
macos/
├── Package.swift
├── build-app.sh                  # icon → SwiftPM binary → signed .app bundle
├── justfile
├── Resources/Info.plist          # LSUIElement, bundle identity
├── Sources/
│   ├── SecretctlKit/             # AppKit-free, unit-testable
│   │   ├── Crypto/               # digest, base64url, SecureChannel
│   │   ├── IPC/                  # socket, JSON-RPC, handshake, typed façade
│   │   └── Models/               # UI-safe DTOs, error translation
│   ├── SecretctlMenuBar/         # the app
│   │   ├── BrokerStore.swift     # the only source of UI truth
│   │   ├── AppDelegate.swift     # status item, popover, windows
│   │   └── Views/
│   └── SecretctlDoctor/          # console diagnostic
├── Tests/SecretctlKitTests/      # incl. cross-language vectors
└── Tools/handshake-vectors/      # Rust vector generator (standalone crate)
```

---

## Status

Phases 1–6 of the PRD are implemented: menu bar and popover, notifications and
the approval window, live operation and failure states, grants/agents/activity,
browser sessions/credentials/settings, and presence, privacy and accessibility.

Verified end to end against a live `secretctld`: Keychain read, broker key pin,
X25519 + Ed25519 handshake, encrypted channel, and every `ui.*`, `grant.*` and
`agent.*` call. See `just doctor`.

The decision path is exercised against a live broker: `approve`, `deny`,
`grant.create`, `grant.revoke`, deciding an approval twice, and the broker
refusing an approval that claims presence it does not have. See
`LiveDecisionTests`.

Not yet covered end to end: credential *execution* — capability consumption in a
real managed browser through the extension. That needs Chrome, the native host
and the executor socket, which the fixture deliberately does not stand up.
