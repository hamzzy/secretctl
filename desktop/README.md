# secretctl desktop

The macOS menu-bar control surface for `secretctld`.

This is a **client** of the security daemon, not the security system. It holds
no credential, no capability, and no policy. It renders what the daemon reports
and relays what you decide; the daemon re-verifies every decision on its own
terms. A compromised UI cannot authorize anything the broker would not have
authorized anyway.

## What it looks like in normal use

Nothing. A single menu-bar icon, and no window until a decision is actually
yours to make.

| Icon state | Meaning |
| --- | --- |
| Closed padlock | Protected — daemon healthy, nothing in flight |
| Padlock + `!` | A request is waiting for you |
| Padlock + bolt | A credential operation is running right now |
| Padlock + check | An operation just completed |
| Padlock + cross | A request was denied or a check failed closed |
| Severed shackle + `!` | Browser protection could not be verified — fail-closed |
| Open padlock + cross | `secretctld` is unreachable; sensitive operations disabled |

Icons are macOS template images: the shape carries the meaning, so the states
stay distinguishable in greyscale and under high-contrast settings.

## Build

```sh
npm install
npm run build          # frontend only
npm run tauri build    # full app bundle
npm run tauri dev      # development
```

Regenerate the icons after editing the generator:

```sh
python3 icons/generate.py
```

## Run at login

```sh
cp launchd/dev.secretctl.desktop.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.secretctl.desktop.plist
```

The daemon is a separate agent. A machine with no UI running is still
protected; a machine with no daemon running is not, which is why the app fails
closed rather than showing a stale healthy state.

## Layout

```
src/                     React frontend — a display layer, no authority
  api.ts                 The frontend's entire capability surface
  components/AgentText   The trusted/untrusted text boundary
  routes/Approval        The authorization ceremony
src-tauri/
  capabilities/          Everything JavaScript is permitted to do
  src/admin.rs           Authenticated client for admin.sock
  src/commands.rs        The narrow command surface
  src/presence.rs        LocalAuthentication, or an error
  src/watcher.rs         The only source of UI state
icons/generate.py        Reproducible menu-bar and app icons
```

## Design rules worth knowing before changing anything

**The frontend receives no secret material, ever.** Not a password, TOTP seed,
API key, capability token, or provider locator. The DTOs it consumes are
defined in `secretctl-protocol::admin`, and a test there walks the serialized
JSON of every UI payload asserting no forbidden field name appears at any depth.

**Agent-controlled text is a security boundary, not styling.** An agent writes
its own `reason`. Rendered plainly it could read as broker-verified chrome
("Verified by secretctl") and borrow the authority of the panel around it. All
such text goes through `AgentText`, which attributes, quotes, demotes, and
clamps it — with no prop to turn any of that off.

**Never claim a protection is active from UI state.** The popover lists only
protections the executor actually confirmed. When the broker cannot verify the
browser session, the panel says so rather than omitting the section; silence
would read as reassurance.

**The safe action holds focus.** The approval window opens with *Deny* focused,
never *Authorize*. A window that can appear while you are typing must not have a
credential authorization one Return away, and Escape dismisses without deciding
— the request stays pending.

**No process, shell, filesystem, or network permission.** See
`src-tauri/capabilities/default.json`. Restarting the daemon is deliberately not
a command: the Disconnected state shows you the CLI invocation instead of the
app acquiring authority to restart a security daemon.
