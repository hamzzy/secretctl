# secretctl Python SDK

Agent-safe Python 3.11+ client for the local `secretctld` broker. The async
client is canonical; `SecretCtl` provides a synchronous wrapper backed by a
dedicated event-loop thread. Both clients require an enrolled agent principal
and reject secret-bearing or unknown response fields.

The async and synchronous clients expose the same broker-routed browser
surface: tabs, navigation, reload, back/forward, click, public typing, public
select, bounded redacted text, safe structural snapshots, and bounded waits.
`authenticate(credential, reason)` asks the broker to resolve the single fresh
managed page and permitted credential action; zero or ambiguous matches fail
closed. `subscribe()` uses the broker's `action.subscribe` long-poll RPC rather
than polling `action.status` in the agent process.

There is intentionally no screenshot API. A screenshot is not agent-safe until
image-level redaction is independently implemented and adversarially verified.
