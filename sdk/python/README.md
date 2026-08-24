# secretctl Python SDK

Agent-safe Python 3.11+ client for the local `secretctld` broker. The async
client is canonical; `SecretCtl` provides a synchronous wrapper backed by a
dedicated event-loop thread. Both clients require an enrolled agent principal
and reject secret-bearing or unknown response fields.
