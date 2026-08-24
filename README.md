# secretctl

**Local-first credential isolation and capability-based authentication for AI agents.**

> *An agent may be authorized to use a credential, but is never authorized to possess it.*

`secretctl` allows an AI agent to perform approved authentication actions (such as `authenticate.password`, `authenticate.totp`, `form.sensitive_fill`, and `oauth.authorize`) without exposing passwords, TOTP codes, session tokens, cookies, or sensitive form values in prompts, logs, LLM context, or tool responses.

---

## Architecture Overview

```text
 Untrusted Zone                                 Trusted Local Zone

 LLM / Agent / MCP Client
          |
          | Agent-Safe JSON-RPC (Zero secret fields)
          v
 +------------------+      OS-Authenticated IPC       +--------------------+
 | TS/Python SDK or | ------------------------------> | Rust Broker Daemon |
 | MCP Adapter      |                                 | Policy + Approval  |
 +------------------+                                 | Capabilities       |
                                                      | Audit + Sessions   |
                                                      +----+----------+----+
                                                           |          |
                                 Provider API (Keytar)     |          | Signed &
                                                           v          | Encrypted
                                                   +-------------+    | Executor Channel
                                                   | OS Keychain |    v
                                                   +-------------+ +------------------+
                                                                   | Rust Native Host |
                                                                   +--------+---------+
                                                                            |
                                                                 Chrome Native Messaging
                                                                            |
                                                                            v
                                                                   +------------------+
                                                                   | MV3 Extension    |
                                                                   | Session Verifier |
                                                                   | Field Executor   |
                                                                   +--------+---------+
                                                                            |
                                                                   Isolated-World Action
                                                                            v
                                                                   Approved Web Origin

 Agent Browser Commands ---> Rust Automation Gateway ---> Private Browser CDP Endpoint
                                      |
                                      +-- Denies/Redacts Secret-Bearing Introspection
```

---

## Core Security Invariants

1. **No Secret-Returning APIs:** No SDK, MCP tool, CLI output, or IPC response ever exposes plaintext credentials or session material to the agent.
2. **Broker Authority:** The local Rust broker is the sole authority for evaluating policy, registering approvals, issuing cryptographically signed single-use capabilities, and accessing the OS keychain.
3. **Exact Destination Binding:** Capabilities are strictly bound to canonical `(scheme, host, port)` tuples, tab navigation epochs, and managed browser sessions.
4. **Zero-Side-Channel Automation Gateway:** The agent interacts with managed browsers only through a filtered proxy that blocks DOM serialization, CDP introspection, and screen-scraping of sensitive inputs.
5. **Tamper-Evident Hash-Chained Audit Log:** Every request, decision, capability issuance, consumption, and secret access is recorded with append-only cryptographic hash chaining (`SHA-256`).

---

## Repository Structure

```text
secretctl/
├── Cargo.toml                         # Rust workspace definition
├── rust-toolchain.toml                # Pinned Rust toolchain
├── deny.toml                          # Cargo deny licenses/bans
├── justfile                           # Automation recipes
├── schemas/                           # Shared JSON schemas
│   ├── agent-rpc.schema.json
│   ├── executor-rpc.schema.json
│   ├── policy.schema.json
│   ├── recipe.schema.json
│   └── audit-event.schema.json
├── crates/
│   ├── secretctl-domain/              # Validated IDs, enums, state machines
│   ├── secretctl-protocol/            # Length-prefixed framing, JSON-RPC 2.0 DTOs
│   ├── secretctl-crypto/              # Ed25519 signatures, X25519, ChaCha20-Poly1305
│   ├── secretctl-policy/              # Policy parser, evaluator, risk engine
│   ├── secretctl-capability/          # Capability minting, verification, consumption
│   ├── secretctl-providers/           # SecretProvider trait & mock provider
│   ├── secretctl-audit/               # Append-only hash chain computation
│   ├── secretctl-store/               # SQLite metadata storage & migrations
│   ├── secretctl-browser-gateway/     # Managed browser launcher & proxy
│   ├── secretctl-native-host/         # Chrome Native Messaging executable
│   ├── secretctl-cli/                 # secretctl CLI binary
│   └── secretctld/                    # Daemon composition root
```

---

## Getting Started

### Prerequisites

- **Rust**: 1.85+ (Edition 2024)
- **Node.js**: v20+ (for extension and TypeScript SDK)
- **Python**: 3.11+ (for Python SDK)
- **just** (optional): Task runner

### Building the Project

```bash
cargo build --workspace --all-targets
```

### Running Tests

```bash
cargo test --workspace
```

---

## License

Apache-2.0
