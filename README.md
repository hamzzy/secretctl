# secretctl

**Give AI agents access to your accounts, not your passwords.**

`secretctl` is an agent credential execution and security layer. It sits between AI agents, your local credentials (macOS Keychain, Linux Secret Service, Windows Credential Manager), and the browser—allowing autonomous agents to authenticate and perform sensitive web actions without ever observing raw credentials in prompts, logs, LLM context, or tool calls.

---

## Why secretctl?

Traditional password managers store and retrieve secrets for humans. If an AI agent asks for a password or TOTP code to log in, handing the secret directly to the agent leaks it into LLM context windows, provider API logs, prompt histories, and tool trace recordings.

`secretctl` changes the paradigm: **agents receive authorization to use a credential, never possession of the credential itself.**

```text
               AI AGENT
                  │
                  │ "authenticate github-work" (JSON-RPC over agent.sock)
                  ▼
      ┌───────────────────────┐
      │       secretctl       │
      │                       │
      │ • Agent Verification  │
      │ • Policy & Grants     │
      │ • Interactive Prompt  │
      │ • Capability Issuance │
      │ • Origin Verification │
      │ • Tamper-Evident Logs │
      └───────────┬───────────┘
                  │
     Single-Use Signed Capability
                  │
                  ▼
      ┌───────────────────────┐       Isolated Injection       ┌────────────────────────┐
      │    Chrome Extension   │ ─────────────────────────────► │   https://github.com   │
      │   Isolated Executor   │    (DOM setter injection;      │   (Target Login Page)  │
      │  (CDP side-channel    │     screenshots / DOM / AX     └────────────────────────┘
      │   shield active)      │     blocked during window)
      └───────────────────────┘
```

---

## Quickstart

### 1. Install and verify runtime health

```bash
# Build the binary workspace
cargo build --release

# Run security diagnostic matrix
secretctl doctor
```

Output:
```text
secretctl doctor
Core daemon              ✓
macOS Keychain           ✓
Chrome extension         ✓ (pinned identity)
Executor channel         ✓
Agent channel            ✓
Browser origin checks    ✓
Sensitive mode           ✓ (fail closed)
CDP filtering            ✓ (private pipe)
Capability signing       ✓
Capability replay        ✓
Audit redaction          ✓
Security boundary        HEALTHY
```

### 2. Store a credential

```bash
secretctl credential add github-work --origin https://github.com
```

### 3. Enroll an agent

```bash
secretctl agent create my-agent
```

### 4. Run an agent with automatic identity injection

```bash
secretctl run --agent my-agent python agent.py
```

---

## SDK Usage

### Python SDK

```bash
pip install secretctl
```

```python
import asyncio
from secretctl import AsyncSecretCtl

async def main():
    # Connects automatically using SECRETCTL_AGENT_ID / SECRETCTL_SOCKET
    client = await AsyncSecretCtl.connect()

    # Request browser authentication on current tab
    result = await client.authenticate(
        credential="github-work",
        reason="Logging in to review pull requests"
    )

    if result.is_ok():
        print(f"Authenticated successfully (evidence: {result.evidence_ref})")
    else:
        print(f"Authentication failed: {result.safe_message}")

asyncio.run(main())
```

### TypeScript SDK

```bash
npm install @secretctl/sdk
```

```typescript
import { SecretCtlClient } from "@secretctl/sdk";

async function main() {
  const client = await SecretCtlClient.connect();

  const result = await client.authenticate({
    credential: "github-work",
    reason: "Logging in to check notifications",
  });

  if (result.success) {
    console.log(`Authenticated: ${result.evidenceRef}`);
  } else {
    console.error(`Failed: ${result.error?.message}`);
  }
}

main();
```

---

## Core Security Invariants

1. **Zero Plaintext Credential Egress**: No API, socket, SDK, or MCP endpoint returns plaintext passwords, TOTP seeds, or session cookies to the agent.
2. **Single-Use Signed Capabilities**: Capabilities are signed Ed25519 tokens consumed atomically via test-and-set database transactions (`CAPABILITY_CONSUMED` fail-closed).
3. **Strict Origin & Navigation Epoch Binding**: Capabilities are bound to exact canonical `https://host:port` origins and tab navigation epochs. Any off-graph redirect invalidates in-flight execution.
4. **CDP Side-Channel Shield**: During sensitive fill execution, screenshots (`Page.captureScreenshot`), accessibility trees (`Accessibility.getFullAXTree`), DOM snapshots (`DOMSnapshot.captureSnapshot`), and cookies (`Network.getAllCookies`) are blocked in real-time.
5. **Tamper-Evident Audit Ledger**: Every action request, policy decision, capability issuance, consumption, and secret access is chained in an append-only HMAC SHA-256 ledger with signed checkpoints.

---

## CLI Reference

| Command | Description |
|---|---|
| `secretctl doctor` | Runs the 11-point security matrix and daemon health check |
| `secretctl credential add <name> --origin <url>` | Stores a credential in the platform keychain bound to an origin |
| `secretctl credential list` | Lists registered credentials (metadata only; no secret values) |
| `secretctl agent create <name>` | Enrolls an AI agent identity and generates Ed25519 keypair |
| `secretctl run --agent <name> <cmd>` | Executes a command with agent environment variables pre-configured |
| `secretctl grants` | Displays active standing authorizations and usage metrics |
| `secretctl revoke <credential>` | Revokes standing authorization for a credential or agent |
| `secretctl logs [--limit N]` | Views sanitized, tamper-evident audit logs |
| `secretctl backup --output <path>` | Creates a consistent SQLite database backup |
| `secretctl restore --from <path>` | Restores the database from a backup snapshot |

---

## Repository Structure

```text
secretctl/
├── crates/
│   ├── secretctl-core/              # Core domain types, IDs, and primitives
│   ├── secretctl-crypto/            # Ed25519 signing, ChaCha20-Poly1305, TOTP generator
│   ├── secretctl-domain/            # Domain models (Credentials, Capabilities, Recipes)
│   ├── secretctl-protocol/          # Length-prefixed Unix socket JSON-RPC 2.0 framing
│   ├── secretctl-policy/            # Rule evaluator and risk engine
│   ├── secretctl-capability/        # COSE_Sign1 capability minting and verification
│   ├── secretctl-providers/         # SecretProvider traits (macOS, Linux, Windows, Memory)
│   ├── secretctl-audit/             # Tamper-evident HMAC hash chain and checkpoints
│   ├── secretctl-store/             # SQLite migrations, grants, and audit storage
│   ├── secretctl-browser-gateway/   # Filtered CDP transport and browser launcher
│   ├── secretctl-native-host/       # Chrome Native Messaging bridge executable
│   ├── secretctl-cli/               # Developer and admin CLI binary
│   └── secretctld/                  # Background security broker daemon
├── extension/                       # Chrome Manifest V3 extension & isolated executor
├── macos/                           # Native macOS Menu Bar companion app
├── sdk/
│   ├── python/                      # Python Async/Sync client library
│   └── typescript/                  # TypeScript / Node.js client library
└── integrations/
    └── mcp/                         # Model Context Protocol (MCP) server
```

---

## Building and Testing

### Prerequisites

- **Rust**: 1.85+ (Edition 2024)
- **Python**: 3.11+ (for Python SDK)
- **Node.js**: 20+ (for Extension and TypeScript SDK)

### Build All Crates

```bash
cargo build --workspace --all-targets
```

### Run Test Suites

```bash
# Run all workspace unit and integration tests
cargo test --all-targets

# Run the acceptance test suite
cargo test --test acceptance

# Run the adversarial attack verification suite
cargo test --test adversarial

# Run the soak and stress benchmarks
cargo test --test soak
```

---

## License

Apache-2.0
