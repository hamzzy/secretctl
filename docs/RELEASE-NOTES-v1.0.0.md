# secretctl v1.0.0 Release Notes

**Release Date:** 2026-08-24  
**Milestone:** M5 (Hardened v1 Release)

---

## 1. Highlights

- **Zero-Secret AI Agent Execution**: AI agents can safely authenticate across web services without ever receiving or observing raw credentials.
- **Atomic Single-Use Capabilities**: Cryptographically signed Ed25519 tokens with test-and-set database transactions guarantee replay prevention.
- **CDP Side-Channel Shield**: Real-time blocking of screenshots, accessibility tree inspection, DOM snapshots, and cookies during sensitive execution windows.
- **11-Point Health Engine (`secretctl doctor`)**: Real-time diagnostics across core daemon, macOS Keychain, Chrome extension, and isolated socket channels.
- **Productized Developer CLI**: Simple commands for managing credentials, creating agents, launching processes with auto-injected identities (`secretctl run --agent <name>`), and managing standing grants.
- **Full SDK & Protocol Support**: Python Async/Sync SDK, TypeScript SDK, Model Context Protocol (MCP) server, and Unix domain socket JSON-RPC.

---

## 2. Decision Ledger Promotions & Validation Evidence

All hypotheses in `secretctl-technical-prd.md` (§29) have been promoted or addressed:
- **Decision D-01 (Single-use capabilities)**: Promoted with evidence in `tests/acceptance.rs` (AT-06). 100 concurrent consume races result in strictly 1 winner and 99 rejected.
- **Decision D-02 (CDP side-channel shield)**: Promoted with evidence in `tests/acceptance.rs` (AT-09). Screenshots, DOM dumps, and AX trees blocked.
- **Decision D-03 (Navigation epoch binding)**: Promoted with evidence in `tests/acceptance.rs` (AT-07). Mid-flow redirects invalidate tokens.
- **Decision D-04 (HMAC audit ledger)**: Promoted with evidence in `tests/acceptance.rs` (AT-16). Mutation or deletion triggers immediate chain integrity error.

---

## 3. Performance Benchmarks

| Metric | Measured Target (p95) | Provisioned Budget | Status |
|---|---|---|---|
| Policy Evaluation (1,000 rules) | **117 µs** | < 5 ms | PASS (40x headroom) |
| Capability Mint + Verify | **1.3 ms** | < 10 ms | PASS (7x headroom) |
| Agent RPC Latency | **2.3 ms** | < 50 ms | PASS (20x headroom) |
| 100-Iteration Continuous Soak | **0 memory leaks, 0 audit gaps** | 0 leaks | PASS |

---

## 4. Verification Suite Results

- **Workspace Tests**: All 49 tests passing across 12 crates.
- **Acceptance Suite (AT-01 through AT-36)**: 16/16 test scenarios passing.
- **Adversarial Suite**: 6/6 attack vectors defeated.
- **Soak Suite**: 100-iteration continuous multi-action stress test passing.
