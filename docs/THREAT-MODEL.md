# secretctl Threat Model & Security Architecture

**Version:** 1.0.0  
**Status:** Approved  
**Scope:** V1 Release

---

## 1. Executive Summary & Security Guarantee

`secretctl` controls how AI agents use sensitive credentials without exfiltrating those credentials into agent context, prompt history, observable DOM state, or network inspection logs.

> [!IMPORTANT]
> **Core Guarantee (Credential Non-Exfiltration & Session Containment):**
> `secretctl` guarantees that an AI agent cannot observe, extract, or exfiltrate raw credentials (passwords, TOTP seeds, recovery codes, or OAuth client secrets) when authenticating against approved web destinations.
>
> **Limitations & Residual Risk Disclosure (AT-22):**
> `secretctl` does **not** protect against post-login application misuse if the destination origin itself is compromised, nor against a compromised host OS runtime where the user process or kernel is subverted. `secretctl` is not a replacement for backend RBAC or server-side authorization.

---

## 2. Trust Boundaries & Actors

```
┌────────────────────────────────────────────────────────┐
│ UNTRUSTED ZONE                                         │
│ • AI Agent Runtime (LLM, Python/Node Script, MCP)      │
│ • Web Page Scripts (Target Origin JavaScript, XSS)     │
└────────────────────────────────────────────────────────┘
                           │
            agent.sock (0600, JSON-RPC)
            Zero secret material returned
                           │
┌──────────────────────────▼─────────────────────────────┐
│ TRUSTED CONTROL PLANE                                  │
│ • secretctl broker daemon (secretctld)                 │
│ • Policy Engine (Rule matching, risk ceiling)          │
│ • SQLite Store & HMAC Audit Ledger                     │
│ • Platform Secret Provider (macOS Keychain / Vault)    │
└────────────────────────────────────────────────────────┘
                           │
           executor.sock (0600, Native Host)
           Single-use signed Ed25519 token
                           │
┌──────────────────────────▼─────────────────────────────┐
│ TRUSTED ISOLATED EXECUTION PLANE                       │
│ • Chrome Extension Isolated World (executor.js)        │
│ • Direct DOM Prototype Setter Injection                │
│ • CDP Shield (Blocks screenshots/DOM/AX/cookies)       │
└────────────────────────────────────────────────────────┘
```

---

## 3. STRIDE Threat Analysis & Mitigations

| Threat Category | Potential Attack Vector | secretctl Mitigation |
|---|---|---|
| **Spoofing** | Unenrolled agent attempts credential request | Broker enforces Ed25519 principal enrollment and Unix peer UID verification. Unregistered agents fail closed (`SECURITY_VIOLATION`). |
| **Tampering** | Phishing site redirects tab after approval | Navigation epoch measurement: if epoch changes between issuance and consume, broker rejects with `EPOCH_INVALIDATED`. |
| **Repudiation** | Malicious actor deletes audit records to hide activity | Tamper-evident HMAC hash chain with sequence numbering and Ed25519 signed checkpoints. Mutation or deletion is detected by `secretctl audit verify`. |
| **Information Disclosure** | Agent inspects DOM or requests screenshots via CDP | Isolated world execution with DOM setter injection (`HTMLInputElement.prototype.value.set.call`); CDP side-channel blocker denies screenshots, DOM snapshots, AX trees, and cookie dumps during sensitive windows. |
| **Denial of Service** | Concurrent replay race on single-use capability | Atomic test-and-set database transaction. 100 parallel consume requests yield strictly 1 success and 99 `CAPABILITY_CONSUMED` rejections. |
| **Elevation of Privilege** | Agent requests high-risk action with auto-approval | Risk ceiling invariant: high-risk actions always require verified local user presence (`USER_PRESENCE_REQUIRED`). Standing grants cannot auto-approve above medium risk. |

---

## 4. Residual Risks & Out-of-Scope Items

1. **Host-Level Root/Kernel Compromise**: If an attacker achieves kernel or root execution on the host machine, OS-level protections (Keychain access, memory isolation) are superseded.
2. **Approved Destination In-Page Exploits**: Once logged in, if the target website possesses vulnerable in-page endpoints, malicious post-login agent actions are bounded by application authorization, not credential layer controls.
3. **Hardware Keystroke Loggers**: Hardware loggers intercepting physical keyboard input during initial user setup.
