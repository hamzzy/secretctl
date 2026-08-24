# secretctl Wire Protocol & IPC Specification

**Version:** 1.0  
**Transport:** Unix Domain Sockets (0600)  
**Framing:** 4-byte big-endian length prefix followed by UTF-8 encoded JSON-RPC 2.0.

---

## 1. Sockets & Access Control

| Socket | Permissions | Intended Clients | Allowed Operations |
|---|---|---|---|
| `~/.secretctl/run/agent.sock` | `0600` | AI Agents, SDKs, MCP | `action.request`, `action.status`, `action.cancel`, `session.hello` |
| `~/.secretctl/run/executor.sock` | `0600` | Native Host Bridge | `executor.prepare`, `executor.consume`, `executor.result`, `executor.heartbeat` |
| `~/.secretctl/run/admin.sock` | `0600` | CLI, Desktop UI | `admin.ping`, `approval.list`, `approval.decide`, `policy.reload` |

---

## 2. Agent Interface (`agent.sock`)

### `action.request`
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "action.request",
  "params": {
    "request_id": "req_8b31a19b-665e-4b2c-b26a-fa0329ebc419",
    "action": "authenticate.password",
    "identity": "github-work",
    "target": {
      "origin": "https://github.com:443",
      "path_prefix": "/login"
    },
    "browser_session_id": "bs_f4a19c0b",
    "tab_hint": 1,
    "reason": "Reviewing assigned pull requests",
    "wait": true,
    "timeout_ms": 30000
  }
}
```

#### Safe Agent Response (Zero Secrets)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "request_id": "req_8b31a19b-665e-4b2c-b26a-fa0329ebc419",
    "state": "capability_issued",
    "result_code": "CAPABILITY_ISSUED",
    "execution_id": "exec_19fba240",
    "evidence_ref": "cap:cap_5b138e02-f389-42b7-a3f2-ef6816cfbc39",
    "completed_at": null
  }
}
```

---

## 3. Executor Interface (`executor.sock`)

### `executor.consume`
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "executor.consume",
  "params": {
    "capability_token": "<COSE_Sign1 Ed25519 Token>",
    "session_signature": "<Extension Session Signature>",
    "current_context": {
      "browser_session_id": "bs_f4a19c0b",
      "tab_id": 1,
      "frame_id": 0,
      "document_id": "doc_18fab321",
      "navigation_epoch": 1,
      "top_origin": "https://github.com:443",
      "frame_origin": "https://github.com:443",
      "path": "/login",
      "path_sha256": "8a3f81b3...e91",
      "tls": true,
      "incognito": false
    }
  }
}
```

---

## 4. Capability Token Structure (COSE_Sign1)

Capabilities are encoded as signed COSE_Sign1 objects:
- **Algorithm:** EdDSA (Ed25519, alg `-8`)
- **Key ID:** `broker-key-v1`
- **Claims Array:**
  `[version, aud, jti, req_id, agent_id, cred_id, action, top_origin, frame_origin, browser_session_id, extension_key_id, tab_id, frame_id, document_id, navigation_epoch, recipe_id, recipe_hash, policy_hash, nbf, iat, exp, max_uses, issuer_key_id]`
