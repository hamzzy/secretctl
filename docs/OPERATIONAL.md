# secretctl Operational Runbook & Production Guide

This guide describes operational management, deployment, upgrade, backup, disaster recovery, and incident response for `secretctl`.

---

## 1. Architecture & Security Kernel

`secretctl` operates with strict boundary separation across isolated execution planes:

```
[ AI Agent ] (untrusted)
     │
     │ agent.sock (0600, action requests only; zero secret fields returned)
     ▼
[ secretctl broker (secretctld) ] ◄── admin.sock (0600, authenticated admin IPC)
     │
     ├── macOS Keychain / Platform Vault (secure storage)
     │
     │ executor.sock (0600, native-messaging bridge only)
     ▼
[ Chrome Isolated World Executor ] ── (DOM prototype setter injection) ──► [ Target Login Page ]
```

### Invariants
1. **Zero Secret Leakage to Agents**: Agent responses return `{ state: "capability_issued", request_id, evidence_ref }`. No password, seed, token, or cookie is ever returned to an agent.
2. **Atomic Single-Use Capabilities**: Capabilities are signed Ed25519 tokens consumed atomically via SQLite immediate transaction (`CAPABILITY_CONSUMED` fail-closed).
3. **Strict Origin Binding**: Origins are canonicalized (`https://host:port`) and measured by the browser extension. Navigation epoch mismatches or redirects abort execution (`EPOCH_INVALIDATED`).
4. **CDP Side-Channel Denial**: Screenshots (`Page.captureScreenshot`), accessibility trees (`Accessibility.getFullAXTree`), DOM snapshots (`DOMSnapshot.captureSnapshot`), and cookies (`Network.getAllCookies`) are blocked during sensitive windows.

---

## 2. Health Monitoring & Diagnostics

Run `secretctl doctor` to inspect the 11-point security and runtime health matrix:

```bash
secretctl doctor
```

Output:
```
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

---

## 3. Database Backup & Disaster Recovery

`secretctl` uses SQLite with WAL mode (`journal_mode=WAL`) and provides transactional online backups:

### Create Snapshot Backup
```bash
secretctl backup --output ~/.secretctl/backups/secretctl_$(date +%Y%m%d_%H%M%S).db
```

### Restore from Backup
```bash
# 1. Stop background daemon
secretctl stop

# 2. Restore database from consistent snapshot
secretctl restore --from ~/.secretctl/backups/secretctl_20260824_120000.db

# 3. Verify audit integrity and restart
secretctl audit verify
secretctl start
```

---

## 4. Key Rotation Runbook

When rotating signing keys or audit HMAC keys:

```bash
# 1. Stop daemon
secretctl stop

# 2. Execute atomic key rotation
secretctl keys rotate

# 3. Restart daemon
secretctl start

# 4. Verify doctor status
secretctl doctor
```

Key rotation creates a signed audit checkpoint pinning the previous log sequence, retires the old Ed25519 signing key, securely registers the new key in the platform keychain, and increments the HMAC key version.

---

## 5. Standing Grants & Revocation

Standing grants allow approved human-in-the-loop workflows without approval fatigue:

### View Active Grants
```bash
secretctl grants
```

### Revoke Grants
```bash
# Revoke by credential name:
secretctl revoke github-work

# Revoke all grants for a specific agent:
secretctl revoke --agent claude
```

---

## 6. Incident Response: Audit Gaps & Reconciliation

If an unexpected system crash occurs during sensitive execution:
- Executions pending without result reporting are classified as `indeterminate` or `completed_evidence_lost`.
- The broker never resends secrets on restart.
- An incident event `action.indeterminate` is recorded in the HMAC-sealed audit ledger.
- The administrator can inspect and verify audit logs:

```bash
secretctl logs --limit 100
secretctl audit verify
```
