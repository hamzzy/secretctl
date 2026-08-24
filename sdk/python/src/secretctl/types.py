"""
secretctl Python SDK Types
Note: Secret-bearing fields (passwords, tokens, seeds, cookies) are intentionally excluded.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Literal

SecretAction = Literal[
    "authenticate.password",
    "authenticate.totp",
    "form.sensitive_fill",
    "oauth.authorize",
]


@dataclass(frozen=True)
class Target:
    origin: str
    path_prefix: Optional[str] = None


@dataclass(frozen=True)
class ExecuteRequest:
    action: SecretAction
    identity: str
    target: Target
    browser_session_id: str
    reason: str
    request_id: Optional[str] = None
    tab_hint: Optional[int] = None
    timeout_ms: int = 60000
    client_context: Optional[Dict[str, str]] = None


@dataclass(frozen=True)
class ExecuteResult:
    status: Literal["completed", "capability_issued", "denied", "expired", "cancelled", "failed"]
    request_id: str
    action: Optional[str] = None
    identity: Optional[str] = None
    verified_origin: Optional[str] = None
    browser_session_id: Optional[str] = None
    evidence_id: Optional[str] = None
    code: Optional[str] = None
    safe_message: Optional[str] = None
    completed_at: Optional[str] = None
