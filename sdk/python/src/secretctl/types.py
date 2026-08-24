"""Strict, agent-safe public models for the secretctl Python SDK."""

from typing import Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict

SecretAction = Literal[
    "authenticate.password",
    "authenticate.totp",
    "form.sensitive_fill",
    "oauth.authorize",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Target(StrictModel):
    origin: str
    path_prefix: Optional[str] = None


class ExecuteRequest(StrictModel):
    action: SecretAction
    identity: str
    target: Target
    browser_session_id: str
    reason: str
    request_id: Optional[str] = None
    tab_hint: Optional[int] = None
    timeout_ms: int = 60000
    client_context: Optional[Dict[str, str]] = None


class ExecuteResult(StrictModel):
    status: Literal[
        "completed", "capability_issued", "denied", "expired", "cancelled", "indeterminate", "revoked", "failed"
    ]
    request_id: str
    action: Optional[str] = None
    identity: Optional[str] = None
    verified_origin: Optional[str] = None
    browser_session_id: Optional[str] = None
    evidence_id: Optional[str] = None
    grant_id: Optional[str] = None
    code: Optional[str] = None
    safe_message: Optional[str] = None
    completed_at: Optional[str] = None


class ActionStatus(StrictModel):
    request_id: str
    state: str
    detail: Optional[str] = None


class SessionInfo(StrictModel):
    protocol_version: str
    principal_id: str
    role: Literal["agent"]
    rekey_after_seconds: int
