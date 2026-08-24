import asyncio
import base64
import hashlib
import json
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import AsyncIterator, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .framing import AsyncLengthPrefixedSocket
from .types import (
    ActionStatus, BrowserTab, ExecuteRequest, ExecuteResult, PageTextResult,
    SafePageSnapshot, SessionInfo, Target,
)

SUITE = "X25519-HKDF-SHA256-CHACHA20POLY1305"
PROHIBITED_RESPONSE_KEYS = (
    "password", "secret", "token", "seed", "cookie", "authorization",
    "private_key", "refresh_token", "access_token", "capability_token",
)
KNOWN_ERROR_CODES = {
    "AUTH_POLICY_DENIED", "APPROVAL_REJECTED", "APPROVAL_TIMEOUT",
    "CAPABILITY_EXPIRED", "CAPABILITY_CONSUMED", "EPOCH_INVALIDATED",
    "ORIGIN_MISMATCH", "FRAME_VIOLATION", "SESSION_TERMINATED",
    "EXECUTOR_FAILED", "RECIPE_NOT_FOUND", "USER_PRESENCE_UNAVAILABLE", "SECURITY_VIOLATION", "INTERNAL_ERROR",
}
ERROR_CODES = {
    -32001: "AUTH_POLICY_DENIED", -32002: "APPROVAL_REJECTED",
    -32003: "APPROVAL_TIMEOUT", -32004: "CAPABILITY_EXPIRED",
    -32005: "CAPABILITY_CONSUMED", -32006: "EPOCH_INVALIDATED",
    -32007: "ORIGIN_MISMATCH", -32008: "FRAME_VIOLATION",
    -32009: "SESSION_TERMINATED", -32010: "EXECUTOR_FAILED",
    -32011: "RECIPE_NOT_FOUND", -32012: "USER_PRESENCE_UNAVAILABLE",
    -32099: "SECURITY_VIOLATION",
}


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _context_digest(parts: list[bytes]) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _assert_agent_safe(value: object) -> None:
    if isinstance(value, list):
        for item in value:
            _assert_agent_safe(item)
    elif isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            if any(part in normalized for part in PROHIBITED_RESPONSE_KEYS):
                raise ValueError("secretctl rejected an unsafe broker response")
            _assert_agent_safe(child)


def _parse_execute_result(result: object, request: ExecuteRequest) -> ExecuteResult:
    if not isinstance(result, dict) or not isinstance(result.get("request_id"), str):
        raise ValueError("Invalid action response shape")
    state = result.get("state")
    if not isinstance(state, str):
        raise ValueError("Invalid action response state")
    common = dict(
        request_id=result["request_id"], action=request.action, identity=request.identity,
        verified_origin=request.target.origin, browser_session_id=request.browser_session_id,
        evidence_id=result.get("evidence_ref"), grant_id=result.get("grant_id"),
        completed_at=result.get("completed_at"),
    )
    if state in {"completed", "capability_issued"}:
        return ExecuteResult(status=state, **common)
    if state in {
        "denied", "expired", "cancelled", "indeterminate", "completed_evidence_lost",
        "revoked", "failed",
    }:
        candidate = result.get("result_code")
        code = candidate if isinstance(candidate, str) and candidate in KNOWN_ERROR_CODES else "INTERNAL_ERROR"
        return ExecuteResult(
            status=state, request_id=common["request_id"],
            code=code if isinstance(code, str) else state.upper(),
            safe_message=(
                "The action may have completed. Do not retry automatically."
                if state in {"completed_evidence_lost", "indeterminate"}
                else f"Action ended in {state}"
            ),
            retryable=state not in {"completed_evidence_lost", "indeterminate", "revoked"},
            evidence_id=common["evidence_id"],
        )
    raise ValueError("Unknown action response state")


class _SecureChannel:
    def __init__(self, shared_secret: bytes, salt: bytes):
        material = HKDF(
            algorithm=hashes.SHA256(), length=64, salt=salt,
            info=b"secretctl-agent-session-v1",
        ).derive(shared_secret)
        self._tx = ChaCha20Poly1305(material[:32])
        self._rx = ChaCha20Poly1305(material[32:])
        self._tx_counter = 0
        self._rx_counter = 0

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\0" * 4 + counter.to_bytes(8, "big")

    def encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = self._tx.encrypt(self._nonce(self._tx_counter), plaintext, None)
        self._tx_counter += 1
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = self._rx.decrypt(self._nonce(self._rx_counter), ciphertext, None)
        self._rx_counter += 1
        return plaintext


class SecretCtlRpcError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AsyncSecretCtl:
    def __init__(
        self,
        principal_id: str,
        socket_path: str,
        broker_public_key_path: str,
        signing_key_path: Optional[str],
        cli_path: str,
    ):
        self.principal_id = principal_id
        self.socket_path = socket_path
        self.broker_public_key_path = broker_public_key_path
        self.signing_key_path = signing_key_path
        self.cli_path = cli_path
        self.socket: Optional[AsyncLengthPrefixedSocket] = None
        self.channel: Optional[_SecureChannel] = None
        self._connected_at = 0.0
        self._rpc_lock = asyncio.Lock()

    @classmethod
    async def connect(
        cls,
        principal_id: Optional[str] = None,
        socket_path: Optional[str] = None,
        broker_public_key_path: Optional[str] = None,
        signing_key_path: Optional[str] = None,
        cli_path: Optional[str] = None,
    ) -> "AsyncSecretCtl":
        config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        principal = principal_id or os.environ.get("SECRETCTL_PRINCIPAL_ID")
        if not principal:
            raise ValueError("secretctl agent principal is required; launch under secretctl run")
        client = cls(
            principal,
            socket_path or str(Path(config_home) / "secretctl/run/agent.sock"),
            broker_public_key_path or str(Path(config_home) / "secretctl/broker_key.pub"),
            signing_key_path,
            cli_path or os.environ.get("SECRETCTL_CLI_PATH", "secretctl"),
        )
        await client._establish()
        return client

    async def _sign(self, digest: bytes) -> bytes:
        if self.signing_key_path:
            seed = await asyncio.to_thread(Path(self.signing_key_path).read_bytes)
            if len(seed) != 32:
                raise ValueError("Invalid agent signing key")
            return Ed25519PrivateKey.from_private_bytes(seed).sign(digest)

        def invoke_signer() -> bytes:
            completed = subprocess.run(
                [self.cli_path, "agent", "sign", "--digest", _b64url_encode(digest)],
                check=True, capture_output=True, text=True, env=os.environ.copy(),
            )
            return _b64url_decode(completed.stdout.strip())

        return await asyncio.to_thread(invoke_signer)

    async def _establish(self) -> None:
        if self.socket is not None:
            try:
                await self.socket.close()
            except (ConnectionError, OSError):
                pass
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        self.socket = AsyncLengthPrefixedSocket(reader, writer)
        self.channel = None
        client_nonce = str(uuid.uuid4())
        hello = await self._exchange(
            "session.hello",
            {
                "protocol_version": "1.0", "role": "agent",
                "principal_id": self.principal_id, "client_nonce": client_nonce,
                "supported_suites": [SUITE],
            },
            encrypted=False,
        )
        if not isinstance(hello, dict) or hello.get("protocol_version") != "1.0":
            raise ValueError("Invalid broker handshake")
        public_key = await asyncio.to_thread(Path(self.broker_public_key_path).read_bytes)
        if len(public_key) != 32:
            raise ValueError("Invalid broker public key")
        server_public = _b64url_decode(str(hello["ephemeral_public_key"]))
        server_nonce = str(hello["server_nonce"])
        transcript = _context_digest([
            b"secretctl-session-hello-v1", client_nonce.encode(), server_nonce.encode(),
            self.principal_id.encode(), server_public,
        ])
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _b64url_decode(str(hello["signature"])), transcript
        )
        ephemeral = X25519PrivateKey.generate()
        client_public = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        auth_transcript = _context_digest([
            b"secretctl-session-auth-v1", b"1.0", b"agent",
            self.principal_id.encode(), client_nonce.encode(), server_nonce.encode(),
            server_public, client_public,
        ])
        authenticated = await self._exchange(
            "session.authenticate",
            {
                "client_ephemeral_public_key": _b64url_encode(client_public),
                "signature": _b64url_encode(await self._sign(auth_transcript)),
            },
            encrypted=False,
        )
        if not isinstance(authenticated, dict) or not authenticated.get("authenticated"):
            raise ValueError("Agent authentication rejected")
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(server_public))
        self.channel = _SecureChannel(shared, server_nonce.encode())
        self._connected_at = time.monotonic()

    async def _exchange(self, method: str, params: dict, *, encrypted: bool) -> object:
        if self.socket is None:
            raise ConnectionError("secretctl transport is not connected")
        request = {
            "jsonrpc": "2.0", "id": f"rpc_{uuid.uuid4()}",
            "method": method, "params": params,
        }
        payload = json.dumps(request, separators=(",", ":")).encode()
        if encrypted:
            if self.channel is None:
                raise ConnectionError("secretctl secure channel is unavailable")
            payload = self.channel.encrypt(payload)
        await self.socket.send(payload)
        response_payload = await self.socket.read_next()
        if encrypted:
            if self.channel is None:
                raise ConnectionError("secretctl secure channel is unavailable")
            response_payload = self.channel.decrypt(response_payload)
        response = json.loads(response_payload.decode())
        _assert_agent_safe(response)
        if not isinstance(response, dict):
            raise ValueError("Invalid secretctl response")
        if response.get("error"):
            error = response["error"]
            raise SecretCtlRpcError(
                ERROR_CODES.get(int(error.get("code", 0)), "INTERNAL_ERROR"),
                error.get("message", "Action failed"),
            )
        return response.get("result")

    async def _rpc(self, method: str, params: dict) -> object:
        async with self._rpc_lock:
            if time.monotonic() - self._connected_at >= 540:
                await self._establish()
            try:
                return await self._exchange(method, params, encrypted=True)
            except (asyncio.IncompleteReadError, BrokenPipeError, ConnectionError, OSError):
                await self._establish()
                return await self._exchange(method, params, encrypted=True)

    async def execute(self, request: ExecuteRequest) -> ExecuteResult:
        request_id = request.request_id or f"req_{uuid.uuid4()}"
        try:
            result = await self._rpc("action.request", {
                "request_id": request_id, "action": request.action,
                "identity": request.identity,
                "target": {"origin": request.target.origin, "path_prefix": request.target.path_prefix},
                "browser_session_id": request.browser_session_id,
                "tab_hint": request.tab_hint, "reason": request.reason,
                "wait": True, "timeout_ms": request.timeout_ms,
                "client_context": request.client_context,
            })
        except SecretCtlRpcError as error:
            return ExecuteResult(status="failed", request_id=request_id, code=error.code,
                                 safe_message=str(error) or "Action failed", retryable=False)
        except Exception:
            return ExecuteResult(status="failed", request_id=request_id, code="INTERNAL_ERROR",
                                 safe_message="secretctl action failed", retryable=False)
        if not isinstance(result, dict):
            raise ValueError("Invalid action response")
        return _parse_execute_result(result, request)

    async def authenticate(
        self,
        credential: str,
        reason: str,
        *,
        action: Optional[str] = None,
        request_id: Optional[str] = None,
        timeout_ms: int = 60000,
        client_context: Optional[dict[str, str]] = None,
    ) -> ExecuteResult:
        params: dict[str, object] = {
            "identity": credential, "reason": reason, "wait": True,
            "timeout_ms": timeout_ms,
        }
        if action is not None:
            params["action"] = action
        if request_id is not None:
            params["request_id"] = request_id
        if client_context is not None:
            params["client_context"] = client_context
        result = await self._rpc("action.authenticate", params)
        if not isinstance(result, dict):
            raise ValueError("Invalid authentication response")
        routed_action = result.get("action")
        origin = result.get("verified_origin")
        session_id = result.get("browser_session_id")
        if not all(isinstance(value, str) for value in (routed_action, origin, session_id)):
            raise ValueError("Broker did not return a verified authentication context")
        request = ExecuteRequest(
            request_id=result.get("request_id") if isinstance(result.get("request_id"), str) else request_id,
            action=routed_action, identity=credential, target=Target(origin=origin),
            browser_session_id=session_id, reason=reason, timeout_ms=timeout_ms,
            client_context=client_context,
        )
        return _parse_execute_result(result, request)

    async def status(self, request_id: str) -> ActionStatus:
        return ActionStatus.model_validate(await self._rpc("action.status", {"request_id": request_id}))

    async def cancel(self, request_id: str, reason: Optional[str] = None) -> bool:
        result = await self._rpc("action.cancel", {"request_id": request_id, "reason": reason})
        return isinstance(result, dict) and result.get("cancelled") is True

    async def session_info(self) -> SessionInfo:
        return SessionInfo.model_validate(await self._rpc("session.info", {}))

    async def tabs(self, session_id: str) -> list[BrowserTab]:
        result = await self._rpc("browser.tabs", {"session_id": session_id})
        if not isinstance(result, dict) or not isinstance(result.get("tabs"), list):
            raise ValueError("Invalid browser tabs response")
        return [BrowserTab.model_validate(tab) for tab in result["tabs"]]

    async def open_tab(self, session_id: str, url: str = "about:blank") -> str:
        result = await self._rpc("browser.open_tab", {"session_id": session_id, "url": url})
        if not isinstance(result, dict) or not isinstance(result.get("tab_id"), str):
            raise ValueError("Invalid browser tab response")
        return result["tab_id"]

    async def close_tab(self, session_id: str, tab_id: str) -> None:
        await self._rpc("browser.close_tab", {"session_id": session_id, "tab_id": tab_id})

    async def navigate(self, session_id: str, tab_id: str, url: str) -> None:
        await self._rpc("browser.navigate", {"session_id": session_id, "tab_id": tab_id, "url": url})

    async def reload(self, session_id: str, tab_id: str) -> None:
        await self._rpc("browser.reload", {"session_id": session_id, "tab_id": tab_id})

    async def click(self, session_id: str, tab_id: str, locator: dict[str, object]) -> None:
        await self._rpc("page.click", {"session_id": session_id, "tab_id": tab_id, "locator": locator})

    async def type_public(
        self, session_id: str, tab_id: str, locator: dict[str, object], text: str,
    ) -> None:
        await self._rpc("page.type_public", {
            "session_id": session_id, "tab_id": tab_id, "locator": locator, "text": text,
        })

    async def select(
        self, session_id: str, tab_id: str, locator: dict[str, object], label: str,
    ) -> None:
        await self._rpc("page.select", {
            "session_id": session_id, "tab_id": tab_id, "locator": locator, "label": label,
        })

    async def read_text(
        self, session_id: str, tab_id: str, locator: Optional[dict[str, object]] = None,
        max_chars: Optional[int] = None,
    ) -> PageTextResult:
        return PageTextResult.model_validate(await self._rpc("page.read_text", {
            "session_id": session_id, "tab_id": tab_id,
            "locator": locator, "max_chars": max_chars,
        }))

    async def snapshot_safe(
        self, session_id: str, tab_id: str, max_nodes: Optional[int] = None,
        check_visibility: bool = True,
    ) -> SafePageSnapshot:
        return SafePageSnapshot.model_validate(await self._rpc("page.snapshot_safe", {
            "session_id": session_id, "tab_id": tab_id, "max_nodes": max_nodes,
            "check_visibility": check_visibility,
        }))

    async def wait_for(
        self, session_id: str, tab_id: str, condition: dict[str, object],
        timeout_ms: int = 10000,
    ) -> bool:
        result = await self._rpc("page.wait_for", {
            "session_id": session_id, "tab_id": tab_id, "condition": condition,
            "timeout_ms": timeout_ms,
        })
        return isinstance(result, dict) and result.get("satisfied") is True

    async def back(self, session_id: str, tab_id: str) -> None:
        await self._rpc("browser.back", {"session_id": session_id, "tab_id": tab_id})

    async def forward(self, session_id: str, tab_id: str) -> None:
        await self._rpc("browser.forward", {"session_id": session_id, "tab_id": tab_id})

    async def subscribe(self, request_id: str, timeout_ms: int = 30000) -> AsyncIterator[ActionStatus]:
        previous: Optional[tuple[str, Optional[str]]] = None
        while True:
            params: dict[str, object] = {
                "request_id": request_id, "timeout_ms": min(timeout_ms, 30000),
            }
            if previous is not None:
                params["after_state"], params["after_detail"] = previous
            status = ActionStatus.model_validate(await self._rpc("action.subscribe", params))
            current = (status.state, status.detail)
            if current != previous:
                yield status
                previous = current
            if status.state in {
                "completed", "denied", "expired", "cancelled", "indeterminate",
                "completed_evidence_lost", "revoked", "failed"
            }:
                return

    async def close(self) -> None:
        if self.socket is not None:
            await self.socket.close()
            self.socket = None
        self.channel = None


class SecretCtl:
    def __init__(self, loop: asyncio.AbstractEventLoop, thread: threading.Thread, client: AsyncSecretCtl):
        self._loop, self._thread, self._client = loop, thread, client

    @classmethod
    def connect(cls, **kwargs: object) -> "SecretCtl":
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Sync SecretCtl cannot be created from an active event loop")
        loop = asyncio.new_event_loop()
        ready = threading.Event()
        def run_loop() -> None:
            asyncio.set_event_loop(loop)
            ready.set()
            loop.run_forever()
        thread = threading.Thread(target=run_loop, name="secretctl-sdk-loop", daemon=True)
        thread.start()
        ready.wait()
        client = asyncio.run_coroutine_threadsafe(AsyncSecretCtl.connect(**kwargs), loop).result()
        return cls(loop, thread, client)

    def execute(self, request: ExecuteRequest) -> ExecuteResult:
        return asyncio.run_coroutine_threadsafe(self._client.execute(request), self._loop).result()

    def authenticate(self, credential: str, reason: str, **kwargs: object) -> ExecuteResult:
        return asyncio.run_coroutine_threadsafe(
            self._client.authenticate(credential, reason, **kwargs), self._loop
        ).result()

    def tabs(self, session_id: str) -> list[BrowserTab]:
        return asyncio.run_coroutine_threadsafe(self._client.tabs(session_id), self._loop).result()

    def open_tab(self, session_id: str, url: str = "about:blank") -> str:
        return asyncio.run_coroutine_threadsafe(self._client.open_tab(session_id, url), self._loop).result()

    def close_tab(self, session_id: str, tab_id: str) -> None:
        asyncio.run_coroutine_threadsafe(self._client.close_tab(session_id, tab_id), self._loop).result()

    def navigate(self, session_id: str, tab_id: str, url: str) -> None:
        asyncio.run_coroutine_threadsafe(self._client.navigate(session_id, tab_id, url), self._loop).result()

    def reload(self, session_id: str, tab_id: str) -> None:
        asyncio.run_coroutine_threadsafe(self._client.reload(session_id, tab_id), self._loop).result()

    def click(self, session_id: str, tab_id: str, locator: dict[str, object]) -> None:
        asyncio.run_coroutine_threadsafe(self._client.click(session_id, tab_id, locator), self._loop).result()

    def type_public(self, session_id: str, tab_id: str, locator: dict[str, object], text: str) -> None:
        asyncio.run_coroutine_threadsafe(
            self._client.type_public(session_id, tab_id, locator, text), self._loop
        ).result()

    def select(
        self, session_id: str, tab_id: str, locator: dict[str, object], label: str,
    ) -> None:
        asyncio.run_coroutine_threadsafe(
            self._client.select(session_id, tab_id, locator, label), self._loop
        ).result()

    def read_text(
        self, session_id: str, tab_id: str, locator: Optional[dict[str, object]] = None,
        max_chars: Optional[int] = None,
    ) -> PageTextResult:
        return asyncio.run_coroutine_threadsafe(
            self._client.read_text(session_id, tab_id, locator, max_chars), self._loop
        ).result()

    def snapshot_safe(
        self, session_id: str, tab_id: str, max_nodes: Optional[int] = None,
        check_visibility: bool = True,
    ) -> SafePageSnapshot:
        return asyncio.run_coroutine_threadsafe(
            self._client.snapshot_safe(session_id, tab_id, max_nodes, check_visibility), self._loop
        ).result()

    def wait_for(
        self, session_id: str, tab_id: str, condition: dict[str, object], timeout_ms: int = 10000,
    ) -> bool:
        return asyncio.run_coroutine_threadsafe(
            self._client.wait_for(session_id, tab_id, condition, timeout_ms), self._loop
        ).result()

    def back(self, session_id: str, tab_id: str) -> None:
        asyncio.run_coroutine_threadsafe(self._client.back(session_id, tab_id), self._loop).result()

    def forward(self, session_id: str, tab_id: str) -> None:
        asyncio.run_coroutine_threadsafe(self._client.forward(session_id, tab_id), self._loop).result()

    def status(self, request_id: str) -> ActionStatus:
        return asyncio.run_coroutine_threadsafe(self._client.status(request_id), self._loop).result()

    def cancel(self, request_id: str, reason: Optional[str] = None) -> bool:
        return asyncio.run_coroutine_threadsafe(self._client.cancel(request_id, reason), self._loop).result()

    def session_info(self) -> SessionInfo:
        return asyncio.run_coroutine_threadsafe(self._client.session_info(), self._loop).result()

    def close(self) -> None:
        asyncio.run_coroutine_threadsafe(self._client.close(), self._loop).result()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=2)
