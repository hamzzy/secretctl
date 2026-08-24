import asyncio
import base64
import hashlib
import json
import os
import threading
import uuid
from pathlib import Path
from typing import Optional

from .framing import AsyncLengthPrefixedSocket
from .types import ActionStatus, ExecuteRequest, ExecuteResult
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROHIBITED_RESPONSE_KEYS = (
    "password",
    "secret",
    "token",
    "seed",
    "cookie",
    "authorization",
    "private_key",
    "refresh_token",
    "access_token",
    "capability_token",
)


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


class AsyncSecretCtl:
    def __init__(self, socket: AsyncLengthPrefixedSocket):
        self.socket = socket

    @classmethod
    async def connect(
        cls,
        principal_id: str,
        socket_path: Optional[str] = None,
        broker_public_key_path: Optional[str] = None,
    ) -> "AsyncSecretCtl":
        if socket_path is None:
            socket_path = os.path.join(
                os.path.expanduser("~"), ".secretctl", "run", "agent.sock"
            )
        reader, writer = await asyncio.open_unix_connection(socket_path)
        client = cls(AsyncLengthPrefixedSocket(reader, writer))
        client_nonce = str(uuid.uuid4())
        hello = await client._rpc(
            "session.hello",
            {
                "protocol_version": "1.0",
                "role": "agent",
                "principal_id": principal_id,
                "client_nonce": client_nonce,
                "supported_suites": ["X25519_CHACHA20_POLY1305_ED25519"],
            },
        )
        if not isinstance(hello, dict):
            raise ValueError("Invalid broker handshake")
        key_path = Path(
            broker_public_key_path
            or os.path.join(os.path.expanduser("~"), ".secretctl", "broker_key.pub")
        )
        public_key = key_path.read_bytes()
        if len(public_key) != 32:
            raise ValueError("Invalid broker public key")

        def decode_base64url(value: str) -> bytes:
            return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

        components = [
            b"secretctl-session-hello-v1",
            client_nonce.encode(),
            str(hello["server_nonce"]).encode(),
            principal_id.encode(),
            decode_base64url(str(hello["ephemeral_public_key"])),
        ]
        digest = hashlib.sha256()
        for component in components:
            digest.update(len(component).to_bytes(8, "big"))
            digest.update(component)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            decode_base64url(str(hello["signature"])), digest.digest()
        )
        return client

    async def _rpc(self, method: str, params: dict) -> object:
        request = {
            "jsonrpc": "2.0",
            "id": f"rpc_{uuid.uuid4()}",
            "method": method,
            "params": params,
        }
        await self.socket.send(json.dumps(request).encode("utf-8"))
        response = json.loads((await self.socket.read_next()).decode("utf-8"))
        _assert_agent_safe(response)
        if not isinstance(response, dict):
            raise ValueError("Invalid secretctl response")
        if response.get("error"):
            error = response["error"]
            raise RuntimeError(error.get("message", "Action failed"))
        return response.get("result")

    async def execute(self, request: ExecuteRequest) -> ExecuteResult:
        request_id = request.request_id or f"req_{uuid.uuid4()}"
        try:
            result = await self._rpc(
                "action.request",
                {
                    "request_id": request_id,
                    "action": request.action,
                    "identity": request.identity,
                    "target": {
                        "origin": request.target.origin,
                        "path_prefix": request.target.path_prefix,
                    },
                    "browser_session_id": request.browser_session_id,
                    "tab_hint": request.tab_hint,
                    "reason": request.reason,
                    "wait": True,
                    "timeout_ms": request.timeout_ms,
                    "client_context": request.client_context,
                },
            )
        except Exception as error:
            return ExecuteResult(
                status="failed",
                request_id=request_id,
                code="INTERNAL_ERROR",
                safe_message=str(error) or "Action failed",
            )
        if not isinstance(result, dict):
            raise ValueError("Invalid action response")
        return ExecuteResult(
            status=(
                "capability_issued"
                if result.get("state") == "capability_issued"
                else "completed"
            ),
            request_id=result.get("request_id", request_id),
            action=request.action,
            identity=request.identity,
            verified_origin=request.target.origin,
            browser_session_id=request.browser_session_id,
            evidence_id=result.get("evidence_ref"),
            completed_at=result.get("completed_at"),
        )

    async def status(self, request_id: str) -> ActionStatus:
        return ActionStatus.model_validate(
            await self._rpc("action.status", {"request_id": request_id})
        )

    async def cancel(self, request_id: str, reason: Optional[str] = None) -> bool:
        result = await self._rpc(
            "action.cancel", {"request_id": request_id, "reason": reason}
        )
        return isinstance(result, dict) and result.get("cancelled") is True

    async def close(self) -> None:
        await self.socket.close()


class SecretCtl:
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        thread: threading.Thread,
        client: AsyncSecretCtl,
    ):
        self._loop = loop
        self._thread = thread
        self._client = client

    @classmethod
    def connect(
        cls,
        principal_id: str,
        socket_path: Optional[str] = None,
        broker_public_key_path: Optional[str] = None,
    ) -> "SecretCtl":
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

        thread = threading.Thread(
            target=run_loop, name="secretctl-sdk-loop", daemon=True
        )
        thread.start()
        ready.wait()
        future = asyncio.run_coroutine_threadsafe(
            AsyncSecretCtl.connect(principal_id, socket_path, broker_public_key_path), loop
        )
        return cls(loop, thread, future.result())

    def execute(self, request: ExecuteRequest) -> ExecuteResult:
        return asyncio.run_coroutine_threadsafe(
            self._client.execute(request), self._loop
        ).result()

    def authenticate(
        self,
        credential: str,
        reason: str = "Automated authentication",
        origin: Optional[str] = None,
        path_prefix: Optional[str] = None,
        session: Optional[str] = None,
        action: str = "authenticate.password",
    ) -> ExecuteResult:
        return asyncio.run_coroutine_threadsafe(
            self._client.authenticate(
                credential=credential,
                reason=reason,
                origin=origin,
                path_prefix=path_prefix,
                session=session,
                action=action,
            ),
            self._loop,
        ).result()

    def status(self, request_id: str) -> ActionStatus:
        return asyncio.run_coroutine_threadsafe(
            self._client.status(request_id), self._loop
        ).result()

    def cancel(self, request_id: str, reason: Optional[str] = None) -> bool:
        return asyncio.run_coroutine_threadsafe(
            self._client.cancel(request_id, reason), self._loop
        ).result()

    def close(self) -> None:
        asyncio.run_coroutine_threadsafe(self._client.close(), self._loop).result()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=2)
