import asyncio
import json
import os
import uuid
from typing import Optional
from .framing import AsyncLengthPrefixedSocket
from .types import ExecuteRequest, ExecuteResult


class AsyncSecretCtl:
    def __init__(self, socket: AsyncLengthPrefixedSocket):
        self.socket = socket

    @classmethod
    async def connect(cls, socket_path: Optional[str] = None) -> "AsyncSecretCtl":
        if socket_path is None:
            home = os.path.expanduser("~")
            socket_path = os.path.join(home, ".secretctl", "run", "agent.sock")

        reader, writer = await asyncio.open_unix_connection(socket_path)
        framed = AsyncLengthPrefixedSocket(reader, writer)
        return cls(framed)

    async def execute(self, request: ExecuteRequest) -> ExecuteResult:
        req_id = request.request_id or f"req_{uuid.uuid4()}"

        rpc_req = {
            "jsonrpc": "2.0",
            "id": f"rpc_{uuid.uuid4()}",
            "method": "action.request",
            "params": {
                "request_id": req_id,
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
        }

        await self.socket.send(json.dumps(rpc_req).encode("utf-8"))
        resp_bytes = await self.socket.read_next()
        rpc_resp = json.loads(resp_bytes.decode("utf-8"))

        if "error" in rpc_resp and rpc_resp["error"]:
            err = rpc_resp["error"]
            return ExecuteResult(
                status="failed",
                request_id=req_id,
                code=err.get("message", "INTERNAL_ERROR"),
                safe_message=err.get("message", "Action failed"),
            )

        res = rpc_resp.get("result", {})
        state = res.get("state")
        status = "capability_issued" if state == "capability_issued" else "completed"

        return ExecuteResult(
            status=status,
            request_id=res.get("request_id", req_id),
            action=request.action,
            identity=request.identity,
            verified_origin=request.target.origin,
            browser_session_id=request.browser_session_id,
            evidence_id=res.get("evidence_ref"),
            completed_at=res.get("completed_at"),
        )

    async def close(self) -> None:
        await self.socket.close()
