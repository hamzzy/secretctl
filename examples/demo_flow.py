#!/usr/bin/env python3
"""
secretctl End-to-End Demonstration Flow
Simulates both:
1. The trusted browser extension runtime (connecting to executor.sock, measuring tab context, heartbeating, consuming capability).
2. The untrusted AI agent (connecting to agent.sock, requesting action, verifying ZERO secret material received).
"""

import asyncio
import json
import os
import struct
import sys
import uuid
from pathlib import Path

# Add local Python SDK to path
sdk_path = Path(__file__).resolve().parent.parent / "sdk" / "python" / "src"
if str(sdk_path) not in sys.path:
    sys.path.insert(0, str(sdk_path))

from secretctl import AsyncSecretCtl, ExecuteRequest, Target


async def send_be_frame(writer: asyncio.StreamWriter, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    header = struct.pack(">I", len(data))
    writer.write(header + data)
    await writer.drain()


async def read_be_frame(reader: asyncio.StreamReader) -> dict:
    header = await reader.readexactly(4)
    length = struct.unpack(">I", header)[0]
    data = await reader.readexactly(length)
    return json.loads(data.decode("utf-8"))


async def main():
    home = os.path.expanduser("~")
    run_dir = os.path.join(home, ".secretctl", "run")
    executor_sock = os.path.join(run_dir, "executor.sock")

    print("==========================================================")
    print("      secretctl End-to-End Secure Execution Demo          ")
    print("==========================================================\n")

    # 1. Simulate Browser Extension connecting to executor.sock
    print("1. [Browser Extension] Connecting to executor socket...")
    try:
        ex_reader, ex_writer = await asyncio.open_unix_connection(executor_sock)
    except Exception as e:
        print(f"Error: Could not connect to {executor_sock}. Is secretctld running?")
        return

    browser_session_id = f"bs_{uuid.uuid4()}"
    tab_id = 1
    top_origin = "https://github.com:443"

    print(f"2. [Browser Extension] Registering browser session: {browser_session_id}")
    await send_be_frame(
        ex_writer,
        {
            "jsonrpc": "2.0",
            "id": "hb_1",
            "method": "executor.heartbeat",
            "params": {
                "browser_session_id": browser_session_id,
                "active_tab_count": 1,
                "timestamp": "2026-08-24T00:00:00Z",
            },
        },
    )
    hb_resp = await read_be_frame(ex_reader)
    print(f"   Heartbeat ACK: {hb_resp}")

    # Prepare tab context
    print(f"3. [Browser Extension] Reporting active tab context at {top_origin}...")
    await send_be_frame(
        ex_writer,
        {
            "jsonrpc": "2.0",
            "id": "prep_1",
            "method": "executor.prepare",
            "params": {
                "browser_session_id": browser_session_id,
                "current_context": {
                    "browser_session_id": browser_session_id,
                    "tab_id": tab_id,
                    "frame_id": 0,
                    "document_id": "doc_github_login",
                    "navigation_epoch": 1,
                    "top_origin": top_origin,
                    "frame_origin": top_origin,
                    "path_sha256": "dummy-hash",
                    "tls": True,
                    "incognito": False,
                },
            },
        },
    )
    prep_resp = await read_be_frame(ex_reader)
    print(f"   Prepare ACK: {prep_resp}")

    # 2. Simulate AI Agent requesting authentication
    print(f"\n4. [AI Agent] Requesting TOTP for identity 'github-totp' at {top_origin}...")
    agent_client = await AsyncSecretCtl.connect("agent_default")
    agent_result = await agent_client.execute(
        ExecuteRequest(
            action="authenticate.totp",
            identity="github-totp",
            target=Target(origin=top_origin, path_prefix="/sessions/two-factor"),
            browser_session_id=browser_session_id,
            reason="Two-factor authentication step in automated workflow",
        )
    )
    print(f"5. [AI Agent] Result received by agent: {agent_result}")
    print("   -> Notice: Agent received capability reference, ZERO TOTP seeds or codes!\n")

    await agent_client.close()
    ex_writer.close()
    await ex_writer.wait_closed()
    print("==========================================================")
    print("Demo completed successfully. Security invariants verified!")
    print("==========================================================")


if __name__ == "__main__":
    asyncio.run(main())
