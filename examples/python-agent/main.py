import asyncio
import os
import sys
from pathlib import Path

# Add local Python SDK source directory to path
sdk_path = Path(__file__).resolve().parent.parent.parent / "sdk" / "python" / "src"
if str(sdk_path) not in sys.path:
    sys.path.insert(0, str(sdk_path))

from secretctl import AsyncSecretCtl, ExecuteRequest, Target


async def main():
    print("Connecting Python AI agent to secretctl broker...")
    principal_id = os.environ.get("SECRETCTL_PRINCIPAL_ID", "agent_default")
    client = await AsyncSecretCtl.connect(principal_id)

    print("Requesting TOTP entry for 'github-totp'...")
    result = await client.execute(
        ExecuteRequest(
            action="authenticate.totp",
            identity="github-totp",
            target=Target(origin="https://github.com:443", path_prefix="/sessions/two-factor"),
            browser_session_id="bs_demo_session",
            reason="Two-factor challenge completion",
        )
    )

    print("Execution result:", result)
    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
