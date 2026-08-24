import asyncio
from secretctl import AsyncSecretCtl, ExecuteRequest, Target


async def main():
    print("Connecting Python AI agent to secretctl broker...")
    client = await AsyncSecretCtl.connect()

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
