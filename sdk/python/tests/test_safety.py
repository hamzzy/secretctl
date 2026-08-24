import pytest
from pydantic import ValidationError
from pathlib import Path
import json

from secretctl.client import AsyncSecretCtl, _assert_agent_safe, _parse_execute_result
from secretctl.types import ExecuteRequest, ExecuteResult, Target


def test_hostile_secret_bearing_response_fails_closed() -> None:
    with pytest.raises(ValueError, match="unsafe broker response"):
        _assert_agent_safe({"result": {"password": "canary"}})


def test_unknown_model_fields_fail_closed() -> None:
    with pytest.raises(ValidationError):
        ExecuteResult(
            status="completed",
            request_id="req_1",
            access_token="canary",
        )


def test_published_action_result_states_match_typescript_contract() -> None:
    request = ExecuteRequest(
        action="authenticate.totp",
        identity="demo",
        target=Target(origin="https://example.test"),
        browser_session_id="bs_m3",
        reason="contract test",
    )
    completed = _parse_execute_result(
        {"request_id": "req_m3_completed", "state": "completed"}, request
    )
    assert completed.status == "completed"
    failed = _parse_execute_result(
        {
            "request_id": "req_m3_failed",
            "state": "failed",
            "result_code": "EXECUTOR_FAILED",
        },
        request,
    )
    assert failed.status == "failed"
    assert failed.code == "EXECUTOR_FAILED"


def test_shared_cross_language_result_fixture_stays_schema_compatible() -> None:
    fixture_path = Path(__file__).parents[3] / "tests" / "fixtures" / "m3-action-results.json"
    fixture = json.loads(fixture_path.read_text())
    request = ExecuteRequest(
        action="authenticate.totp",
        identity="demo",
        target=Target(origin="https://example.test"),
        browser_session_id="bs_m3",
        reason="fixture",
    )
    assert [_parse_execute_result(value, request).status for value in fixture] == [
        "completed", "failed"
    ]


@pytest.mark.asyncio
async def test_ergonomic_authentication_and_browser_surface_are_broker_routed() -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    client = object.__new__(AsyncSecretCtl)

    async def fake_rpc(method: str, params: dict[str, object]) -> object:
        calls.append((method, params))
        if method == "action.authenticate":
            return {
                "request_id": "req_auth", "state": "capability_issued",
                "action": "authenticate.password",
                "verified_origin": "https://example.test:443",
                "browser_session_id": "bs_1",
            }
        if method == "browser.tabs":
            return {"tabs": [{"tab_id": "tab_1", "url": "https://example.test/", "title": "Example"}]}
        if method == "page.read_text":
            return {"text": "Sign in", "truncated": False}
        if method == "page.snapshot_safe":
            return {"url": "https://example.test/", "elements": [], "truncated": False}
        if method == "page.wait_for":
            return {"satisfied": True}
        return {}

    client._rpc = fake_rpc  # type: ignore[method-assign]
    result = await client.authenticate("github-work", "Sign me in")
    assert result.status == "capability_issued"
    assert (await client.tabs("bs_1"))[0].tab_id == "tab_1"
    assert (await client.read_text("bs_1", "tab_1")).text == "Sign in"
    assert (await client.snapshot_safe("bs_1", "tab_1")).url == "https://example.test/"
    assert await client.wait_for(
        "bs_1", "tab_1", {"kind": "text_present", "value": "Sign in"}
    )
    await client.select(
        "bs_1", "tab_1", {"kind": "role", "role": "combobox", "name": "Region"}, "EU"
    )
    await client.back("bs_1", "tab_1")
    await client.forward("bs_1", "tab_1")

    assert [method for method, _ in calls] == [
        "action.authenticate", "browser.tabs", "page.read_text",
        "page.snapshot_safe", "page.wait_for", "page.select", "browser.back", "browser.forward",
    ]
