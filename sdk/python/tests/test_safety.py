import pytest
from pydantic import ValidationError
from pathlib import Path
import json

from secretctl.client import _assert_agent_safe, _parse_execute_result
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
