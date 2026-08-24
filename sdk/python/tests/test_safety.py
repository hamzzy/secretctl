import pytest
from pydantic import ValidationError

from secretctl.client import _assert_agent_safe
from secretctl.types import ExecuteResult


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
