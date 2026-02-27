import json
from pathlib import Path

import pytest

from agentsafe.integrations.openclaw.adapter_strict_v1 import (
    OpenClawStrictV1AdapterError,
    parse_strict_v1_request,
)


def _fixture(name: str) -> dict:
    path = Path(__file__).parent / "fixtures" / "openclaw" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_openclaw_strict_v1_extracts_fields():
    payload = _fixture("request_tool_execute_v1.json")
    action = parse_strict_v1_request("/v1/tools/execute", payload)
    assert action.request_id == "oc-req-1"
    assert action.actor == "openclaw-agent"
    assert action.session_id == "oc-session-1"
    assert action.tool == "shell.run"
    assert action.args["command"] == "ls"


def test_openclaw_strict_v1_rejects_wrong_route():
    payload = _fixture("request_tool_execute_v1.json")
    with pytest.raises(OpenClawStrictV1AdapterError):
        parse_strict_v1_request("/gateway/tools/execute", payload)
