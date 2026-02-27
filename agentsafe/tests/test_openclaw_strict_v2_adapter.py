import json
from pathlib import Path

import pytest

from agentsafe.integrations.openclaw.adapter_strict_v2 import (
    OpenClawStrictV2AdapterError,
    parse_strict_v2_request,
)


def _fixture(name: str) -> dict:
    path = Path(__file__).parent / "fixtures" / "openclaw" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_openclaw_strict_v2_extracts_fields():
    payload = _fixture("request_tool_execute_v2.json")
    action = parse_strict_v2_request("/v2/tools/execute", payload)
    assert action.request_id == "oc2-req-1"
    assert action.actor == "openclaw-agent"
    assert action.session_id == "oc2-session-1"
    assert action.tool == "http.fetch"
    assert action.args["url"] == "https://example.com"


def test_openclaw_strict_v2_rejects_wrong_route():
    payload = _fixture("request_tool_execute_v2.json")
    with pytest.raises(OpenClawStrictV2AdapterError):
        parse_strict_v2_request("/v1/tools/execute", payload)
