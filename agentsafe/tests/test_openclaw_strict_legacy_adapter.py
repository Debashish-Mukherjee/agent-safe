import json
from pathlib import Path

import pytest

from agentsafe.integrations.openclaw.adapter_strict_legacy import (
    OpenClawStrictLegacyAdapterError,
    parse_strict_legacy_request,
)


def _fixture(name: str) -> dict:
    path = Path(__file__).parent / "fixtures" / "openclaw" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_openclaw_strict_legacy_extracts_fields():
    payload = _fixture("request_tool_execute_legacy.json")
    action = parse_strict_legacy_request("/gateway/tools/execute", payload)
    assert action.request_id == "legacy-1"
    assert action.actor == "legacy-agent"
    assert action.session_id == "legacy-session"
    assert action.tool == "shell.run"
    assert action.args["command"] == "ls -la"


def test_openclaw_strict_legacy_rejects_wrong_route():
    payload = _fixture("request_tool_execute_legacy.json")
    with pytest.raises(OpenClawStrictLegacyAdapterError):
        parse_strict_legacy_request("/v1/tools/execute", payload)
