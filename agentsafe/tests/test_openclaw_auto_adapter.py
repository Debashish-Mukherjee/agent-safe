import json
from pathlib import Path

from agentsafe.integrations.openclaw.adapter_router import parse_openclaw_auto_request


def _fixture(name: str) -> dict:
    path = Path(__file__).parent / "fixtures" / "openclaw" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_openclaw_auto_prefers_strict_v1_for_canonical_route():
    payload = _fixture("request_tool_execute_v1.json")
    action = parse_openclaw_auto_request("/v1/tools/execute", payload, fallback_actor="fallback")
    assert action.request_id == "oc-req-1"
    assert action.actor == "openclaw-agent"
    assert action.tool == "shell.run"


def test_openclaw_auto_falls_back_to_generic_for_legacy_payload():
    payload = _fixture("request_tool_execute_legacy.json")
    action = parse_openclaw_auto_request("/gateway/tools/execute", payload, fallback_actor="fallback")
    assert action.request_id == "legacy-1"
    assert action.actor == "legacy-agent"
    assert action.session_id == "legacy-session"
    assert action.tool == "shell.run"
    assert action.args["command"] == "ls -la"


def test_openclaw_auto_falls_back_if_strict_parse_fails():
    payload = _fixture("request_tool_execute_legacy.json")
    action = parse_openclaw_auto_request("/v1/tools/execute", payload, fallback_actor="fallback")
    assert action.request_id == "legacy-1"
    assert action.tool == "shell.run"


def test_openclaw_auto_prefers_strict_v2_for_canonical_route():
    payload = _fixture("request_tool_execute_v2.json")
    action = parse_openclaw_auto_request("/v2/tools/execute", payload, fallback_actor="fallback")
    assert action.request_id == "oc2-req-1"
    assert action.tool == "http.fetch"
