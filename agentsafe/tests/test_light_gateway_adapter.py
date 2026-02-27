import json
from pathlib import Path

from agentsafe.integrations.light_gateway.adapter import parse_execute_request


def _fixture(name: str) -> dict:
    path = Path(__file__).parent / "fixtures" / "light_gateway" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_strict_shell_extraction():
    payload = _fixture("request_shell_run.json")
    action = parse_execute_request("/v1/tools/execute", payload, fallback_actor="fallback")
    assert action.request_id == "req-shell-1"
    assert action.actor == "openclaw-agent"
    assert action.session_id == "session-123"
    assert action.tool == "shell.run"
    assert action.args["command"] == "ls"
    assert action.route == "/v1/tools/execute"


def test_strict_http_extraction():
    payload = _fixture("request_http_fetch.json")
    action = parse_execute_request("/v1/tools/execute", payload, fallback_actor="fallback")
    assert action.tool == "http.fetch"
    assert action.args["url"] == "https://example.com"
