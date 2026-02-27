from types import SimpleNamespace

from agentsafe.integrations.model import ToolAction
from agentsafe.proxy.modeb_proxy import (
    _method_matches,
    _route_matches,
    ProxyConfig,
    forward_upstream,
    grant_scope_for_action,
    should_inspect_tool_call,
)


def test_route_matching():
    regexes = [r"^/v1/tools/execute$", r"^/api/tools/.+"]
    assert _route_matches("/v1/tools/execute", regexes)
    assert _route_matches("/api/tools/run", regexes)
    assert not _route_matches("/health", regexes)


def test_scope_string_for_shell():
    action = ToolAction(
        request_id="x",
        actor="a",
        session_id="s",
        tool="shell.run",
        args={"command": "ls -la"},
        route="/v1/tools/execute",
    )
    assert grant_scope_for_action(action) == "shell.run ls -la"


def test_method_matching():
    assert _method_matches("POST", ["POST", "PUT"])
    assert _method_matches("put", ["POST", "PUT"])
    assert not _method_matches("GET", ["POST", "PUT"])


def test_should_inspect_tool_call_by_route_and_method():
    config = ProxyConfig(
        upstream="http://upstream",
        policy_path="policies/demo-openclaw.yaml",
        policy_backend="yaml",
        workspace=".",
        path_regexes=[r"^/v1/tools/execute$", r"^/api/tools/.+"],
        tool_methods=["POST", "PUT", "PATCH"],
    )
    assert should_inspect_tool_call("POST", "/v1/tools/execute", config)
    assert should_inspect_tool_call("PATCH", "/api/tools/run", config)
    assert not should_inspect_tool_call("GET", "/v1/tools/execute", config)
    assert not should_inspect_tool_call("POST", "/health", config)


def test_forward_upstream_uses_streaming_request(monkeypatch):
    captured = {}

    def fake_request(method, url, data, headers, timeout, stream):
        captured.update(
            {
                "method": method,
                "url": url,
                "data": data,
                "headers": headers,
                "timeout": timeout,
                "stream": stream,
            }
        )
        return SimpleNamespace(status_code=200, headers={}, iter_content=lambda chunk_size: iter(()), close=lambda: None)

    monkeypatch.setattr("agentsafe.proxy.modeb_proxy.requests.request", fake_request)
    forward_upstream("PUT", "http://example.test/v1/tools/execute", {"x-id": "1"}, b'{"k":"v"}')
    assert captured["method"] == "PUT"
    assert captured["stream"] is True
    assert captured["timeout"] == 20
