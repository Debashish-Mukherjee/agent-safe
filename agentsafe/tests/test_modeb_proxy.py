import io
from types import SimpleNamespace

from agentsafe.integrations.model import ToolAction
from agentsafe.policy.factory import load_backend
from agentsafe.proxy.modeb_proxy import (
    _method_matches,
    _route_matches,
    ProxyConfig,
    evaluate_action,
    forward_upstream,
    grant_scope_for_action,
    load_proxy_config,
    relay_upstream_response,
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


def test_load_proxy_config_reads_profile_and_header_env(monkeypatch):
    monkeypatch.setenv("AGENTSAFE_PROFILE_HEADER", "X-Profile")
    monkeypatch.setenv("AGENTSAFE_PROXY_PROFILES_PATH", "policies/profiles.example.yaml")
    config = load_proxy_config()
    assert config.profile_header == "X-Profile"
    assert config.profiles_path == "policies/profiles.example.yaml"


def test_proxy_http_fetch_blocks_deny_header_and_large_body(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
policy_id: p
default_decision: deny
tools:
  commands:
    - binary: ls
      rule_id: cmd_ls
  paths:
    allow: [.]
    deny: [/etc]
  env_allowlist: []
  network:
    mode: allow_proxy
    domains: [openai.com]
    ports: [443]
    http_methods: [GET, POST]
    http_path_allow_regex: ["^/v1/.*"]
    max_request_body_bytes: 10
    deny_header_patterns: ["(?i)authorization"]
    deny_body_patterns: ["(?i)secret"]
""".strip(),
        encoding="utf-8",
    )
    backend = load_backend("yaml", policy_path)
    action_header = ToolAction(
        request_id="r1",
        actor="a",
        session_id="s",
        tool="http.fetch",
        args={
            "url": "https://openai.com/v1/chat",
            "method": "POST",
            "headers": {"Authorization": "Bearer token"},
            "body": "ok",
        },
        route="/v1/tools/execute",
    )
    header_block = evaluate_action(action=action_header, backend=backend, workspace_root=tmp_path)
    assert header_block.allowed is False
    assert header_block.rule_id == "net_header_block"

    action_size = ToolAction(
        request_id="r2",
        actor="a",
        session_id="s",
        tool="http.fetch",
        args={
            "url": "https://openai.com/v1/chat",
            "method": "POST",
            "headers": {"X-Req": "1"},
            "body": "x" * 32,
        },
        route="/v1/tools/execute",
    )
    size_block = evaluate_action(action=action_size, backend=backend, workspace_root=tmp_path)
    assert size_block.allowed is False
    assert size_block.rule_id == "net_body_size_block"

    action_method = ToolAction(
        request_id="r3",
        actor="a",
        session_id="s",
        tool="http.fetch",
        args={
            "url": "https://openai.com/v1/chat",
            "method": "DELETE",
            "headers": {"X-Req": "1"},
            "body": "ok",
        },
        route="/v1/tools/execute",
    )
    method_block = evaluate_action(action=action_method, backend=backend, workspace_root=tmp_path)
    assert method_block.allowed is False
    assert method_block.rule_id == "net_method_block"

    action_path = ToolAction(
        request_id="r4",
        actor="a",
        session_id="s",
        tool="http.fetch",
        args={
            "url": "https://openai.com/internal/admin",
            "method": "POST",
            "headers": {"X-Req": "1"},
            "body": "ok",
        },
        route="/v1/tools/execute",
    )
    path_block = evaluate_action(action=action_path, backend=backend, workspace_root=tmp_path)
    assert path_block.allowed is False
    assert path_block.rule_id == "net_path_block"

    action_body = ToolAction(
        request_id="r5",
        actor="a",
        session_id="s",
        tool="http.fetch",
        args={
            "url": "https://openai.com/v1/chat",
            "method": "POST",
            "headers": {"X-Req": "1"},
            "body": "secret",
        },
        route="/v1/tools/execute",
    )
    body_block = evaluate_action(action=action_body, backend=backend, workspace_root=tmp_path)
    assert body_block.allowed is False
    assert body_block.rule_id == "net_body_pattern_block"


def test_relay_upstream_response_caps_bytes_and_applies_delay(monkeypatch):
    class DummyHandler:
        def __init__(self):
            self.status = 0
            self.headers = {}
            self.wfile = io.BytesIO()

        def send_response(self, code):
            self.status = code

        def send_header(self, key, value):
            self.headers[key] = value

        def end_headers(self):
            return None

    class DummyResponse:
        status_code = 200
        headers = {"Content-Type": "text/plain"}

        @staticmethod
        def iter_content(chunk_size=0):
            _ = chunk_size
            yield b"abcdef"
            yield b"ghijkl"

        @staticmethod
        def close():
            return None

    slept = {"called": 0}

    def fake_sleep(seconds):
        slept["called"] = seconds

    monkeypatch.setattr("agentsafe.proxy.modeb_proxy.time.sleep", fake_sleep)
    handler = DummyHandler()
    relay_upstream_response(
        handler,
        DummyResponse(),
        max_bytes=8,
        min_delay_ms=10,
        jitter_ms=0,
        jitter_seed="seed",
    )
    assert handler.status == 200
    assert handler.wfile.getvalue() == b"abcdefgh"
    assert slept["called"] == 0.01
