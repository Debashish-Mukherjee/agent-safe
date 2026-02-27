import json
from pathlib import Path

from agentsafe.approvals.grants import GrantStore
from agentsafe.integrations.registry import get_adapter
from agentsafe.policy.factory import load_backend
from agentsafe.proxy.modeb_proxy import ProxyConfig, build_audit_event, process_tool_request


REPO_ROOT = Path(__file__).resolve().parents[2]


def _fixture(name: str) -> dict:
    path = Path(__file__).parent / "fixtures" / "light_gateway" / name
    return json.loads(path.read_text(encoding="utf-8"))


def _config(tmp_path: Path) -> ProxyConfig:
    return ProxyConfig(
        upstream="http://light-gateway:8088",
        policy_path=str(REPO_ROOT / "policies" / "demo-openclaw.yaml"),
        policy_backend="yaml",
        workspace=str(tmp_path),
        path_regexes=[r"^/v1/tools/execute$"],
        adapter="light_gateway",
    )


def test_modeb_shell_allow_and_audit_fields(tmp_path: Path):
    config = _config(tmp_path)
    backend = load_backend("yaml", config.policy_path)
    grants = GrantStore(tmp_path / "grants.jsonl")
    adapter_fn = get_adapter("light_gateway")

    payload = _fixture("request_shell_run.json")
    result = process_tool_request(
        path="/v1/tools/execute",
        payload=payload,
        fallback_actor="fallback",
        config=config,
        backend=backend,
        grants=grants,
        workspace_root=tmp_path,
        adapter_fn=adapter_fn,
    )
    assert result.allowed is True
    event = build_audit_event(result, config, request_id=result.action.request_id)
    assert event["proxy"]["route"] == "/v1/tools/execute"
    assert event["proxy"]["tool"] == "shell.run"
    assert event["proxy"]["args"]["command"] == "ls"
    assert event["decision"] == "ALLOW"


def test_modeb_http_block_and_audit_reason(tmp_path: Path):
    config = _config(tmp_path)
    backend = load_backend("yaml", config.policy_path)
    grants = GrantStore(tmp_path / "grants.jsonl")
    adapter_fn = get_adapter("light_gateway")

    payload = _fixture("request_http_fetch.json")
    result = process_tool_request(
        path="/v1/tools/execute",
        payload=payload,
        fallback_actor="fallback",
        config=config,
        backend=backend,
        grants=grants,
        workspace_root=tmp_path,
        adapter_fn=adapter_fn,
    )
    assert result.allowed is False
    assert result.rule_id == "net_domain_block"
    event = build_audit_event(result, config, request_id=result.action.request_id)
    assert event["decision"] == "BLOCK"
    assert "domain not allowlisted" in event["reason"]


def test_modeb_grant_required_then_allowed(tmp_path: Path):
    config = _config(tmp_path)
    backend = load_backend("yaml", config.policy_path)
    grants = GrantStore(tmp_path / "grants.jsonl")
    adapter_fn = get_adapter("light_gateway")

    payload = {
        "request_id": "req-grant",
        "actor": "openclaw-agent",
        "session_id": "s1",
        "tool": "shell.run",
        "args": {"command": "curl https://openai.com"},
        "context": {"cwd": "/workspace"},
    }

    denied = process_tool_request(
        path="/v1/tools/execute",
        payload=payload,
        fallback_actor="fallback",
        config=config,
        backend=backend,
        grants=grants,
        workspace_root=tmp_path,
        adapter_fn=adapter_fn,
    )
    assert denied.allowed is False
    assert denied.rule_id == "proxy_approval_required"

    grants.issue(
        actor="openclaw-agent",
        tool="shell.run",
        scope="shell.run curl https://openai.com",
        ttl_seconds=600,
        reason="test",
    )

    allowed = process_tool_request(
        path="/v1/tools/execute",
        payload=payload,
        fallback_actor="fallback",
        config=config,
        backend=backend,
        grants=grants,
        workspace_root=tmp_path,
        adapter_fn=adapter_fn,
    )
    assert allowed.allowed is True
    assert allowed.rule_id == "cmd_curl"
