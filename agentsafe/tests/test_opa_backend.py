from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from agentsafe.policy.opa_backend import OpaPolicyBackend


def _policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
policy_id: test-opa
default_decision: deny
tools:
  commands:
    - binary: ls
      rule_id: cmd_ls
  paths:
    allow: [.]
    deny: [/etc]
  env_allowlist: [HTTP_PROXY]
  network:
    mode: allow_proxy
    domains: [openai.com]
    ports: [443]
""".strip(),
        encoding="utf-8",
    )
    return path


def test_opa_backend_not_configured(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AGENTSAFE_OPA_URL", raising=False)
    backend = OpaPolicyBackend(str(_policy_file(tmp_path)))
    decision = backend.evaluate_run(["ls"], tmp_path)
    assert decision.allowed is False
    assert decision.rule_id == "opa_not_configured"


def test_opa_backend_queries_endpoint_and_parses_decision(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AGENTSAFE_OPA_URL", "http://opa:8181")

    captured = {}

    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"result": {"allow": True, "reason": "allow from rego", "rule_id": "rego_allow"}}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["input"] = json["input"]
        captured["timeout"] = timeout
        return FakeResp()

    monkeypatch.setattr("agentsafe.policy.opa_backend.requests.post", fake_post)
    backend = OpaPolicyBackend(str(_policy_file(tmp_path)))
    decision = backend.evaluate_fetch("https://openai.com")

    assert decision.allowed is True
    assert decision.rule_id == "rego_allow"
    assert captured["url"] == "http://opa:8181/v1/data/agentsafe/evaluate"
    assert captured["timeout"] == 8
    assert captured["input"]["action"]["type"] == "fetch"
    assert captured["input"]["action"]["host"] == "openai.com"
    assert captured["input"]["action"]["port"] == 443


def test_opa_backend_handles_malformed_result(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AGENTSAFE_OPA_URL", "http://opa:8181")

    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"result": []}

    monkeypatch.setattr("agentsafe.policy.opa_backend.requests.post", lambda *args, **kwargs: FakeResp())
    backend = OpaPolicyBackend(str(_policy_file(tmp_path)))
    decision = backend.evaluate_path("./x.txt", tmp_path)
    assert decision.allowed is False
    assert decision.rule_id == "opa_bad_result"


def test_opa_backend_exposes_env_and_network_from_policy(tmp_path: Path):
    backend = OpaPolicyBackend(str(_policy_file(tmp_path)), opa_url="http://opa:8181")
    assert backend.env_allowlist() == ["HTTP_PROXY"]
    assert backend.network_mode() == "allow_proxy"
