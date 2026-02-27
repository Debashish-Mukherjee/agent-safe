from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentsafe.policy.opa_backend import OpaPolicyBackend
from agentsafe.policy.yaml_backend import YamlPolicyBackend


def _write_policy(tmp_path: Path) -> Path:
    workspace_root = tmp_path.resolve()
    policy_path = tmp_path / "policy-live.yaml"
    policy_path.write_text(
        f"""
policy_id: test-live-opa
default_decision: deny
tools:
  commands:
    - binary: ls
      rule_id: cmd_ls
  paths:
    allow:
      - {workspace_root}
    deny:
      - /etc
  env_allowlist: [LANG]
  network:
    mode: allow_proxy
    domains:
      - openai.com
    ports: [443]
""".strip(),
        encoding="utf-8",
    )
    return policy_path


@pytest.mark.skipif(not os.environ.get("AGENTSAFE_OPA_URL"), reason="AGENTSAFE_OPA_URL not set")
def test_live_opa_backend_parity_on_allow_and_deny(tmp_path: Path):
    policy_path = _write_policy(tmp_path)
    yaml_backend = YamlPolicyBackend.from_path(policy_path)
    opa_backend = OpaPolicyBackend(str(policy_path))

    decisions = [
        (
            yaml_backend.evaluate_run(["ls"], tmp_path),
            opa_backend.evaluate_run(["ls"], tmp_path),
        ),
        (
            yaml_backend.evaluate_fetch("https://openai.com"),
            opa_backend.evaluate_fetch("https://openai.com"),
        ),
        (
            yaml_backend.evaluate_fetch("https://example.com"),
            opa_backend.evaluate_fetch("https://example.com"),
        ),
        (
            yaml_backend.evaluate_path("/etc/passwd", tmp_path),
            opa_backend.evaluate_path("/etc/passwd", tmp_path),
        ),
        (
            yaml_backend.evaluate_path(str(tmp_path / "notes.txt"), tmp_path),
            opa_backend.evaluate_path(str(tmp_path / "notes.txt"), tmp_path),
        ),
    ]

    for yaml_decision, opa_decision in decisions:
        assert yaml_decision.allowed == opa_decision.allowed
