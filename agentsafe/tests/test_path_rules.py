from pathlib import Path

from agentsafe.policy.evaluate import evaluate_path
from agentsafe.policy.load import load_policy


def _policy(tmp_path: Path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        """
policy_id: paths
default_decision: deny
tools:
  commands: []
  paths:
    allow: [.] 
    deny: [/etc, ~/.ssh]
  env_allowlist: []
  network:
    mode: none
""".strip()
    )
    return load_policy(p)


def test_workspace_allowed(tmp_path: Path):
    policy = _policy(tmp_path)
    d = evaluate_path(policy, "./notes.txt", tmp_path)
    assert d.allowed is True


def test_etc_blocked(tmp_path: Path):
    policy = _policy(tmp_path)
    d = evaluate_path(policy, "/etc/passwd", tmp_path)
    assert d.allowed is False
