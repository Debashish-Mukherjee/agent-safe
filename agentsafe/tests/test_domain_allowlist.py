from pathlib import Path

from agentsafe.policy.evaluate import evaluate_url
from agentsafe.policy.load import load_policy


def _policy(tmp_path: Path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        """
policy_id: net
default_decision: deny
tools:
  commands: []
  paths:
    allow: [.] 
    deny: [/etc]
  env_allowlist: []
  network:
    mode: allow_proxy
    domains: [github.com]
    ports: [443]
""".strip()
    )
    return load_policy(p)


def test_domain_allowed(tmp_path: Path):
    policy = _policy(tmp_path)
    d = evaluate_url(policy, "https://api.github.com/repos")
    assert d.allowed is True


def test_domain_blocked(tmp_path: Path):
    policy = _policy(tmp_path)
    d = evaluate_url(policy, "https://example.com")
    assert d.allowed is False
