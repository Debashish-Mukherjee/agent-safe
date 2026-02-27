from pathlib import Path

from agentsafe.policy.evaluate import RateLimiter, evaluate_command
from agentsafe.policy.load import load_policy


def test_command_allow_and_block(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
policy_id: test
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
    mode: none
""".strip()
    )
    policy = load_policy(policy_path)
    allowed = evaluate_command(policy, ["ls", "-la"], tmp_path)
    blocked = evaluate_command(policy, ["cat", "x"], tmp_path)
    assert allowed.allowed is True
    assert blocked.allowed is False


def test_rate_limiter_blocks_after_capacity():
    policy_rules = [
        type("Rule", (), {"category": "run", "capacity": 1, "refill_per_sec": 0.0})(),
    ]
    limiter = RateLimiter(policy_rules)
    first = limiter.check("run")
    second = limiter.check("run")
    assert first.allowed is True
    assert second.allowed is False
