from pathlib import Path

from agentsafe.policy.evaluate import RateLimiter, evaluate_command, evaluate_fetch_request
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


def test_fetch_request_policy_blocks_header_body_and_method(tmp_path: Path):
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
    mode: allow_proxy
    domains: [openai.com]
    ports: [443]
    http_methods: [GET]
    http_path_allow_regex: ["^/v1/.*"]
    max_request_body_bytes: 16
    deny_header_patterns: ["(?i)authorization"]
    deny_body_patterns: ["(?i)secret"]
""".strip(),
        encoding="utf-8",
    )
    policy = load_policy(policy_path)

    method_block = evaluate_fetch_request(
        policy,
        method="POST",
        path="/v1/chat",
        headers={},
        body="",
    )
    assert method_block.allowed is False
    assert method_block.rule_id == "net_method_block"

    path_block = evaluate_fetch_request(
        policy,
        method="GET",
        path="/health",
        headers={},
        body="",
    )
    assert path_block.allowed is False
    assert path_block.rule_id == "net_path_block"

    header_block = evaluate_fetch_request(
        policy,
        method="GET",
        path="/v1/chat",
        headers={"Authorization": "Bearer abc"},
        body="",
    )
    assert header_block.allowed is False
    assert header_block.rule_id == "net_header_block"

    size_block = evaluate_fetch_request(
        policy,
        method="GET",
        path="/v1/chat",
        headers={},
        body="x" * 32,
    )
    assert size_block.allowed is False
    assert size_block.rule_id == "net_body_size_block"

    body_block = evaluate_fetch_request(
        policy,
        method="GET",
        path="/v1/chat",
        headers={},
        body="secret=1",
    )
    assert body_block.allowed is False
    assert body_block.rule_id == "net_body_pattern_block"

    allowed = evaluate_fetch_request(
        policy,
        method="GET",
        path="/v1/chat",
        headers={"X-Request-Id": "1"},
        body="ok",
    )
    assert allowed.allowed is True
