from __future__ import annotations

from pathlib import Path

from agentsafe.policy.rbac import is_tool_allowed, load_rbac_policy


def _write_rbac(tmp_path: Path) -> Path:
    path = tmp_path / "rbac.yaml"
    path.write_text(
        """
roles:
  viewer:
    - "http.fetch"
  operator:
    - "shell.run"
  admin:
    - "*"
actor_roles:
  alice:
    - operator
team_roles:
  secops:
    - viewer
default_roles:
  - viewer
""".strip(),
        encoding="utf-8",
    )
    return path


def test_rbac_allows_by_actor_team_and_default_roles(tmp_path: Path):
    policy = load_rbac_policy(_write_rbac(tmp_path))

    assert is_tool_allowed(policy, actor="alice", team="", tool="shell.run")
    assert is_tool_allowed(policy, actor="bob", team="secops", tool="http.fetch")
    assert is_tool_allowed(policy, actor="bob", team="", tool="http.fetch")
    assert not is_tool_allowed(policy, actor="bob", team="", tool="shell.run")


def test_rbac_global_deny_overrides_allow(tmp_path: Path):
    path = tmp_path / "rbac.yaml"
    path.write_text(
        """
roles:
  admin:
    - "*"
actor_roles:
  alice:
    - admin
deny_tools:
  - "shell.run"
""".strip(),
        encoding="utf-8",
    )
    policy = load_rbac_policy(path)
    assert not is_tool_allowed(policy, actor="alice", team="", tool="shell.run")
    assert is_tool_allowed(policy, actor="alice", team="", tool="http.fetch")


def test_rbac_role_deny_overrides_role_allow(tmp_path: Path):
    path = tmp_path / "rbac.yaml"
    path.write_text(
        """
roles:
  mixed:
    allow:
      - "shell.*"
    deny:
      - "shell.run"
actor_roles:
  alice:
    - mixed
""".strip(),
        encoding="utf-8",
    )
    policy = load_rbac_policy(path)
    assert not is_tool_allowed(policy, actor="alice", team="", tool="shell.run")
    assert is_tool_allowed(policy, actor="alice", team="", tool="shell.exec")
