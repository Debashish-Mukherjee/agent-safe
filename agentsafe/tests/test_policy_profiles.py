from __future__ import annotations

from pathlib import Path

import pytest

from agentsafe.policy.profiles import PolicyProfileError, resolve_policy_profile


def _write_profiles(tmp_path: Path) -> Path:
    profiles = tmp_path / "profiles.yaml"
    profiles.write_text(
        """
default:
  policy: policy-default.yaml
  backend: yaml
profiles:
  strict:
    policy: policy-strict.yaml
    backend: opa
users:
  alice:
    policy: policy-alice.yaml
teams:
  secops:
    policy: policy-secops.yaml
    backend: opa
""".strip(),
        encoding="utf-8",
    )
    return profiles


def test_resolve_named_profile(tmp_path: Path):
    path = _write_profiles(tmp_path)
    selected = resolve_policy_profile(profiles_path=path, profile_name="strict")
    assert selected.source == "named"
    assert selected.backend == "opa"
    assert selected.policy_path == str((tmp_path / "policy-strict.yaml").resolve())


def test_resolve_user_then_team_then_default(tmp_path: Path):
    path = _write_profiles(tmp_path)

    user_selected = resolve_policy_profile(profiles_path=path, actor="alice", team="secops")
    assert user_selected.source == "user"
    assert user_selected.policy_path == str((tmp_path / "policy-alice.yaml").resolve())

    team_selected = resolve_policy_profile(profiles_path=path, actor="bob", team="secops")
    assert team_selected.source == "team"
    assert team_selected.backend == "opa"

    default_selected = resolve_policy_profile(profiles_path=path, actor="bob", team="unknown")
    assert default_selected.source == "default"
    assert default_selected.backend == "yaml"


def test_resolve_unknown_named_profile_fails(tmp_path: Path):
    path = _write_profiles(tmp_path)
    with pytest.raises(PolicyProfileError):
        resolve_policy_profile(profiles_path=path, profile_name="missing")
