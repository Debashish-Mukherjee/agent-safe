from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(slots=True)
class ProfileSelection:
    profile: str
    policy_path: str
    backend: str
    source: str


class PolicyProfileError(ValueError):
    pass


def _load_yaml(path: str | Path) -> dict:
    path_obj = Path(path)
    if not path_obj.exists():
        raise PolicyProfileError(f"profile file not found: {path_obj}")
    data = yaml.safe_load(path_obj.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise PolicyProfileError("profile file must be a mapping")
    return data


def _profile_entry(name: str, entry: object, base_dir: Path, source: str) -> ProfileSelection:
    if not isinstance(entry, dict):
        raise PolicyProfileError(f"profile entry for {name} must be a mapping")
    raw_policy = entry.get("policy")
    if not isinstance(raw_policy, str) or not raw_policy.strip():
        raise PolicyProfileError(f"profile entry for {name} missing non-empty 'policy'")
    policy_path = (base_dir / raw_policy).resolve() if not Path(raw_policy).is_absolute() else Path(raw_policy).resolve()
    backend = str(entry.get("backend", "yaml")).strip() or "yaml"
    return ProfileSelection(profile=name, policy_path=str(policy_path), backend=backend, source=source)


def resolve_policy_profile(
    *,
    profiles_path: str | Path,
    profile_name: str = "",
    actor: str = "",
    team: str = "",
) -> ProfileSelection:
    path_obj = Path(profiles_path)
    data = _load_yaml(path_obj)
    base_dir = path_obj.parent.resolve()

    named = data.get("profiles", {})
    users = data.get("users", {})
    teams = data.get("teams", {})
    default_entry = data.get("default")

    if named and not isinstance(named, dict):
        raise PolicyProfileError("profiles must be a mapping")
    if users and not isinstance(users, dict):
        raise PolicyProfileError("users must be a mapping")
    if teams and not isinstance(teams, dict):
        raise PolicyProfileError("teams must be a mapping")

    requested = profile_name.strip()
    if requested:
        if requested in named:
            return _profile_entry(requested, named[requested], base_dir, source="named")
        raise PolicyProfileError(f"unknown profile: {requested}")

    if actor and actor in users:
        return _profile_entry(actor, users[actor], base_dir, source="user")

    if team and team in teams:
        return _profile_entry(team, teams[team], base_dir, source="team")

    if isinstance(default_entry, dict):
        return _profile_entry("default", default_entry, base_dir, source="default")

    raise PolicyProfileError("no matching profile and no default profile configured")
