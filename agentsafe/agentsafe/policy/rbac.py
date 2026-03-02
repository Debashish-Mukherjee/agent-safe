from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(slots=True)
class RolePolicy:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RbacPolicy:
    roles: dict[str, RolePolicy] = field(default_factory=dict)
    actor_roles: dict[str, list[str]] = field(default_factory=dict)
    team_roles: dict[str, list[str]] = field(default_factory=dict)
    default_roles: list[str] = field(default_factory=list)
    deny_tools: list[str] = field(default_factory=list)


class RbacPolicyError(ValueError):
    pass


def _as_str_list(value: object, field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        raise RbacPolicyError(f"{field_name} must be a list or string")
    return [str(v) for v in value]


def load_rbac_policy(path: str | Path) -> RbacPolicy:
    path_obj = Path(path)
    if not path_obj.exists():
        raise RbacPolicyError(f"rbac policy not found: {path_obj}")

    data = yaml.safe_load(path_obj.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise RbacPolicyError("rbac policy must be a mapping")

    roles_data = data.get("roles", {})
    actor_roles_data = data.get("actor_roles", {})
    team_roles_data = data.get("team_roles", {})
    default_roles_data = data.get("default_roles", [])
    deny_tools_data = data.get("deny_tools", [])

    if not isinstance(roles_data, dict):
        raise RbacPolicyError("roles must be a mapping")
    if not isinstance(actor_roles_data, dict):
        raise RbacPolicyError("actor_roles must be a mapping")
    if not isinstance(team_roles_data, dict):
        raise RbacPolicyError("team_roles must be a mapping")

    roles: dict[str, RolePolicy] = {}
    for role, tools in roles_data.items():
        if isinstance(tools, dict):
            roles[str(role)] = RolePolicy(
                allow=_as_str_list(tools.get("allow"), f"roles.{role}.allow"),
                deny=_as_str_list(tools.get("deny"), f"roles.{role}.deny"),
            )
            continue
        roles[str(role)] = RolePolicy(allow=_as_str_list(tools, f"roles.{role}"))

    actor_roles: dict[str, list[str]] = {}
    for actor, actor_list in actor_roles_data.items():
        actor_roles[str(actor)] = _as_str_list(actor_list, f"actor_roles.{actor}")

    team_roles: dict[str, list[str]] = {}
    for team, team_list in team_roles_data.items():
        team_roles[str(team)] = _as_str_list(team_list, f"team_roles.{team}")

    return RbacPolicy(
        roles=roles,
        actor_roles=actor_roles,
        team_roles=team_roles,
        default_roles=_as_str_list(default_roles_data, "default_roles"),
        deny_tools=_as_str_list(deny_tools_data, "deny_tools"),
    )


def _effective_roles(policy: RbacPolicy, actor: str, team: str) -> list[str]:
    roles = list(policy.default_roles)
    roles.extend(policy.team_roles.get(team, []))
    roles.extend(policy.actor_roles.get(actor, []))
    seen: set[str] = set()
    ordered: list[str] = []
    for role in roles:
        if role in seen:
            continue
        seen.add(role)
        ordered.append(role)
    return ordered


def is_tool_allowed(policy: RbacPolicy, actor: str, team: str, tool: str) -> bool:
    for pattern in policy.deny_tools:
        if fnmatch.fnmatch(tool, pattern):
            return False

    roles = _effective_roles(policy, actor=actor, team=team)
    for role in roles:
        role_policy = policy.roles.get(role, RolePolicy())
        for pattern in role_policy.deny:
            if fnmatch.fnmatch(tool, pattern):
                return False
        for pattern in role_policy.allow:
            if fnmatch.fnmatch(tool, pattern):
                return True
    return False
