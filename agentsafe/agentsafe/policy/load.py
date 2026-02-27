from __future__ import annotations

from pathlib import Path

import yaml

from .model import CommandRule, NetworkPolicy, PathPolicy, Policy, RateLimitRule, ToolPolicy


class PolicyError(ValueError):
    pass


def _ensure_list(value: object, field_name: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyError(f"{field_name} must be a list")
    return value


def load_policy(path: str | Path) -> Policy:
    path_obj = Path(path)
    if not path_obj.exists():
        raise PolicyError(f"Policy file not found: {path_obj}")

    data = yaml.safe_load(path_obj.read_text()) or {}
    if not isinstance(data, dict):
        raise PolicyError("Policy must be a mapping")

    policy_id = data.get("policy_id", path_obj.stem)
    default_decision = data.get("default_decision", "deny")
    if default_decision != "deny":
        raise PolicyError("Only default deny is supported in MVP")

    tools_data = data.get("tools", {})
    if not isinstance(tools_data, dict):
        raise PolicyError("tools must be a mapping")

    command_rules: list[CommandRule] = []
    for idx, item in enumerate(_ensure_list(tools_data.get("commands"), "tools.commands")):
        if not isinstance(item, dict) or "binary" not in item:
            raise PolicyError(f"Invalid command rule at index {idx}")
        command_rules.append(
            CommandRule(
                binary=str(item["binary"]),
                arg_regex=item.get("arg_regex"),
                rule_id=str(item.get("rule_id", f"cmd_{idx}")),
            )
        )

    paths_data = tools_data.get("paths", {})
    if not isinstance(paths_data, dict):
        raise PolicyError("tools.paths must be a mapping")
    path_policy = PathPolicy(
        allow=[str(v) for v in _ensure_list(paths_data.get("allow"), "tools.paths.allow")],
        deny=[str(v) for v in _ensure_list(paths_data.get("deny"), "tools.paths.deny")],
    )

    network_data = tools_data.get("network", {})
    if not isinstance(network_data, dict):
        raise PolicyError("tools.network must be a mapping")
    network_policy = NetworkPolicy(
        mode=str(network_data.get("mode", "none")),
        domains=[str(v) for v in _ensure_list(network_data.get("domains"), "tools.network.domains")],
        ports=[int(v) for v in _ensure_list(network_data.get("ports"), "tools.network.ports") or [443]],
    )

    rate_limits: list[RateLimitRule] = []
    for idx, item in enumerate(_ensure_list(tools_data.get("rate_limits"), "tools.rate_limits")):
        if not isinstance(item, dict) or "category" not in item:
            raise PolicyError(f"Invalid rate limit at index {idx}")
        rate_limits.append(
            RateLimitRule(
                category=str(item["category"]),
                capacity=int(item.get("capacity", 10)),
                refill_per_sec=float(item.get("refill_per_sec", 1.0)),
            )
        )

    env_allowlist = [str(v) for v in _ensure_list(tools_data.get("env_allowlist"), "tools.env_allowlist")]

    return Policy(
        policy_id=str(policy_id),
        default_decision=default_decision,
        tools=ToolPolicy(
            commands=command_rules,
            paths=path_policy,
            env_allowlist=env_allowlist,
            network=network_policy,
            rate_limits=rate_limits,
        ),
    )
