from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CommandRule:
    binary: str
    arg_regex: str | None = None
    rule_id: str = "cmd_allow"


@dataclass(slots=True)
class PathPolicy:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass(slots=True)
class NetworkPolicy:
    mode: str = "none"
    domains: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=lambda: [443])


@dataclass(slots=True)
class RateLimitRule:
    category: str
    capacity: int = 10
    refill_per_sec: float = 1.0


@dataclass(slots=True)
class ToolPolicy:
    commands: list[CommandRule] = field(default_factory=list)
    paths: PathPolicy = field(default_factory=PathPolicy)
    env_allowlist: list[str] = field(default_factory=list)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    rate_limits: list[RateLimitRule] = field(default_factory=list)


@dataclass(slots=True)
class Policy:
    policy_id: str
    default_decision: str = "deny"
    tools: ToolPolicy = field(default_factory=ToolPolicy)
