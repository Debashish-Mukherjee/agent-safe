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
    http_methods: list[str] = field(default_factory=lambda: ["GET"])
    http_path_allow_regex: list[str] = field(default_factory=list)
    max_request_body_bytes: int = 8192
    deny_header_patterns: list[str] = field(default_factory=list)
    deny_body_patterns: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RateLimitRule:
    category: str
    capacity: int = 10
    refill_per_sec: float = 1.0


@dataclass(slots=True)
class OutputPolicy:
    max_stdout_bytes: int = 65536
    max_stderr_bytes: int = 65536
    proxy_max_response_bytes: int = 1048576
    proxy_min_delay_ms: int = 0
    proxy_jitter_ms: int = 0


@dataclass(slots=True)
class ToolPolicy:
    commands: list[CommandRule] = field(default_factory=list)
    paths: PathPolicy = field(default_factory=PathPolicy)
    env_allowlist: list[str] = field(default_factory=list)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    rate_limits: list[RateLimitRule] = field(default_factory=list)
    output: OutputPolicy = field(default_factory=OutputPolicy)


@dataclass(slots=True)
class Policy:
    policy_id: str
    default_decision: str = "deny"
    tools: ToolPolicy = field(default_factory=ToolPolicy)
