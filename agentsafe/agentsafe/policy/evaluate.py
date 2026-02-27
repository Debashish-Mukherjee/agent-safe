from __future__ import annotations

import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .model import Policy, RateLimitRule


DENY_SYSTEM_PATHS = ["/etc", "/proc", "/sys", "/root", "~", "$HOME"]


@dataclass(slots=True)
class Decision:
    allowed: bool
    reason: str
    rule_id: str


class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill_per_sec = refill_per_sec
        self.last_ts = time.monotonic()

    def consume(self, count: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_ts
        self.last_ts = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        if self.tokens < count:
            return False
        self.tokens -= count
        return True


class RateLimiter:
    def __init__(self, rules: list[RateLimitRule]):
        self.buckets = {
            rule.category: TokenBucket(capacity=rule.capacity, refill_per_sec=rule.refill_per_sec)
            for rule in rules
        }

    def check(self, category: str) -> Decision:
        bucket = self.buckets.get(category)
        if bucket is None:
            return Decision(True, "no rate limit configured", "rate_default_allow")
        if bucket.consume(1):
            return Decision(True, "within rate limit", "rate_allow")
        return Decision(False, "rate limit exceeded", "rate_limit_block")


def _normalize_path(path: str, workspace_root: Path) -> Path:
    path = path.replace("$HOME", str(Path.home())).replace("~", str(Path.home()))
    p = Path(path)
    if not p.is_absolute():
        p = workspace_root / p
    return p.resolve()


def evaluate_command(policy: Policy, cmd: list[str], workspace_root: Path) -> Decision:
    if not cmd:
        return Decision(False, "empty command", "cmd_empty")

    binary = Path(cmd[0]).name
    for rule in policy.tools.commands:
        if binary != rule.binary:
            continue
        if rule.arg_regex:
            rendered = shlex.join(cmd[1:])
            if not re.search(rule.arg_regex, rendered):
                continue
        return Decision(True, f"command allowed: {binary}", rule.rule_id)
    return Decision(False, f"command blocked: {binary} not allowlisted", "cmd_not_allowlisted")


def evaluate_path(policy: Policy, candidate: str, workspace_root: Path) -> Decision:
    normalized = _normalize_path(candidate, workspace_root)

    for denied in [*DENY_SYSTEM_PATHS, *policy.tools.paths.deny]:
        denied_path = _normalize_path(denied, workspace_root)
        if normalized == denied_path or str(normalized).startswith(str(denied_path) + "/"):
            return Decision(False, f"path denied: {candidate}", "path_deny")

    allow_roots = policy.tools.paths.allow or [str(workspace_root)]
    for allowed in allow_roots:
        allowed_path = _normalize_path(allowed, workspace_root)
        if normalized == allowed_path or str(normalized).startswith(str(allowed_path) + "/"):
            return Decision(True, f"path allowed: {candidate}", "path_allow")

    return Decision(False, f"path outside allowlist: {candidate}", "path_outside_allowlist")


def evaluate_url(policy: Policy, url: str) -> Decision:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return Decision(False, "unsupported URL scheme", "net_bad_scheme")
    host = parsed.hostname
    if not host:
        return Decision(False, "URL missing host", "net_no_host")

    if policy.tools.network.mode == "none":
        return Decision(False, "network disabled by policy", "net_disabled")

    for allowed in policy.tools.network.domains:
        if host == allowed or host.endswith("." + allowed):
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if port in policy.tools.network.ports:
                return Decision(True, f"domain allowed: {host}:{port}", "net_domain_allow")
            return Decision(False, f"port not allowed for domain: {host}:{port}", "net_port_block")

    return Decision(False, f"domain not allowlisted: {host}", "net_domain_block")
