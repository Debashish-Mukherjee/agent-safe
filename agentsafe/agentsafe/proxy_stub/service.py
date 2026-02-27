"""Mode B proxy scaffold.

This module defines the MVP interface for reverse-proxy policy enforcement
in front of an agent gateway API. Not wired in runtime yet.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ToolCall:
    actor: str
    tool_name: str
    payload: dict


@dataclass(slots=True)
class ProxyDecision:
    allowed: bool
    reason: str


def evaluate_tool_call(_call: ToolCall) -> ProxyDecision:
    """TODO: integrate with policy evaluator and audited forwarding path."""
    return ProxyDecision(allowed=False, reason="not_implemented_mode_b")
