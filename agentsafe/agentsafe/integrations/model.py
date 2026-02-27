from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ToolAction:
    request_id: str
    actor: str
    session_id: str
    tool: str
    args: dict
    route: str
    context: dict = field(default_factory=dict)
    raw_payload: dict = field(default_factory=dict)
