from __future__ import annotations

from typing import Callable

from agentsafe.integrations.light_gateway.adapter import parse_execute_request
from agentsafe.integrations.model import ToolAction
from agentsafe.integrations.openclaw.adapter_generic import parse_generic_request
from agentsafe.integrations.openclaw.adapter_strict_v1 import parse_strict_v1_request

AdapterFn = Callable[[str, dict, str], ToolAction]


def get_adapter(name: str) -> AdapterFn:
    if name == "light_gateway":
        return parse_execute_request
    if name == "openclaw_generic":
        return parse_generic_request
    if name == "openclaw_strict_v1":
        return parse_strict_v1_request
    raise ValueError(f"unknown adapter: {name}")
