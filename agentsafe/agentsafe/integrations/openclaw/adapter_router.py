from __future__ import annotations

from agentsafe.integrations.model import ToolAction
from agentsafe.integrations.openclaw.adapter_generic import parse_generic_request
from agentsafe.integrations.openclaw.adapter_strict_v1 import OpenClawStrictV1AdapterError, parse_strict_v1_request
from agentsafe.integrations.openclaw.adapter_strict_v2 import OpenClawStrictV2AdapterError, parse_strict_v2_request


def parse_openclaw_auto_request(path: str, payload: dict, fallback_actor: str = "openclaw-agent") -> ToolAction:
    """
    Strict-first OpenClaw adapter routing.

    - Uses strict v1 adapter for /v1/tools/execute or explicit openclaw_version=v1 payloads.
    - Falls back to generic extraction for unknown/legacy payloads.
    """
    version = payload.get("openclaw_version")
    if path == "/v2/tools/execute" or version == "v2":
        try:
            return parse_strict_v2_request(path, payload, fallback_actor=fallback_actor)
        except OpenClawStrictV2AdapterError:
            pass

    if path == "/v1/tools/execute" or version == "v1":
        try:
            return parse_strict_v1_request(path, payload, fallback_actor=fallback_actor)
        except OpenClawStrictV1AdapterError:
            # Graceful fallback keeps proxy usable across mixed gateway payloads.
            pass

    return parse_generic_request(path, payload, fallback_actor=fallback_actor)
