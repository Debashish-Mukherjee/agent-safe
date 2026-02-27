from __future__ import annotations

from agentsafe.integrations.model import ToolAction


class LightGatewayAdapterError(ValueError):
    pass


def parse_execute_request(path: str, payload: dict, fallback_actor: str = "openclaw-agent") -> ToolAction:
    required = ["request_id", "tool", "args"]
    missing = [name for name in required if name not in payload]
    if missing:
        raise LightGatewayAdapterError(f"missing required fields: {', '.join(missing)}")

    request_id = payload["request_id"]
    tool = payload["tool"]
    args = payload["args"]

    if not isinstance(request_id, str) or not request_id.strip():
        raise LightGatewayAdapterError("request_id must be a non-empty string")
    if not isinstance(tool, str) or not tool.strip():
        raise LightGatewayAdapterError("tool must be a non-empty string")
    if not isinstance(args, dict):
        raise LightGatewayAdapterError("args must be an object")

    actor = payload.get("actor")
    if actor is None:
        actor = fallback_actor
    if not isinstance(actor, str) or not actor.strip():
        raise LightGatewayAdapterError("actor must be a non-empty string")

    session_id = payload.get("session_id", "")
    if session_id is None:
        session_id = ""
    if not isinstance(session_id, str):
        raise LightGatewayAdapterError("session_id must be a string")

    context = payload.get("context", {})
    if context is None:
        context = {}
    if not isinstance(context, dict):
        raise LightGatewayAdapterError("context must be an object")

    return ToolAction(
        request_id=request_id,
        actor=actor,
        session_id=session_id,
        tool=tool,
        args=args,
        route=path,
        context=context,
        raw_payload=payload,
    )
