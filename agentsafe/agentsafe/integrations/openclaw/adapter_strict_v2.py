from __future__ import annotations

from agentsafe.integrations.model import ToolAction


class OpenClawStrictV2AdapterError(ValueError):
    pass


def parse_strict_v2_request(path: str, payload: dict, fallback_actor: str = "openclaw-agent") -> ToolAction:
    if path != "/v2/tools/execute":
        raise OpenClawStrictV2AdapterError(f"unsupported strict v2 route: {path}")

    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or not request_id.strip():
        raise OpenClawStrictV2AdapterError("request_id must be a non-empty string")

    action = payload.get("action")
    if not isinstance(action, dict):
        raise OpenClawStrictV2AdapterError("action must be an object")

    tool = action.get("name")
    if not isinstance(tool, str) or not tool.strip():
        raise OpenClawStrictV2AdapterError("action.name must be a non-empty string")

    args = action.get("args")
    if not isinstance(args, dict):
        raise OpenClawStrictV2AdapterError("action.args must be an object")

    actor = payload.get("actor") or fallback_actor
    if not isinstance(actor, str) or not actor.strip():
        raise OpenClawStrictV2AdapterError("actor must be a non-empty string")

    session_id = payload.get("session_id", "")
    if session_id is None:
        session_id = ""
    if not isinstance(session_id, str):
        raise OpenClawStrictV2AdapterError("session_id must be a string")

    context = payload.get("context", {})
    if context is None:
        context = {}
    if not isinstance(context, dict):
        raise OpenClawStrictV2AdapterError("context must be an object")

    openclaw_version = payload.get("openclaw_version", "v2")
    if openclaw_version != "v2":
        raise OpenClawStrictV2AdapterError(f"unsupported openclaw_version: {openclaw_version}")

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
