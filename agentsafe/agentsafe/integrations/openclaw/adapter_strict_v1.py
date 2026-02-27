from __future__ import annotations

from agentsafe.integrations.model import ToolAction


class OpenClawStrictV1AdapterError(ValueError):
    pass


def parse_strict_v1_request(path: str, payload: dict, fallback_actor: str = "openclaw-agent"):
    if path != "/v1/tools/execute":
        raise OpenClawStrictV1AdapterError(f"unsupported strict v1 route: {path}")

    required = ["request_id", "tool", "args"]
    missing = [field for field in required if field not in payload]
    if missing:
        raise OpenClawStrictV1AdapterError(f"missing required fields: {', '.join(missing)}")

    request_id = payload["request_id"]
    if not isinstance(request_id, str) or not request_id.strip():
        raise OpenClawStrictV1AdapterError("request_id must be a non-empty string")

    tool = payload["tool"]
    if not isinstance(tool, str) or not tool.strip():
        raise OpenClawStrictV1AdapterError("tool must be a non-empty string")

    args = payload["args"]
    if not isinstance(args, dict):
        raise OpenClawStrictV1AdapterError("args must be an object")

    actor = payload.get("actor") or fallback_actor
    if not isinstance(actor, str) or not actor.strip():
        raise OpenClawStrictV1AdapterError("actor must be a non-empty string")

    session_id = payload.get("session_id", "")
    if session_id is None:
        session_id = ""
    if not isinstance(session_id, str):
        raise OpenClawStrictV1AdapterError("session_id must be a string")

    context = payload.get("context", {})
    if context is None:
        context = {}
    if not isinstance(context, dict):
        raise OpenClawStrictV1AdapterError("context must be an object")

    openclaw_version = payload.get("openclaw_version", "v1")
    if openclaw_version != "v1":
        raise OpenClawStrictV1AdapterError(f"unsupported openclaw_version: {openclaw_version}")

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
