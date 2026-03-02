from __future__ import annotations

from agentsafe.integrations.model import ToolAction


class OpenClawStrictLegacyAdapterError(ValueError):
    pass


def parse_strict_legacy_request(path: str, payload: dict, fallback_actor: str = "openclaw-agent") -> ToolAction:
    if path != "/gateway/tools/execute":
        raise OpenClawStrictLegacyAdapterError(f"unsupported strict legacy route: {path}")

    required = ["id", "name", "input"]
    missing = [field for field in required if field not in payload]
    if missing:
        raise OpenClawStrictLegacyAdapterError(f"missing required fields: {', '.join(missing)}")

    request_id = payload["id"]
    if not isinstance(request_id, str) or not request_id.strip():
        raise OpenClawStrictLegacyAdapterError("id must be a non-empty string")

    tool = payload["name"]
    if not isinstance(tool, str) or not tool.strip():
        raise OpenClawStrictLegacyAdapterError("name must be a non-empty string")

    args = payload["input"]
    if not isinstance(args, dict):
        raise OpenClawStrictLegacyAdapterError("input must be an object")

    actor = payload.get("actor") or fallback_actor
    if not isinstance(actor, str) or not actor.strip():
        raise OpenClawStrictLegacyAdapterError("actor must be a non-empty string")

    session_id = payload.get("session", "")
    if session_id is None:
        session_id = ""
    if not isinstance(session_id, str):
        raise OpenClawStrictLegacyAdapterError("session must be a string")

    context = payload.get("context", {})
    if context is None:
        context = {}
    if not isinstance(context, dict):
        raise OpenClawStrictLegacyAdapterError("context must be an object")

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
