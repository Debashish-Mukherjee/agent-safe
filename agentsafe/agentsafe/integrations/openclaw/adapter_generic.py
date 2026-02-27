from __future__ import annotations

from agentsafe.integrations.model import ToolAction


def parse_generic_request(path: str, payload: dict, fallback_actor: str = "openclaw-agent") -> ToolAction:
    request_id = str(payload.get("request_id") or payload.get("id") or "")
    if not request_id:
        request_id = "proxy-generated"

    actor = payload.get("actor") or fallback_actor
    if not isinstance(actor, str):
        actor = fallback_actor

    session_id = payload.get("session_id") or payload.get("session") or ""
    if not isinstance(session_id, str):
        session_id = ""

    tool = payload.get("tool") or payload.get("tool_name") or payload.get("name") or payload.get("action") or ""
    if not isinstance(tool, str):
        tool = ""

    args = payload.get("args") or payload.get("input") or payload.get("payload") or {}
    if not isinstance(args, dict):
        args = {"raw": args}

    context = payload.get("context")
    if not isinstance(context, dict):
        context = {}

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
