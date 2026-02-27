from __future__ import annotations

from collections import Counter

from .ledger import AuditLedger


def render_markdown_report(ledger: AuditLedger, limit: int = 500) -> str:
    events = ledger.tail(limit)
    if not events:
        return "# AgentSafe Audit Report\n\nNo events found."

    decisions = Counter(event.get("decision", "UNKNOWN") for event in events)
    tools = Counter(event.get("tool", "unknown") for event in events)

    lines = [
        "# AgentSafe Audit Report",
        "",
        "## Summary",
        f"- Events: {len(events)}",
        f"- ALLOW: {decisions.get('ALLOW', 0)}",
        f"- BLOCK: {decisions.get('BLOCK', 0)}",
        "",
        "## Tool Usage",
    ]
    for tool, count in tools.most_common():
        lines.append(f"- {tool}: {count}")

    lines.append("")
    lines.append("## Recent Events")
    for event in events[-20:]:
        rid = event.get("request_id", "-")
        actor = event.get("actor", "unknown")
        tool = event.get("tool", "unknown")
        decision = event.get("decision", "UNKNOWN")
        reason = event.get("reason", "")
        lines.append(f"- `{rid}` `{actor}` `{tool}` `{decision}`: {reason}")

    return "\n".join(lines)
