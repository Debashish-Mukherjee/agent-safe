from __future__ import annotations

from collections import Counter
import json

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


def render_html_dashboard(ledger: AuditLedger, limit: int = 500) -> str:
    events = ledger.tail(limit)
    decisions = Counter(event.get("decision", "UNKNOWN") for event in events)
    tools = Counter(event.get("tool", "unknown") for event in events)
    recent = events[-100:]
    summary = {
        "events": len(events),
        "allow": decisions.get("ALLOW", 0),
        "block": decisions.get("BLOCK", 0),
        "by_tool": dict(tools.most_common()),
    }
    recent_json = json.dumps(recent)
    summary_json = json.dumps(summary)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentSafe Audit Dashboard</title>
  <style>
    :root {{
      --bg: #f4f6f8;
      --card: #ffffff;
      --ink: #18212b;
      --muted: #516070;
      --ok: #177245;
      --block: #b33939;
      --line: #d7dee6;
    }}
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background: radial-gradient(circle at top, #ffffff, var(--bg));
      color: var(--ink);
    }}
    .wrap {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 24px 16px 40px;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
    }}
    .label {{ color: var(--muted); font-size: 12px; }}
    .value {{ font-weight: 700; font-size: 24px; margin-top: 4px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: hidden;
    }}
    th, td {{
      text-align: left;
      padding: 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      font-size: 13px;
    }}
    th {{ background: #eef3f7; color: var(--muted); font-weight: 600; }}
    .ALLOW {{ color: var(--ok); font-weight: 600; }}
    .BLOCK {{ color: var(--block); font-weight: 600; }}
    .tools {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
      margin-bottom: 12px;
      font-size: 13px;
    }}
    code {{ background: #eef3f7; padding: 1px 5px; border-radius: 6px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>AgentSafe Audit Dashboard</h1>
    <div class="cards">
      <div class="card"><div class="label">Events</div><div class="value" id="events">0</div></div>
      <div class="card"><div class="label">ALLOW</div><div class="value" id="allow">0</div></div>
      <div class="card"><div class="label">BLOCK</div><div class="value" id="block">0</div></div>
    </div>
    <div class="tools">
      <strong>Tool Usage</strong>
      <div id="tool-usage"></div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Request</th>
          <th>Actor</th>
          <th>Tool</th>
          <th>Decision</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <script>
    const summary = {summary_json};
    const events = {recent_json};
    document.getElementById("events").textContent = String(summary.events);
    document.getElementById("allow").textContent = String(summary.allow);
    document.getElementById("block").textContent = String(summary.block);
    document.getElementById("tool-usage").textContent = Object.entries(summary.by_tool)
      .map(([tool, count]) => `${{tool}}: ${{count}}`)
      .join(" | ");
    const rows = document.getElementById("rows");
    for (const event of events.slice().reverse()) {{
      const tr = document.createElement("tr");
      const ts = event.timestamp || "-";
      const rid = event.request_id || "-";
      const actor = event.actor || "-";
      const tool = event.tool || "-";
      const decision = event.decision || "UNKNOWN";
      const reason = event.reason || "";
      tr.innerHTML = `
        <td><code>${{ts}}</code></td>
        <td><code>${{rid}}</code></td>
        <td>${{actor}}</td>
        <td>${{tool}}</td>
        <td class="${{decision}}">${{decision}}</td>
        <td>${{reason}}</td>
      `;
      rows.appendChild(tr);
    }}
  </script>
</body>
</html>
"""
