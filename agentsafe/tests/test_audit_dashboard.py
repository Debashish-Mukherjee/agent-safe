from __future__ import annotations

from agentsafe.audit.ledger import AuditLedger
from agentsafe.audit.render import render_html_dashboard


def test_render_html_dashboard_contains_summary(tmp_path):
    ledger = AuditLedger(audit_dir=tmp_path / "audit")
    ledger.write_event(
        {
            "request_id": "r1",
            "actor": "agent",
            "tool": "run",
            "decision": "ALLOW",
            "reason": "ok",
        }
    )
    html = render_html_dashboard(ledger, limit=10)
    assert "AgentSafe Audit Dashboard" in html
    assert '"events": 1' in html
    assert "r1" in html
