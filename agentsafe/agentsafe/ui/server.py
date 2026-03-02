from __future__ import annotations

import json
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from agentsafe.approvals.grants import ApprovalRequestStore, GrantStore


def _dashboard_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentSafe Approval Dashboard</title>
  <style>
    body { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; margin: 0; padding: 20px; background: #f5f7fa; color: #1f2933; }
    .card { background: #fff; border: 1px solid #d9e2ec; border-radius: 10px; padding: 14px; margin-bottom: 10px; }
    .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
    button { border: 1px solid #cbd2d9; border-radius: 8px; padding: 6px 10px; background: #fff; cursor: pointer; }
    button.primary { background: #1f6feb; color: #fff; border-color: #1f6feb; }
    code { background: #eef2f7; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>AgentSafe Approval Dashboard</h1>
  <p>Review and action pending approval requests.</p>
  <div id="items"></div>
  <script>
    async function loadRequests() {
      const res = await fetch('/api/approval-requests?status=pending');
      const data = await res.json();
      const items = document.getElementById('items');
      items.innerHTML = '';
      for (const req of data.requests || []) {
        const el = document.createElement('div');
        el.className = 'card';
        el.innerHTML = `
          <div><strong>${req.actor}</strong> requested <code>${req.tool}</code></div>
          <div>scope: <code>${req.scope}</code></div>
          <div>reason: ${req.reason || ''}</div>
          <div class="row">
            <button class="primary" onclick="approve('${req.request_id}')">Approve</button>
            <button onclick="rejectReq('${req.request_id}')">Reject</button>
          </div>
        `;
        items.appendChild(el);
      }
      if ((data.requests || []).length === 0) {
        items.innerHTML = '<div class="card">No pending approval requests.</div>';
      }
    }
    async function approve(id) {
      await fetch(`/api/approval-requests/${id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewer: 'dashboard-operator', reason: 'approved via dashboard', ttl: 900 }),
      });
      await loadRequests();
    }
    async function rejectReq(id) {
      await fetch(`/api/approval-requests/${id}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewer: 'dashboard-operator', reason: 'rejected via dashboard' }),
      });
      await loadRequests();
    }
    loadRequests();
  </script>
</body>
</html>"""


class _ApprovalHandler(BaseHTTPRequestHandler):
    req_store = ApprovalRequestStore()
    grant_store = GrantStore()

    def log_message(self, format: str, *args):
        _ = (format, args)

    def _write_json(self, code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        content_len = int(self.headers.get("Content-Length", "0"))
        if content_len <= 0:
            return {}
        raw = self.rfile.read(content_len)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/dashboard"}:
            body = _dashboard_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/approval-requests":
            status = parse_qs(parsed.query).get("status", ["pending"])[0]
            rows = [asdict(item) for item in self.req_store.list(status=status)]
            self._write_json(200, {"requests": rows})
            return
        self._write_json(404, {"error": "not_found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        if len(parts) != 4 or parts[0] != "api" or parts[1] != "approval-requests":
            self._write_json(404, {"error": "not_found"})
            return
        req_id = parts[2]
        action = parts[3]
        payload = self._read_json()
        reviewer = str(payload.get("reviewer", "dashboard-operator"))
        reason = str(payload.get("reason", "dashboard action"))

        try:
            if action == "approve":
                ttl = int(payload.get("ttl", 900))
                grant = self.req_store.approve(
                    request_id=req_id,
                    reviewer=reviewer,
                    ttl_seconds=ttl,
                    reason=reason,
                    grant_store=self.grant_store,
                )
                self._write_json(200, {"status": "approved", "grant": asdict(grant)})
                return
            if action == "reject":
                self.req_store.reject(request_id=req_id, reviewer=reviewer, reason=reason)
                self._write_json(200, {"status": "rejected", "request_id": req_id})
                return
            self._write_json(404, {"error": "not_found"})
        except ValueError as exc:
            self._write_json(400, {"error": "bad_request", "reason": str(exc)})


def run_dashboard_server(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), _ApprovalHandler)
    print(f"agentsafe dashboard listening on http://{host}:{server.server_address[1]}")
    server.serve_forever()
