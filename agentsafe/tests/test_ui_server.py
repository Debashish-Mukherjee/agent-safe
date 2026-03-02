from __future__ import annotations

import json
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.request import Request, urlopen

from agentsafe.approvals.grants import ApprovalRequestStore, GrantStore
from agentsafe.ui.server import _ApprovalHandler


def _start_server(tmp_path):
    _ApprovalHandler.req_store = ApprovalRequestStore(path=tmp_path / "requests.jsonl")
    _ApprovalHandler.grant_store = GrantStore(path=tmp_path / "grants.jsonl")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ApprovalHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _post_json(url: str, payload: dict) -> dict:
    req = Request(
        url,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urlopen(req, timeout=3) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_dashboard_api_approve_flow(tmp_path):
    server = _start_server(tmp_path)
    try:
        port = server.server_address[1]
        req_store = _ApprovalHandler.req_store
        created = req_store.create(actor="alice", tool="run", scope="curl *", reason="need network", ttl_seconds=300)

        with urlopen(f"http://127.0.0.1:{port}/api/approval-requests?status=pending", timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        assert len(data["requests"]) == 1
        assert data["requests"][0]["request_id"] == created.request_id

        approved = _post_json(
            f"http://127.0.0.1:{port}/api/approval-requests/{created.request_id}/approve",
            {"reviewer": "secops", "reason": "ok", "ttl": 120},
        )
        assert approved["status"] == "approved"
        assert approved["grant"]["actor"] == "alice"
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_api_reject_flow(tmp_path):
    server = _start_server(tmp_path)
    try:
        port = server.server_address[1]
        req_store = _ApprovalHandler.req_store
        created = req_store.create(actor="bob", tool="run", scope="apt-get *", reason="install package", ttl_seconds=300)

        rejected = _post_json(
            f"http://127.0.0.1:{port}/api/approval-requests/{created.request_id}/reject",
            {"reviewer": "secops", "reason": "deny"},
        )
        assert rejected["status"] == "rejected"

        rows = req_store.list(status="rejected")
        assert any(r.request_id == created.request_id for r in rows)
    finally:
        server.shutdown()
        server.server_close()

