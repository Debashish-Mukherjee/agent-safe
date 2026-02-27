from agentsafe.approvals.grants import ApprovalRequestStore
from agentsafe.approvals.grants import GrantStore
from agentsafe.approvals.grants import render_scope_template


def test_issue_and_match_grant(tmp_path):
    store = GrantStore(tmp_path / "grants.jsonl")
    grant = store.issue(actor="openclaw-agent", tool="run", scope="curl *", ttl_seconds=60, reason="demo")
    assert grant.grant_id
    assert store.is_allowed(actor="openclaw-agent", tool="run", scope="curl https://openai.com")


def test_revoke_grant(tmp_path):
    store = GrantStore(tmp_path / "grants.jsonl")
    grant = store.issue(actor="openclaw-agent", tool="run", scope="curl *", ttl_seconds=60, reason="demo")
    store.revoke(grant.grant_id)
    assert not store.is_allowed(actor="openclaw-agent", tool="run", scope="curl https://openai.com")


def test_request_approve_flow(tmp_path):
    grants = GrantStore(tmp_path / "grants.jsonl")
    reqs = ApprovalRequestStore(tmp_path / "approval_requests.jsonl")
    req = reqs.create(
        actor="openclaw-agent",
        tool="run",
        scope="curl https://openai.com",
        reason="need external docs",
        ttl_seconds=300,
    )
    pending = reqs.list("pending")
    assert any(item.request_id == req.request_id for item in pending)

    grant = reqs.approve(
        request_id=req.request_id,
        reviewer="secops",
        ttl_seconds=600,
        reason="approved for demo",
        grant_store=grants,
    )
    assert grant.actor == "openclaw-agent"
    assert grants.is_allowed(actor="openclaw-agent", tool="run", scope="curl https://openai.com")


def test_request_reject_flow(tmp_path):
    reqs = ApprovalRequestStore(tmp_path / "approval_requests.jsonl")
    req = reqs.create(
        actor="openclaw-agent",
        tool="run",
        scope="apt-get *",
        reason="install package",
        ttl_seconds=300,
    )
    reqs.reject(request_id=req.request_id, reviewer="secops", reason="not allowed")
    rejected = reqs.list("rejected")
    assert any(item.request_id == req.request_id for item in rejected)


def test_scope_template_rendering():
    assert render_scope_template("run-binary", "curl", "run") == "curl *"
    assert render_scope_template("run-command", "curl https://openai.com", "run") == "curl https://openai.com"
    assert render_scope_template("tool-prefix", "curl ", "shell.run") == "shell.run curl *"
    assert render_scope_template("http-domain", "OpenAI.com", "fetch") == "http.fetch https://openai.com*"
