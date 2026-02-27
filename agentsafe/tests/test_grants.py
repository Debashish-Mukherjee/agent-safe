from agentsafe.approvals.grants import GrantStore


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
