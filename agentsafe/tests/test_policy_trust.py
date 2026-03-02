from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
import textwrap

from agentsafe.policy.signing.bundle import bundle_digest, write_bundle
from agentsafe.policy.signing.trust import verify_bundle_trust


def _write_yaml(path, text: str) -> None:
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


def test_verify_bundle_trust_accepts_valid_issuer_source_and_chain(tmp_path):
    policy = tmp_path / "policy.yaml"
    parent = tmp_path / "parent.json"
    child = tmp_path / "child.json"
    trust = tmp_path / "trust.yaml"
    policy.write_text("policy_id: t\ndefault_decision: deny\n", encoding="utf-8")
    write_bundle(policy_path=policy, out_path=parent, issuer="secops", source_uri="git+https://example.com/policies")
    write_bundle(
        policy_path=policy,
        out_path=child,
        issuer="secops",
        source_uri="git+https://example.com/policies",
        parent_bundle_sha256=bundle_digest(parent),
    )
    _write_yaml(
        trust,
        """
        trusted_issuers: [secops]
        source_uri_allow_regex: ['^git\\+https://example\\.com/']
        max_bundle_age_hours: 48
        require_parent_chain: true
        require_signature: false
        """,
    )
    result = verify_bundle_trust(
        policy_path=policy,
        bundle_path=child,
        trust_policy_path=trust,
        parent_bundles=[parent],
    )
    assert result.valid is True
    assert result.errors == []


def test_verify_bundle_trust_blocks_untrusted_issuer_and_old_bundle(tmp_path):
    policy = tmp_path / "policy.yaml"
    bundle = tmp_path / "bundle.json"
    trust = tmp_path / "trust.yaml"
    policy.write_text("policy_id: t\ndefault_decision: deny\n", encoding="utf-8")
    write_bundle(policy_path=policy, out_path=bundle, issuer="other", source_uri="https://bad.example/")

    payload = json.loads(bundle.read_text(encoding="utf-8"))
    payload["provenance"]["issued_at"] = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
    bundle.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    _write_yaml(
        trust,
        """
        trusted_issuers: [secops]
        source_uri_allow_regex: ['^git\\+https://example\\.com/']
        max_bundle_age_hours: 24
        require_signature: false
        """,
    )
    result = verify_bundle_trust(policy_path=policy, bundle_path=bundle, trust_policy_path=trust)
    assert result.valid is False
    assert "issuer_untrusted" in result.errors
    assert "source_uri_blocked" in result.errors
    assert "bundle_expired" in result.errors


def test_verify_bundle_trust_requires_parent_chain_when_configured(tmp_path):
    policy = tmp_path / "policy.yaml"
    bundle = tmp_path / "bundle.json"
    trust = tmp_path / "trust.yaml"
    policy.write_text("policy_id: t\ndefault_decision: deny\n", encoding="utf-8")
    write_bundle(policy_path=policy, out_path=bundle, issuer="secops", source_uri="git+https://example.com/policies")
    _write_yaml(
        trust,
        """
        trusted_issuers: [secops]
        source_uri_allow_regex: ['^git\\+https://example\\.com/']
        require_parent_chain: true
        require_signature: false
        """,
    )
    result = verify_bundle_trust(policy_path=policy, bundle_path=bundle, trust_policy_path=trust)
    assert result.valid is False
    assert "parent_chain_required" in result.errors
