import json

from agentsafe.policy.signing.bundle import (
    attest_policy,
    bundle_digest,
    verify_bundle_chain,
    verify_bundle_hash,
    verify_bundle_manifest,
    write_bundle,
)


def test_bundle_hash_verification(tmp_path):
    policy = tmp_path / "policy.yaml"
    bundle = tmp_path / "bundle.json"
    policy.write_text("policy_id: t\ndefault_decision: deny\n", encoding="utf-8")
    write_bundle(policy_path=policy, out_path=bundle, issuer="secops", source_uri="git://repo/policies")
    assert verify_bundle_hash(policy_path=policy, bundle_path=bundle)
    assert verify_bundle_manifest(bundle_path=bundle)


def test_bundle_chain_verification_with_parent(tmp_path):
    policy = tmp_path / "policy.yaml"
    bundle1 = tmp_path / "bundle1.json"
    bundle2 = tmp_path / "bundle2.json"
    policy.write_text("policy_id: t\ndefault_decision: deny\n", encoding="utf-8")

    write_bundle(policy_path=policy, out_path=bundle1)
    write_bundle(policy_path=policy, out_path=bundle2, parent_bundle_sha256=bundle_digest(bundle1))
    assert verify_bundle_chain(bundle_path=bundle1)
    assert verify_bundle_chain(bundle_path=bundle2, parent_bundle_path=bundle1)


def test_bundle_chain_verification_parent_mismatch(tmp_path):
    policy = tmp_path / "policy.yaml"
    parent = tmp_path / "parent.json"
    child = tmp_path / "child.json"
    other = tmp_path / "other.json"
    policy.write_text("policy_id: t\ndefault_decision: deny\n", encoding="utf-8")

    write_bundle(policy_path=policy, out_path=parent)
    write_bundle(policy_path=policy, out_path=other)

    write_bundle(policy_path=policy, out_path=child, parent_bundle_sha256=bundle_digest(parent))

    assert verify_bundle_chain(bundle_path=child, parent_bundle_path=parent)
    assert not verify_bundle_chain(bundle_path=child, parent_bundle_path=other)


def test_bundle_manifest_detects_tamper(tmp_path):
    policy = tmp_path / "policy.yaml"
    bundle = tmp_path / "bundle.json"
    policy.write_text("policy_id: t\ndefault_decision: deny\n", encoding="utf-8")
    write_bundle(policy_path=policy, out_path=bundle)

    payload = json.loads(bundle.read_text(encoding="utf-8"))
    payload["policy_file"] = "tampered.yaml"
    bundle.write_text(json.dumps(payload), encoding="utf-8")

    assert not verify_bundle_manifest(bundle_path=bundle)


def test_attest_policy_returns_digests(tmp_path):
    policy = tmp_path / "policy.yaml"
    bundle = tmp_path / "bundle.json"
    policy.write_text("policy_id: t\ndefault_decision: deny\n", encoding="utf-8")

    result = attest_policy(policy_path=policy, out_path=bundle, issuer="secops")
    assert result["bundle_path"] == str(bundle)
    assert result["bundle_sha256"]
    assert result["policy_sha256"]
