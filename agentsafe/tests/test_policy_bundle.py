from agentsafe.policy.signing.bundle import verify_bundle_hash, write_bundle


def test_bundle_hash_verification(tmp_path):
    policy = tmp_path / "policy.yaml"
    bundle = tmp_path / "bundle.json"
    policy.write_text("policy_id: t\ndefault_decision: deny\n", encoding="utf-8")
    write_bundle(policy_path=policy, out_path=bundle)
    assert verify_bundle_hash(policy_path=policy, bundle_path=bundle)
